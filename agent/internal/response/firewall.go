package response

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"vps-soc/agent/internal/state"
)

const (
	nftTable    = "vps_soc"
	blocksFile  = "blocks.json"
	MaxBlockTTL = 30 * 24 * time.Hour
	MinBlockTTL = time.Minute
)

// Runner runs a command, feeding stdin when non-empty. Swapped in tests.
type Runner func(ctx context.Context, stdin string, name string, args ...string) (string, error)

// DefaultRunner executes real commands.
var DefaultRunner Runner = execRunner

func execRunner(ctx context.Context, stdin string, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// Block is one blocked address, persisted so blocks survive agent restarts and reboots.
type Block struct {
	IP     string    `json:"ip"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
	Origin string    `json:"origin"` // agent | soc
}

// Firewall manages a dedicated nftables table. The drop rule sits on the prerouting hook,
// before Docker's DNAT, so it also covers container-published ports, and established
// sessions from a blocked address die at once. Each element carries a kernel timeout:
// a block expires on its own even if the agent is gone.
type Firewall struct {
	State *state.Store
	Run   Runner

	mu     sync.Mutex
	blocks map[string]Block
	ready  bool
}

func NewFirewall(st *state.Store) *Firewall {
	return &Firewall{State: st, Run: execRunner, blocks: map[string]Block{}}
}

const nftRuleset = `table inet ` + nftTable + ` {
	set blocked4 { type ipv4_addr; flags timeout; }
	set blocked6 { type ipv6_addr; flags timeout; }
	chain prerouting {
		type filter hook prerouting priority -200; policy accept;
		ip saddr @blocked4 counter drop comment "vps-soc blocked"
		ip6 saddr @blocked6 counter drop comment "vps-soc blocked"
	}
}
`

// Init (re)creates the table and restores blocks that have not expired yet.
func (f *Firewall) Init(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, _ = f.Run(ctx, "", "nft", "delete", "table", "inet", nftTable) // absent on first run
	if _, err := f.Run(ctx, nftRuleset, "nft", "-f", "-"); err != nil {
		if _, lookErr := exec.LookPath("nft"); lookErr != nil {
			return errors.New("nft not found: install nftables (apt install nftables) to enable IP blocking")
		}
		return err
	}
	f.ready = true

	var saved map[string]Block
	if _, err := f.State.LoadJSON(blocksFile, &saved); err != nil {
		log.Printf("blocks state unreadable: %v", err)
	}
	now := time.Now()
	for ip, b := range saved {
		if b.Until.After(now) {
			if err := f.addElement(ctx, ip, b.Until.Sub(now)); err != nil {
				log.Printf("restore block %s: %v", ip, err)
				continue
			}
			f.blocks[ip] = b
		}
	}
	if len(f.blocks) > 0 {
		log.Printf("firewall: restored %d active blocks", len(f.blocks))
	}
	return f.save()
}

// Block drops all traffic from ip for ttl. Re-blocking an address extends the block.
func (f *Firewall) Block(ctx context.Context, ip net.IP, ttl time.Duration, reason, origin string) (Block, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ready {
		return Block{}, errors.New("firewall not initialised (nftables unavailable)")
	}
	ttl = min(max(ttl, MinBlockTTL), MaxBlockTTL)
	key := ip.String()
	_, _ = f.Run(ctx, "", "nft", "delete", "element", "inet", nftTable, setFor(ip), "{ "+key+" }")
	if err := f.addElement(ctx, key, ttl); err != nil {
		return Block{}, err
	}
	b := Block{IP: key, Until: time.Now().Add(ttl).Truncate(time.Second), Reason: reason, Origin: origin}
	f.blocks[key] = b
	return b, f.save()
}

// Unblock removes ip from the block set (no error if it was not blocked).
func (f *Firewall) Unblock(ctx context.Context, ip net.IP) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.ready {
		return errors.New("firewall not initialised (nftables unavailable)")
	}
	key := ip.String()
	// Fails when the element is absent (already expired), which is the state we want anyway.
	_, _ = f.Run(ctx, "", "nft", "delete", "element", "inet", nftTable, setFor(ip), "{ "+key+" }")
	delete(f.blocks, key)
	return f.save()
}

// IsBlocked reports whether ip has an active block.
func (f *Firewall) IsBlocked(ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.blocks[ip]
	return ok && b.Until.After(time.Now())
}

// Stats is shipped with the heartbeat: how many addresses are blocked and how many
// packets the drop rules have stopped since the table was created.
type Stats struct {
	Enabled        bool  `json:"enabled"`
	BlockedIPs     int   `json:"blockedIps"`
	DroppedPackets int64 `json:"droppedPackets"`
	DroppedBytes   int64 `json:"droppedBytes"`
}

func (f *Firewall) Stats(ctx context.Context) Stats {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := Stats{Enabled: f.ready}
	if !f.ready {
		return s
	}
	now := time.Now()
	for ip, b := range f.blocks {
		if b.Until.After(now) {
			s.BlockedIPs++
		} else {
			delete(f.blocks, ip)
		}
	}
	out, err := f.Run(ctx, "", "nft", "-j", "list", "chain", "inet", nftTable, "prerouting")
	if err == nil {
		s.DroppedPackets, s.DroppedBytes = ParseCounters(out)
	}
	return s
}

// ParseCounters sums the counter expressions in `nft -j list chain` output.
func ParseCounters(js string) (packets, bytes int64) {
	var doc struct {
		Nftables []struct {
			Rule *struct {
				Expr []map[string]json.RawMessage `json:"expr"`
			} `json:"rule"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(js), &doc) != nil {
		return 0, 0
	}
	for _, item := range doc.Nftables {
		if item.Rule == nil {
			continue
		}
		for _, expr := range item.Rule.Expr {
			raw, ok := expr["counter"]
			if !ok {
				continue
			}
			var c struct {
				Packets int64 `json:"packets"`
				Bytes   int64 `json:"bytes"`
			}
			if json.Unmarshal(raw, &c) == nil {
				packets += c.Packets
				bytes += c.Bytes
			}
		}
	}
	return packets, bytes
}

func (f *Firewall) addElement(ctx context.Context, ip string, ttl time.Duration) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid ip %q", ip)
	}
	_, err := f.Run(ctx, "", "nft", "add", "element", "inet", nftTable, setFor(parsed),
		fmt.Sprintf("{ %s timeout %ds }", parsed.String(), int(ttl.Seconds())))
	return err
}

func (f *Firewall) save() error {
	return f.State.SaveJSON(blocksFile, f.blocks)
}

func setFor(ip net.IP) string {
	if ip.To4() != nil {
		return "blocked4"
	}
	return "blocked6"
}
