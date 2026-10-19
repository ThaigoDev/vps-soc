package collector

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"vps-soc/agent/internal/event"
	"vps-soc/agent/internal/state"
)

type Listener struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Process string `json:"process,omitempty"`
	Exe     string `json:"exe,omitempty"`
	PID     int    `json:"pid,omitempty"`
	User    string `json:"user,omitempty"`
}

func (l Listener) key() string { return fmt.Sprintf("%s/%s/%d", l.Proto, l.Address, l.Port) }

const portsStateFile = "ports.json"

// PortMonitor snapshots TCP listening sockets and emits an event for every
// port that appears or disappears between snapshots.
type PortMonitor struct {
	Interval time.Duration
	State    *state.Store
	Emit     func(event.Event)

	mu      sync.RWMutex
	current []Listener
}

// Current returns the latest snapshot (shipped with the heartbeat).
func (m *PortMonitor) Current() []Listener {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current
}

func (m *PortMonitor) Run(ctx context.Context) {
	var prev map[string]Listener
	found, err := m.State.LoadJSON(portsStateFile, &prev)
	if err != nil {
		log.Printf("ports state unreadable, rebuilding baseline: %v", err)
		found = false
	}

	ticker := time.NewTicker(m.Interval)
	defer ticker.Stop()
	for {
		listeners, err := ListListeners()
		if err != nil {
			log.Printf("port scan: %v", err)
		} else {
			now := map[string]Listener{}
			for _, l := range listeners {
				now[l.key()] = l
			}
			if !found {
				m.Emit(event.Event{
					Type: event.PortBaseline, OccurredAt: time.Now(),
					Message:  fmt.Sprintf("baseline of %d listening ports recorded", len(listeners)),
					Metadata: map[string]any{"ports": listeners},
				})
				found = true
			} else {
				m.diff(prev, now)
			}
			prev = now
			if err := m.State.SaveJSON(portsStateFile, now); err != nil {
				log.Printf("save ports state: %v", err)
			}
			m.mu.Lock()
			m.current = listeners
			m.mu.Unlock()
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (m *PortMonitor) diff(prev, now map[string]Listener) {
	ts := time.Now()
	for k, l := range now {
		if _, ok := prev[k]; !ok {
			m.Emit(listenerEvent(event.PortOpened, l, ts))
		}
	}
	for k, l := range prev {
		if _, ok := now[k]; !ok {
			m.Emit(listenerEvent(event.PortClosed, l, ts))
		}
	}
}

func listenerEvent(typ string, l Listener, ts time.Time) event.Event {
	verb := "opened"
	if typ == event.PortClosed {
		verb = "closed"
	}
	return event.Event{
		Type: typ, OccurredAt: ts, Username: l.User,
		Message: fmt.Sprintf("%s port %s:%d %s (process %s, pid %d)", l.Proto, l.Address, l.Port, verb, l.Process, l.PID),
		Metadata: map[string]any{
			"proto": l.Proto, "address": l.Address, "port": l.Port,
			"process": l.Process, "exe": l.Exe, "pid": l.PID,
		},
	}
}

// ListListeners reads /proc/net/tcp{,6} and resolves the owning process.
func ListListeners() ([]Listener, error) {
	owners := socketOwners()
	var out []Listener
	for _, f := range []struct{ path, proto string }{{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"}} {
		file, err := os.Open(f.path)
		if err != nil {
			if f.proto == "tcp6" {
				continue // IPv6 disabled
			}
			return nil, err
		}
		sc := bufio.NewScanner(file)
		sc.Scan() // header
		for sc.Scan() {
			l, inode, uid, ok := parseProcNetLine(sc.Text(), f.proto)
			if !ok {
				continue
			}
			if o, ok := owners[inode]; ok {
				l.PID, l.Process, l.Exe = o.pid, o.comm, o.exe
			}
			l.User = lookupUser(uid)
			out = append(out, l)
		}
		file.Close()
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].key() < out[j].key()
	})
	return out, nil
}

// PublicListenerPIDs returns the processes holding a TCP socket that listens on a
// non-loopback address. Process managers that legitimately spawn shells (systemd
// socket activation, sshd) are left out.
func PublicListenerPIDs() map[int]bool {
	inodes := map[string]bool{}
	for _, f := range []struct{ path, proto string }{{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"}} {
		b, err := os.ReadFile(f.path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			if l, inode, _, ok := parseProcNetLine(line, f.proto); ok && isExposedAddress(l.Address) {
				inodes[inode] = true
			}
		}
	}
	out := map[int]bool{}
	if len(inodes) == 0 {
		return out
	}
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range pids {
		pid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil || pid == 1 {
			continue
		}
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(dir + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			if inodes[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] {
				comm, _ := os.ReadFile(dir + "/comm")
				if !shellLaunchers(strings.TrimSpace(string(comm))) {
					out[pid] = true
				}
				break
			}
		}
	}
	return out
}

func shellLaunchers(comm string) bool {
	return strings.HasPrefix(comm, "sshd") || strings.HasPrefix(comm, "systemd") || comm == "tailscaled"
}

func isExposedAddress(addr string) bool {
	ip := net.ParseIP(addr)
	return ip != nil && !ip.IsLoopback()
}

const tcpListen = "0A"

// parseProcNetLine parses one /proc/net/tcp row, keeping only LISTEN sockets:
//
//	sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
//	0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0  0 18291 ...
func parseProcNetLine(line, proto string) (l Listener, inode, uid string, ok bool) {
	f := strings.Fields(line)
	if len(f) < 10 || f[3] != tcpListen {
		return l, "", "", false
	}
	addrHex, portHex, found := strings.Cut(f[1], ":")
	if !found {
		return l, "", "", false
	}
	port, err := strconv.ParseInt(portHex, 16, 32)
	if err != nil {
		return l, "", "", false
	}
	ip, err := decodeProcIP(addrHex)
	if err != nil {
		return l, "", "", false
	}
	return Listener{Proto: proto, Address: ip.String(), Port: int(port)}, f[9], f[7], true
}

// decodeProcIP decodes the kernel's hex address: each 32-bit word is stored
// in host (little-endian) byte order.
func decodeProcIP(s string) (net.IP, error) {
	b, err := hex.DecodeString(s)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return nil, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return net.IP(b), nil
}

type owner struct {
	pid       int
	comm, exe string
}

// socketOwners maps socket inode -> process by scanning /proc/<pid>/fd (needs root).
func socketOwners() map[string]owner {
	out := map[string]owner{}
	pids, _ := filepath.Glob("/proc/[0-9]*")
	for _, dir := range pids {
		pid, err := strconv.Atoi(filepath.Base(dir))
		if err != nil {
			continue
		}
		fds, err := os.ReadDir(dir + "/fd")
		if err != nil {
			continue
		}
		var o *owner
		for _, fd := range fds {
			target, err := os.Readlink(dir + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			if o == nil {
				comm, _ := os.ReadFile(dir + "/comm")
				exe, _ := os.Readlink(dir + "/exe")
				o = &owner{pid: pid, comm: strings.TrimSpace(string(comm)), exe: exe}
			}
			out[strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")] = *o
		}
	}
	return out
}

var userCache sync.Map

func lookupUser(uid string) string {
	if v, ok := userCache.Load(uid); ok {
		return v.(string)
	}
	name := uid
	if u, err := user.LookupId(uid); err == nil {
		name = u.Username
	}
	userCache.Store(uid, name)
	return name
}
