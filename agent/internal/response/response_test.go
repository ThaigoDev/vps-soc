package response

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"vps-soc/agent/internal/event"
	"vps-soc/agent/internal/state"
)

type fakeNft struct {
	mu    sync.Mutex
	calls []string
}

func (f *fakeNft) run(_ context.Context, stdin, name string, args ...string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if len(args) > 0 && args[0] == "-j" {
		return `{"nftables":[{"metainfo":{}},{"rule":{"expr":[{"match":{}},{"counter":{"packets":12,"bytes":720}},{"drop":null}]}},` +
			`{"rule":{"expr":[{"counter":{"packets":3,"bytes":240}}]}}]}`, nil
	}
	return "", nil
}

func newFirewall(t *testing.T) (*Firewall, *fakeNft) {
	st, err := state.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeNft{}
	fw := NewFirewall(st)
	fw.Run = fake.run
	if err := fw.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	return fw, fake
}

func TestAllowlistProtectsOwnerPaths(t *testing.T) {
	a, err := NewAllowlist("203.0.113.9, 198.51.100.0/24", "http://100.111.247.53:8088")
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"127.0.0.1", "100.111.247.53", "100.80.1.2", "169.254.0.1", "192.168.1.10", "203.0.113.9", "198.51.100.77", "::1"} {
		if ok, _ := a.Protected(net.ParseIP(ip)); !ok {
			t.Errorf("%s should be protected", ip)
		}
	}
	for _, ip := range []string{"45.33.10.1", "185.220.101.7", "2001:db8::1"} {
		if ok, _ := a.Protected(net.ParseIP(ip)); ok {
			t.Errorf("%s should be blockable", ip)
		}
	}
	if _, err := NewAllowlist("not-an-ip", ""); err == nil {
		t.Error("invalid entry must fail")
	}
}

func TestFirewallBlockPersistsAndRestores(t *testing.T) {
	fw, fake := newFirewall(t)
	b, err := fw.Block(context.Background(), net.ParseIP("45.33.10.1"), 2*time.Hour, "brute force", "agent")
	if err != nil {
		t.Fatal(err)
	}
	if !fw.IsBlocked("45.33.10.1") || b.Until.Before(time.Now().Add(119*time.Minute)) {
		t.Fatalf("block not recorded: %+v", b)
	}
	last := fake.calls[len(fake.calls)-1]
	if !strings.Contains(last, "add element inet vps_soc blocked4 { 45.33.10.1 timeout 7200s }") {
		t.Errorf("unexpected nft call %q", last)
	}
	if _, err := fw.Block(context.Background(), net.ParseIP("2001:db8::1"), time.Hour, "x", "soc"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fake.calls[len(fake.calls)-1], "blocked6") {
		t.Error("IPv6 must go to blocked6")
	}

	// A fresh agent (e.g. after reboot) re-applies the still-valid blocks.
	fw2 := NewFirewall(fw.State)
	fake2 := &fakeNft{}
	fw2.Run = fake2.run
	if err := fw2.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !fw2.IsBlocked("45.33.10.1") || !fw2.IsBlocked("2001:db8::1") {
		t.Error("blocks not restored")
	}

	s := fw2.Stats(context.Background())
	if s.BlockedIPs != 2 || s.DroppedPackets != 15 || s.DroppedBytes != 960 {
		t.Errorf("stats %+v", s)
	}

	if err := fw2.Unblock(context.Background(), net.ParseIP("45.33.10.1")); err != nil || fw2.IsBlocked("45.33.10.1") {
		t.Errorf("unblock failed: %v", err)
	}
}

func TestExecutorRefusesProtectedAndUnknown(t *testing.T) {
	fw, _ := newFirewall(t)
	a, _ := NewAllowlist("", "")
	x := &Executor{Enabled: true, Firewall: fw, Allowlist: a, Run: (&fakeNft{}).run}

	r := x.Execute(context.Background(), Action{ID: 1, Type: BlockIP, Params: map[string]any{"ip": "100.111.247.53", "ttlSeconds": 3600.0}})
	if r.Status != StatusRejected {
		t.Errorf("tailscale IP must be refused, got %+v", r)
	}
	r = x.Execute(context.Background(), Action{ID: 2, Type: "RUN_SHELL", Params: map[string]any{"cmd": "rm -rf /"}})
	if r.Status != StatusRejected {
		t.Errorf("unknown action must be refused, got %+v", r)
	}
	r = x.Execute(context.Background(), Action{ID: 3, Type: RestartService, Params: map[string]any{"unit": "nginx; reboot"}})
	if r.Status != StatusRejected {
		t.Errorf("bad unit name must be refused, got %+v", r)
	}
	r = x.Execute(context.Background(), Action{ID: 4, Type: KillProcess, Params: map[string]any{"pid": 1.0}})
	if r.Status != StatusRejected {
		t.Errorf("pid 1 must be refused, got %+v", r)
	}
	r = x.Execute(context.Background(), Action{ID: 5, Type: BlockIP, Params: map[string]any{"ip": "45.33.10.1", "ttlSeconds": 3600.0}})
	if r.Status != StatusSucceeded || !fw.IsBlocked("45.33.10.1") {
		t.Errorf("public IP should be blocked, got %+v", r)
	}

	x.Enabled = false
	if r := x.Execute(context.Background(), Action{ID: 6, Type: DiskCleanup}); r.Status != StatusRejected {
		t.Errorf("disabled executor must refuse, got %+v", r)
	}
}

func TestGuardBlocksBurstButNotKnownGoodIP(t *testing.T) {
	fw, _ := newFirewall(t)
	a, _ := NewAllowlist("", "")
	var emitted []event.Event
	g := &Guard{Enabled: true, Threshold: 5, Window: time.Minute, TTL: time.Hour, Firewall: fw, Allowlist: a, State: fw.State,
		Emit: func(e event.Event) { emitted = append(emitted, e) }}
	g.Load()
	now := time.Now()

	// The owner logged in cleanly from this IP before, then mistypes the password.
	g.Observe(event.Event{Type: event.SSHLoginSuccess, OccurredAt: now.Add(-time.Hour), SourceIP: "203.0.113.50"})
	for i := 0; i < 6; i++ {
		g.Observe(event.Event{Type: event.SSHFailedLogin, OccurredAt: now, SourceIP: "203.0.113.50"})
	}
	if fw.IsBlocked("203.0.113.50") {
		t.Error("known-good IP must not be auto-blocked")
	}

	for i := 0; i < 4; i++ {
		g.Observe(event.Event{Type: event.SSHInvalidUser, OccurredAt: now, SourceIP: "45.33.10.1"})
	}
	if fw.IsBlocked("45.33.10.1") {
		t.Error("below threshold must not block")
	}
	g.Observe(event.Event{Type: event.SSHFailedLogin, OccurredAt: now, SourceIP: "45.33.10.1"})
	if !fw.IsBlocked("45.33.10.1") {
		t.Fatal("burst should be blocked")
	}
	if len(emitted) != 1 || emitted[0].Type != event.ResponseExecuted || emitted[0].Metadata["status"] != StatusSucceeded {
		t.Errorf("expected one RESPONSE_EXECUTED event, got %+v", emitted)
	}

	// Brute force that then succeeds does not make the attacker "known good".
	for i := 0; i < 4; i++ {
		g.Observe(event.Event{Type: event.SSHFailedLogin, OccurredAt: now, SourceIP: "198.51.100.66"})
	}
	g.Observe(event.Event{Type: event.SSHLoginSuccess, OccurredAt: now, SourceIP: "198.51.100.66"})
	if _, ok := g.knownGood["198.51.100.66"]; ok {
		t.Error("login after a failure burst must not be trusted")
	}

	// Old lines replayed from the journal after a restart never block.
	for i := 0; i < 10; i++ {
		g.Observe(event.Event{Type: event.SSHFailedLogin, OccurredAt: now.Add(-time.Hour), SourceIP: "45.33.10.99"})
	}
	if fw.IsBlocked("45.33.10.99") {
		t.Error("replayed old failures must not block")
	}
}

func TestParseCountersIgnoresGarbage(t *testing.T) {
	if p, b := ParseCounters("not json"); p != 0 || b != 0 {
		t.Error("garbage must give zero")
	}
}
