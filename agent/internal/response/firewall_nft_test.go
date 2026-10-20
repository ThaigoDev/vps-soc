//go:build nftintegration

// Runs the firewall against a real nftables (needs root + CAP_NET_ADMIN):
//
//	docker run --rm --cap-add NET_ADMIN -v "$PWD:/src" -w /src golang:1.23-alpine \
//	  sh -c 'apk add -q nftables && go test -tags nftintegration ./internal/response/'
package response

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"vps-soc/agent/internal/state"
)

func TestRealNftables(t *testing.T) {
	ctx := context.Background()
	st, _ := state.New(t.TempDir())
	fw := NewFirewall(st)
	if err := fw.Init(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	if _, err := fw.Block(ctx, net.ParseIP("45.33.10.1"), time.Hour, "test", "agent"); err != nil {
		t.Fatalf("block v4: %v", err)
	}
	if _, err := fw.Block(ctx, net.ParseIP("45.33.10.1"), 2*time.Hour, "extend", "agent"); err != nil {
		t.Fatalf("re-block (extend): %v", err)
	}
	if _, err := fw.Block(ctx, net.ParseIP("2001:db8::1"), time.Hour, "test", "agent"); err != nil {
		t.Fatalf("block v6: %v", err)
	}
	out, err := DefaultRunner(ctx, "", "nft", "list", "table", "inet", nftTable)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(out)
	for _, want := range []string{"45.33.10.1", "2001:db8::1", "hook prerouting priority -200", "counter", "drop"} {
		if !strings.Contains(out, want) {
			t.Errorf("ruleset missing %q", want)
		}
	}
	s := fw.Stats(ctx)
	if !s.Enabled || s.BlockedIPs != 2 {
		t.Errorf("stats %+v", s)
	}
	if err := fw.Unblock(ctx, net.ParseIP("45.33.10.1")); err != nil {
		t.Fatal(err)
	}
	out, _ = DefaultRunner(ctx, "", "nft", "list", "set", "inet", nftTable, "blocked4")
	if strings.Contains(out, "45.33.10.1") {
		t.Error("unblock did not remove the element")
	}
	// Re-init (agent restart) keeps the remaining block.
	fw2 := NewFirewall(st)
	if err := fw2.Init(ctx); err != nil {
		t.Fatal(err)
	}
	out, _ = DefaultRunner(ctx, "", "nft", "list", "set", "inet", nftTable, "blocked6")
	if !strings.Contains(out, "2001:db8::1") {
		t.Errorf("block not restored after restart: %s", out)
	}
}
