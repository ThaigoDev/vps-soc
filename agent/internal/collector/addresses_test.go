package collector

import (
	"net/netip"
	"testing"
)

func TestIsPublicAddr(t *testing.T) {
	cases := map[string]bool{
		"82.25.79.73":          true,
		"2a02:4780:14:f6c5::1": true,
		"10.0.0.5":             false,
		"192.168.1.10":         false,
		"172.17.0.1":           false,
		"100.80.183.61":        false, // Tailscale / CGNAT
		"127.0.0.1":            false,
		"169.254.0.1":          false,
		"fe80::1":              false,
		"fd7a:115c:a1e0::1":    false, // Tailscale IPv6 (ULA)
		"203.0.113.10":         false,
	}
	for s, want := range cases {
		if got := IsPublicAddr(netip.MustParseAddr(s)); got != want {
			t.Errorf("IsPublicAddr(%s) = %v, want %v", s, got, want)
		}
	}
}
