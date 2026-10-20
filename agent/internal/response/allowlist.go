// Package response executes the agent's containment actions. It only knows a fixed set of
// actions with validated parameters: the backend can ask for "block this IP" or "kill this
// suspicious process", never run an arbitrary command.
package response

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// defaultProtected are ranges that are never blocked: loopback, private networks, CGNAT
// (Tailscale 100.64.0.0/10) and link-local (Hostinger's hPanel terminal uses 169.254.0.1).
// Blocking any of them risks cutting the owner's own access or the link to the SOC.
var defaultProtected = []string{
	"0.0.0.0/8", "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
	"100.64.0.0/10", "169.254.0.0/16",
	"::1/128", "fc00::/7", "fe80::/10", "fd7a:115c:a1e0::/48",
}

// Allowlist decides which addresses may never be blocked.
type Allowlist struct {
	nets []*net.IPNet
}

// NewAllowlist combines the built-in ranges, the operator's extra entries (IPs or CIDRs,
// comma-separated) and the addresses the SOC server name resolves to.
func NewAllowlist(extra string, serverURL string) (*Allowlist, error) {
	a := &Allowlist{}
	entries := append([]string{}, defaultProtected...)
	for _, e := range strings.Split(extra, ",") {
		if e = strings.TrimSpace(e); e != "" {
			entries = append(entries, e)
		}
	}
	if u, err := url.Parse(serverURL); err == nil && u.Hostname() != "" {
		if ips, err := net.LookupIP(u.Hostname()); err == nil {
			for _, ip := range ips {
				entries = append(entries, ip.String())
			}
		}
	}
	for _, e := range entries {
		if err := a.add(e); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (a *Allowlist) add(entry string) error {
	if !strings.Contains(entry, "/") {
		ip := net.ParseIP(entry)
		if ip == nil {
			return fmt.Errorf("invalid allowlist entry %q", entry)
		}
		bits := 128
		if ip.To4() != nil {
			ip, bits = ip.To4(), 32
		}
		entry = fmt.Sprintf("%s/%d", ip, bits)
	}
	_, n, err := net.ParseCIDR(entry)
	if err != nil {
		return fmt.Errorf("invalid allowlist entry %q: %w", entry, err)
	}
	a.nets = append(a.nets, n)
	return nil
}

// Protected reports whether ip must never be blocked, and why.
func (a *Allowlist) Protected(ip net.IP) (bool, string) {
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true, n.String()
		}
	}
	return false, ""
}
