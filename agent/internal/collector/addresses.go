package collector

import (
	"net"
	"net/netip"
)

// cgnat is 100.64.0.0/10: carrier-grade NAT, also used by Tailscale. Not reachable from the internet.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// PublicAddresses lists the internet-routable addresses configured on this host's interfaces
// (a VPS usually has its public IPv4 on eth0). The SOC uses them to place the server on the map.
func PublicAddresses() []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip, ok := netip.AddrFromSlice(n.IP); ok && IsPublicAddr(ip.Unmap()) {
			out = append(out, ip.Unmap().String())
		}
	}
	return out
}

// IsPublicAddr reports whether ip is a global unicast address outside private, CGNAT and
// documentation ranges.
func IsPublicAddr(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || cgnat.Contains(ip) {
		return false
	}
	for _, doc := range documentation {
		if doc.Contains(ip) {
			return false
		}
	}
	return true
}

var documentation = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}
