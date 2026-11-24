package netguard

import "net/netip"

// ipv6RateBits is the prefix length an IPv6 client is rate limited by.
const ipv6RateBits = 64

// RateKey is the rate-limit key of a client address, "unknown" for none. An IPv6 address is keyed by
// its /64 (one subscriber holds at least that many addresses, so a budget per address would be none);
// an IPv4-mapped one by its IPv4 address.
func RateKey(ip string) string {
	if ip == "" {
		return "unknown"
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	if addr = addr.Unmap().WithZone(""); addr.Is4() {
		return addr.String()
	}
	prefix, _ := addr.Prefix(ipv6RateBits)
	return prefix.String()
}
