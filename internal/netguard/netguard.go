// Package netguard is the outbound-request guard plugins use when a URL comes from a tenant or a
// client (OIDC issuers, client metadata documents, jwks_uri, domain-verification files): connect
// only to public unicast addresses, decided after DNS resolution, so a public name that resolves to
// an internal address (cloud metadata, internal services) is refused too.
package netguard

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
)

// ErrNonPublicAddress is returned when a connection would reach a non-public address.
var ErrNonPublicAddress = errors.New("netguard: refusing to connect to a non-public address")

// reserved are the IPv4 and IPv6 ranges netip does not classify but that are never public.
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fec0::/10"),
}

// PublicAddr reports whether a is a public unicast address (IPv4-mapped IPv6 and zoned addresses
// are not).
func PublicAddr(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range reserved {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Control is a net.Dialer Control refusing connections to non-public addresses.
func Control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !PublicAddr(addr) {
		return ErrNonPublicAddress
	}
	return nil
}

// Client returns an HTTP client that connects to public addresses only (5 s dial, 10 s overall).
func Client() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: Control}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
}

// NoRedirects returns a copy of c (Client() when nil) that never follows a redirect.
func NoRedirects(c *http.Client) *http.Client {
	if c == nil {
		c = Client()
	}
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}
