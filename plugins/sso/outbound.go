package sso

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"syscall"
	"time"
)

// An organization admin names the OIDC issuer and the domain to verify, so every outbound request
// would otherwise reach whatever address they choose (cloud metadata, internal services). The
// default client connects to public addresses only and never follows redirects.
// ponytail: same guard as plugins/oauth/fetch.go; move it to a shared internal package when a
// third plugin needs it.

// extraReserved are the ranges netip does not classify but that are never public.
var extraReserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// publicAddr reports whether a is a public unicast address.
func publicAddr(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" || a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range extraReserved {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var errNonPublicAddress = errors.New("sso: refusing to connect to a non-public address")

// guardedControl refuses a connection to a non-public address (the name is resolved already).
func guardedControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || !publicAddr(addr) {
		return errNonPublicAddress
	}
	return nil
}

func guardedClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: guardedControl}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second, ForceAttemptHTTP2: true},
	}
}

// noRedirects is a copy of c (the guarded client when nil) that never follows a redirect.
func noRedirects(c *http.Client) *http.Client {
	if c == nil {
		c = guardedClient()
	}
	cp := *c
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}

// DomainVerifier proves an organization controls a domain: a DNS TXT record _polaris.<domain> or
// the file https://<domain>/.well-known/polaris-sso.txt carrying the domain's token.
type DomainVerifier interface {
	// Verify reports how the domain was proven ("dns", "https"), "" when it was not.
	Verify(ctx context.Context, domain, token string) string
}

// DNSHTTPSVerifier is the default DomainVerifier: the DNS TXT records first, then the well-known
// file over HTTPS.
type DNSHTTPSVerifier struct {
	// LookupTXT returns the TXT values of a name; net.DefaultResolver's by default.
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	// HTTP fetches the well-known file; nil skips the HTTPS check. The plugin's default refuses
	// non-public addresses and redirects.
	HTTP *http.Client
}

// maxWellKnownBytes bounds the well-known file read.
const maxWellKnownBytes = 1024

// Verify implements DomainVerifier. A lookup or fetch failure is "not proven".
func (v DNSHTTPSVerifier) Verify(ctx context.Context, domain, token string) string {
	lookup := v.LookupTXT
	if lookup == nil {
		lookup = net.DefaultResolver.LookupTXT
	}
	if values, err := lookup(ctx, DNSRecord+"."+domain); err == nil &&
		slices.ContainsFunc(values, func(s string) bool { return strings.TrimSpace(s) == token }) {
		return "dns"
	}
	if v.HTTP == nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+WellKnownPath, nil)
	if err != nil {
		return ""
	}
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxWellKnownBytes))
	if err != nil || resp.StatusCode != http.StatusOK || subtle.ConstantTimeCompare([]byte(token), []byte(strings.TrimSpace(string(body)))) != 1 {
		return ""
	}
	return "https"
}
