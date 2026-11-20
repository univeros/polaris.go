package sso

import (
	"context"
	"crypto/subtle"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
)

// An organization admin names the OIDC issuer and the domain to verify, so every outbound request
// would otherwise reach whatever address they choose (cloud metadata, internal services). The
// default client connects to public addresses only and never follows redirects.
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
