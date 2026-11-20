package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// maxDocumentBytes bounds a fetched metadata document or key set (64 KiB).
const maxDocumentBytes = 65536

// specialHosts are the RFC 6761 / special-use names that never host a client document.
var specialHosts = []string{"localhost", ".localhost", ".local", ".internal", ".home.arpa", ".onion", ".test", ".example", ".invalid", ".arpa"}

var (
	numericHost = regexp.MustCompile(`(?i)^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$`)
	dottedQuad  = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
)

// extraReserved are the IPv4 and IPv6 ranges netip does not classify but that are never public.
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

// assertPublicHTTPSURL refuses a URL a client document or key set cannot live at: not https on
// port 443 with a host and a path, credentials or a fragment, a numeric or special-use address,
// a special-use name. The name is not resolved here; the default HTTP client refuses non-public
// addresses at connect time.
func assertPublicHTTPSURL(raw, what string) error {
	u, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(raw, "https://") || u.Host == "" || u.EscapedPath() == "" ||
		strings.ContainsAny(raw, "#@") || (u.Port() != "" && u.Port() != "443") {
		return refusal(CodeInvalidClientMetadata, what+" is https on port 443, with a host and a path, without credentials or a fragment.")
	}
	lower := strings.ToLower(what[:1]) + what[1:]
	host := strings.TrimRight(strings.ToLower(u.Hostname()), ".")
	numeric := numericHost.MatchString(host)
	addr, ipErr := netip.ParseAddr(host)
	if numeric || ipErr == nil || strings.Contains(host, ":") {
		if ipErr != nil || !publicAddr(addr) || (numeric && !dottedQuad.MatchString(host)) {
			return refusal(CodeInvalidClientMetadata, "A special-use or numeric address cannot host "+lower+".")
		}
		return nil
	}
	for _, special := range specialHosts {
		if host == strings.Trim(special, ".") || strings.HasSuffix(host, special) {
			return refusal(CodeInvalidClientMetadata, "A special-use name cannot host "+lower+".")
		}
	}
	return nil
}

var errNonPublicAddress = errors.New("oauth: refusing to connect to a non-public address")

// guardedClient is the default fetcher: it connects to public addresses only, so a public name
// that resolves to an internal address is refused too.
func guardedClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			addr, err := netip.ParseAddr(host)
			if err != nil || !publicAddr(addr.Unmap()) || addr.Is4In6() {
				return errNonPublicAddress
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			ForceAttemptHTTP2:   true,
		},
	}
}

// fetchJSON GETs url and decodes a JSON object of at most 64 KiB; failures carry code (400). A
// JSON list decodes to an empty object, as PHP's array would read. The reason a fetch failed is
// logged, never answered: it would tell a caller which internal hosts this server reaches.
func fetchJSON(ctx context.Context, client *http.Client, log *slog.Logger, rawURL, code string) (map[string]any, error) {
	failed := refusal(code, "The document at "+rawURL+" could not be fetched, or is too large.")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, refusal(code, "The document at "+rawURL+" could not be fetched.")
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.WarnContext(ctx, "oauth: fetching a client document failed", "url", rawURL, "error", err)
		return nil, refusal(code, "The document at "+rawURL+" could not be fetched.")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocumentBytes+1))
	if err != nil || resp.StatusCode != http.StatusOK || len(body) > maxDocumentBytes {
		return nil, failed
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, refusal(code, rawURL+" is not a JSON object.")
	}
	switch v := decoded.(type) {
	case map[string]any:
		return v, nil
	case []any:
		return map[string]any{}, nil
	default:
		return nil, refusal(code, rawURL+" is not a JSON object.")
	}
}
