package oauth

import (
	"context"
	"encoding/json"
	"github.com/univeros/polaris.go/internal/netguard"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// maxDocumentBytes bounds a fetched metadata document or key set (64 KiB).
const maxDocumentBytes = 65536

// specialHosts are the RFC 6761 / special-use names that never host a client document.
var specialHosts = []string{"localhost", ".localhost", ".local", ".internal", ".home.arpa", ".onion", ".test", ".example", ".invalid", ".arpa"}

var (
	numericHost = regexp.MustCompile(`(?i)^(0x[0-9a-f]+|[0-9]+)(\.(0x[0-9a-f]+|[0-9]+))*$`)
	dottedQuad  = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
)

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
		if ipErr != nil || !netguard.PublicAddr(addr) || (numeric && !dottedQuad.MatchString(host)) {
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

// fetchJSON GETs url and decodes a JSON object of at most 64 KiB; failures carry code (400). Any
// other JSON value is refused: a metadata document and a JWK Set are objects. The reason a fetch
// failed is logged, never answered: it would tell a caller which internal hosts this server reaches.
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
	if v, ok := decoded.(map[string]any); ok {
		return v, nil
	}
	return nil, refusal(code, rawURL+" is not a JSON object.")
}
