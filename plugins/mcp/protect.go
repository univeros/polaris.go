package mcp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/wiring"
)

const (
	// ProtocolVersion is the MCP revision served: the 2026-07-28 stateless profile.
	ProtocolVersion = "2026-07-28"
	// WellKnown is the RFC 9728 metadata path; the resource's path is appended to it.
	WellKnown   = "/.well-known/oauth-protected-resource"
	maxBodySize = 4 << 20
)

// ProtectConfig configures [Protect]. Resource is required, and the issuer's keys come from
// exactly one of JWKSURL (a remote Polaris), Keys or Graph (Polaris in the same process).
type ProtectConfig struct {
	// Resource is the MCP server's URL, the aud a token must name ("https://tools.example.com/mcp").
	Resource string
	// Issuer is the authorization server, the iss a token must carry ("https://auth.example.com").
	// Default with Graph: the graph's Auth.Issuer.
	Issuer string
	// JWKSURL is the issuer's JWK Set (https), e.g. "https://auth.example.com/auth/.well-known/jwks.json".
	// It is fetched once, cached for JWKSTTL, and fetched again for an unknown kid at most once a minute.
	JWKSURL string
	// Keys are the issuer's verification keys by kid, for an issuer whose keys you hold.
	Keys map[string]crypto.PublicKey
	// Graph is Polaris in this process: its issuer, signing keys (current and previous), cache and clock.
	Graph *wiring.Graph

	// Audiences are further aud values naming this resource (Polaris's own /mcp accepts its issuer).
	Audiences []string
	// Scopes must all be held by every request's token; a token short of one is answered 403
	// insufficient_scope naming the missing ones, so the client steps up.
	Scopes []string
	// ScopesSupported is what the metadata advertises; default Scopes.
	ScopesSupported []string
	// AllowLegacy serves the 2025 session-based protocol too; by default it is answered 400.
	AllowLegacy bool
	// MetadataURL is where the RFC 9728 document is served; default the path-inserted well-known
	// URL of Resource ("https://tools.example.com/.well-known/oauth-protected-resource/mcp").
	MetadataURL string
	// ResourceName is the metadata's resource_name; omitted when empty.
	ResourceName string

	HTTPClient *http.Client  // JWKS fetches; default a client with a 10 s timeout
	JWKSTTL    time.Duration // default DefaultJWKSTTL
	Cache      cache.Cache   // DPoP replay; default the graph's, else in-memory (share one across replicas)
	Clock      clock.Clock   // default the graph's, else the system clock
	Logger     *slog.Logger  // why a JWKS fetch failed; default slog.Default()
}

// ProtectedResource guards an MCP server as RFC 9728 and the MCP authorization profile have it.
// Build it with [NewProtectedResource]; it is safe for concurrent use.
type ProtectedResource struct {
	resource     string
	metadataURL  string
	metadataPath string
	origin       string
	scopes       []string
	supported    []string
	name         string
	legacy       bool
	verifier     *verifier
	dpop         *dpopProofs
}

// Protect wraps next, an MCP server's handler (one built with the official Go MCP SDK, or any
// other), so that every request carries an access token for cfg.Resource, verified locally, bound
// as it must be and holding cfg.Scopes; the verified claims reach next through [Claims]. It also
// serves the RFC 9728 metadata at the well-known URL, so mount the result where both paths reach
// it (usually "/"):
//
//	h, err := mcp.Protect(mcpHandler, mcp.ProtectConfig{
//		Resource: "https://tools.example.com/mcp",
//		Issuer:   "https://auth.example.com",
//		JWKSURL:  "https://auth.example.com/auth/.well-known/jwks.json",
//		Scopes:   []string{"deploy"},
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	http.Handle("/", h)
//
// Refusals: 401 with WWW-Authenticate: Bearer resource_metadata="..." without a token (the client
// discovers the authorization server from the metadata); 401 error="invalid_token" for a token
// that does not verify, is for another resource or issuer, expired, or presented against its DPoP
// binding; 403 error="insufficient_scope" scope="<missing>"; 400 mcp/legacy_protocol for the 2025
// session protocol unless AllowLegacy.
func Protect(next http.Handler, cfg ProtectConfig) (http.Handler, error) {
	pr, err := NewProtectedResource(cfg)
	if err != nil {
		return nil, err
	}
	return pr.Handler(next), nil
}

var originPattern = regexp.MustCompile(`^https?://[^/\s]+`)

// NewProtectedResource validates cfg; every problem is reported at once, naming its fix.
func NewProtectedResource(cfg ProtectConfig) (*ProtectedResource, error) {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf("mcp: "+format, args...)) }
	origin := originPattern.FindString(cfg.Resource)
	if origin == "" {
		bad("ProtectConfig.Resource %q must be the MCP server's absolute http(s) URL, e.g. \"https://tools.example.com/mcp\"", cfg.Resource)
	}
	clk, store, keys := cfg.Clock, cfg.Cache, map[string]any{}
	if g := cfg.Graph; g != nil {
		if cfg.Issuer == "" {
			cfg.Issuer = g.Auth().Issuer
		}
		clk, store = cmp(clk, g.Clock()), cmp(store, g.Cache())
		var err error
		if keys, err = graphKeys(g); err != nil {
			bad("%v", err)
		}
	}
	if cfg.Issuer == "" {
		bad("ProtectConfig.Issuer is empty: set the Polaris issuer URL (its AUTH_ISSUER), or pass Graph")
	}
	sources := 0
	for _, set := range []bool{cfg.JWKSURL != "", len(cfg.Keys) > 0, cfg.Graph != nil} {
		if set {
			sources++
		}
	}
	if sources != 1 {
		bad("set exactly one of ProtectConfig.JWKSURL (a remote issuer's JWK Set), Keys or Graph; %d are set", sources)
	}
	if cfg.JWKSURL != "" && !strings.HasPrefix(cfg.JWKSURL, "https://") {
		bad("ProtectConfig.JWKSURL %q must be an https URL", cfg.JWKSURL)
	}
	for kid, key := range cfg.Keys {
		keys[kid] = key
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	if clk == nil {
		clk = clock.System{}
	}
	if store == nil {
		store = cache.NewMemory(clk)
	}
	pr := &ProtectedResource{
		resource:    cfg.Resource,
		metadataURL: cfg.MetadataURL,
		origin:      origin,
		scopes:      slices.Clone(cfg.Scopes),
		supported:   cfg.ScopesSupported,
		name:        cfg.ResourceName,
		legacy:      cfg.AllowLegacy,
		verifier: &verifier{
			issuer:    cfg.Issuer,
			audiences: append([]string{cfg.Resource}, cfg.Audiences...),
			clock:     clk,
			keys:      keys,
		},
		dpop: &dpopProofs{cache: store, clock: clk},
	}
	if pr.metadataURL == "" {
		u, _ := url.Parse(cfg.Resource)
		pr.metadataURL = origin + WellKnown + strings.TrimRight(u.Path, "/")
	}
	if u, err := url.Parse(pr.metadataURL); err == nil {
		pr.metadataPath = u.Path
	}
	if pr.supported == nil {
		pr.supported = slices.Clone(pr.scopes)
	}
	if pr.supported == nil {
		pr.supported = []string{}
	}
	if cfg.JWKSURL != "" {
		client := cfg.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: 10 * time.Second}
		}
		ttl := cfg.JWKSTTL
		if ttl <= 0 {
			ttl = DefaultJWKSTTL
		}
		logger := cfg.Logger
		if logger == nil {
			logger = slog.Default()
		}
		pr.verifier.jwks = &jwks{url: cfg.JWKSURL, client: client, ttl: ttl, clock: clk, log: logger.Warn}
	}
	return pr, nil
}

func cmp[T comparable](a, b T) T {
	var zero T
	if a != zero {
		return a
	}
	return b
}

// graphKeys are the graph's verification keys, read from its JWK Set: the active one and, during a
// rotation, the previous (RSA for RS256, Ed25519 for EdDSA).
func graphKeys(g *wiring.Graph) (map[string]any, error) {
	keys := map[string]any{}
	for _, jwk := range g.JWKS().Keys {
		raw, err := json.Marshal(jwk)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		key, err := parseJWK(m, jwk.Alg)
		if err != nil {
			return nil, fmt.Errorf("the graph's public key %q: %w (AUTH_JWT_PUBLIC_KEY)", jwk.Kid, err)
		}
		keys[jwk.Kid] = key
	}
	return keys, nil
}

// MetadataURL is where the RFC 9728 document is served, the URL the challenges name.
func (p *ProtectedResource) MetadataURL() string { return p.metadataURL }

// Metadata is the RFC 9728 document.
func (p *ProtectedResource) Metadata() map[string]any {
	doc := map[string]any{
		"resource":                          p.resource,
		"authorization_servers":             []string{p.verifier.issuer},
		"scopes_supported":                  p.supported,
		"bearer_methods_supported":          []string{"header"},
		"dpop_signing_alg_values_supported": Algorithms,
	}
	if p.name != "" {
		doc["resource_name"] = p.name
	}
	return doc
}

type claimsKey struct{}

// Claims returns the verified access token claims of a request [Protect] let through (numbers as
// json.Number); nil outside it.
func Claims(ctx context.Context) map[string]any {
	c, _ := ctx.Value(claimsKey{}).(map[string]any)
	return c
}

// Handler serves the metadata document and guards every other request; see [Protect].
func (p *ProtectedResource) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == p.metadataPath {
			writeJSON(w, http.StatusOK, "application/json", p.Metadata(), http.Header{"Cache-Control": {"public, max-age=3600"}})
			return
		}
		r, ref := p.rejectLegacy(r)
		if ref == nil {
			var claims map[string]any
			if claims, ref = p.authenticate(r); ref == nil {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims))) //nolint:contextcheck // r.Context() is inherited; the linter follows into dispatch.go's deliberate fresh context
				return
			}
		}
		ref.write(w)
	})
}

// refusal is a refused request: an RFC 9457 problem of type mcp/<name>.
type refusal struct {
	name      string
	detail    string
	status    int
	challenge string
	ext       map[string]any
}

func (e *refusal) write(w http.ResponseWriter) {
	body := map[string]any{
		"type":    endpoint.ProblemTypes + "mcp/" + e.name,
		"title":   title(e.name),
		"status":  e.status,
		"detail":  e.detail,
		"error":   "mcp_" + e.name,
		"message": e.detail,
	}
	for k, v := range e.ext {
		body[k] = v
	}
	h := http.Header{"Cache-Control": {"no-store"}}
	if e.challenge != "" {
		h.Set("WWW-Authenticate", e.challenge)
	}
	writeJSON(w, e.status, "application/problem+json", body, h)
}

// title is PHP's ucwords(str_replace('_', ' ', name)).
func title(name string) string {
	words := strings.Split(name, "_")
	for i, w := range words {
		if w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

func writeJSON(w http.ResponseWriter, status int, contentType string, body any, extra http.Header) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	for k, v := range extra {
		h[k] = v
	}
	w.WriteHeader(status)
	_, _ = w.Write(encodeJSON(body))
}

func encodeJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal server error."}}`)
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
}

// rejectLegacy refuses the 2025 handshake (a session header, an older protocol version, an
// initialize call) before any token is looked at, unless AllowLegacy. The body stays readable.
func (p *ProtectedResource) rejectLegacy(r *http.Request) (*http.Request, *refusal) {
	if p.legacy {
		return r, nil
	}
	version := r.Header.Get("MCP-Protocol-Version")
	legacy := r.Header.Get("Mcp-Session-Id") != "" || (version != "" && version < ProtocolVersion)
	if !legacy && r.Method == http.MethodPost && r.Body != nil && r.Body != http.NoBody {
		body, _ := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
		r.Body = io.NopCloser(bytes.NewReader(body))
		var msg struct {
			Method any `json:"method"`
		}
		legacy = len(body) <= maxBodySize && json.Unmarshal(body, &msg) == nil && msg.Method == "initialize"
	}
	if !legacy {
		return r, nil
	}
	return r, &refusal{
		name:   "legacy_protocol",
		detail: "This server speaks MCP " + ProtocolVersion + " (stateless); the session-based protocol is not served.",
		status: http.StatusBadRequest,
		ext:    map[string]any{"protocol_version": ProtocolVersion},
	}
}

var authorizationPattern = regexp.MustCompile(`(?i)^(Bearer|DPoP)\s+(\S+)$`)

// authenticate returns the claims of the token the request presents for this resource, bound as
// it must be and holding the required scopes.
func (p *ProtectedResource) authenticate(r *http.Request) (map[string]any, *refusal) {
	m := authorizationPattern.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil {
		return nil, &refusal{name: "unauthorized", detail: "An access token for this resource is required.",
			status: http.StatusUnauthorized, challenge: p.challenge("", "", "")}
	}
	scheme, raw := m[1], m[2]
	claims, err := p.verifier.verify(r.Context(), raw)
	if err == nil {
		err = p.assertBinding(r, scheme, raw, claims)
	}
	if err != nil {
		detail := "The token does not verify."
		var inv invalid
		switch {
		case errors.As(err, &inv):
			detail = string(inv)
		case errors.Is(err, errUnavailable):
			detail = errUnavailable.Error()
		}
		return nil, p.invalidToken(detail)
	}
	held := scopesOf(claims["scope"])
	var missing []string
	for _, s := range p.scopes {
		if !slices.Contains(held, s) {
			missing = append(missing, s)
		}
	}
	if len(missing) > 0 {
		scope := strings.Join(missing, " ")
		return nil, &refusal{name: "insufficient_scope", detail: "The token lacks the scopes " + scope + ".",
			status: http.StatusForbidden, challenge: p.challenge("insufficient_scope", "", scope),
			ext: map[string]any{"missing_scopes": missing}}
	}
	return claims, nil
}

func (p *ProtectedResource) invalidToken(detail string) *refusal {
	return &refusal{name: "unauthorized", detail: detail, status: http.StatusUnauthorized,
		challenge: p.challenge("invalid_token", detail, "")}
}

// assertBinding: a DPoP-bound token (cnf.jkt) comes with the DPoP scheme and a proof for this
// request and token, by its key; a bearer token with the Bearer scheme.
func (p *ProtectedResource) assertBinding(r *http.Request, scheme, raw string, claims map[string]any) error {
	cnf, _ := claims["cnf"].(map[string]any)
	jkt, _ := cnf["jkt"].(string)
	dpopScheme := strings.EqualFold(scheme, "dpop")
	if jkt == "" {
		if dpopScheme {
			return invalid("A bearer token is presented with the Bearer scheme.")
		}
		return nil
	}
	proof := r.Header.Get(dpopHeader)
	if !dpopScheme || proof == "" {
		return invalid("A DPoP-bound token is presented with the DPoP scheme and a proof.")
	}
	thumb, err := p.dpop.thumbprint(r.Context(), proof, r.Method, p.origin+r.URL.RequestURI(), raw)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(thumb), []byte(jkt)) == 1 {
		return nil
	}
	return invalid("The DPoP proof is not for the key the token is bound to.")
}

// scopesOf reads a scope claim: a space-separated string or a list.
func scopesOf(v any) []string {
	switch s := v.(type) {
	case string:
		return strings.Fields(s)
	case []any:
		out := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				out = append(out, str)
			}
		}
		return out
	}
	return nil
}

func (p *ProtectedResource) challenge(errCode, description, scope string) string {
	var parts []string
	if errCode != "" {
		parts = append(parts, `error="`+errCode+`"`)
	}
	if description != "" {
		parts = append(parts, `error_description="`+strings.NewReplacer(`"`, "", `\`, "").Replace(description)+`"`)
	}
	if scope != "" {
		parts = append(parts, `scope="`+scope+`"`)
	}
	parts = append(parts, `resource_metadata="`+p.metadataURL+`"`)
	return "Bearer " + strings.Join(parts, ", ")
}
