package oauth

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

const (
	requestCache = "polaris.oauth.request."
	requestTTL   = 10 * time.Minute
)

var (
	base64URL43     = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	requestIDFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{32}$`)
	resourceFormat  = regexp.MustCompile(`^https?://[^\s#]+$`)
)

// pendingRequest is a validated authorization request parked in the cache until the user decides.
type pendingRequest struct {
	ID            string   `json:"id"`
	ClientID      string   `json:"client_id"`
	RedirectURI   string   `json:"redirect_uri"`
	Scopes        []string `json:"scopes"`
	State         string   `json:"state,omitempty"`
	CodeChallenge string   `json:"code_challenge"`
	Nonce         string   `json:"nonce,omitempty"`
	Resource      string   `json:"resource,omitempty"`
	DPoPJKT       string   `json:"dpop_jkt,omitempty"`
	Prompt        string   `json:"prompt,omitempty"`
	CreatedAt     int64    `json:"created_at"`
}

// authorization is the authorization endpoint's half of the code flow.
type authorization struct {
	clients  *clients
	scopes   *scopes
	codes    *codes
	consents *consents
	settings settings
	issuer   string
	cache    cache.Cache
	clock    clock.Clock
}

// start validates the query of GET /oauth2/authorize and parks it.
func (a *authorization) start(ctx context.Context, query func(string) string) (pendingRequest, *Client, error) {
	var c *Client
	if id := query("client_id"); id != "" {
		var err error
		if c, err = a.clients.find(ctx, id); err != nil {
			return pendingRequest{}, nil, err
		}
	}
	if c == nil || c.DisabledAt != nil {
		return pendingRequest{}, nil, refusal(CodeInvalidClient, "Unknown client.")
	}
	redirect := query("redirect_uri")
	if redirect == "" || !c.AllowsRedirect(redirect) {
		return pendingRequest{}, nil, refusal(CodeInvalidRequest, "redirect_uri is required and must be one the client registered.")
	}
	if !c.AllowsGrant(GrantAuthorizationCode) {
		return pendingRequest{}, nil, refusal(CodeUnauthorizedClient, "The client may not use the authorization code grant.")
	}
	if query("response_type") != "code" {
		return pendingRequest{}, nil, refusal(CodeUnsupportedResponseType, "response_type must be code.")
	}
	challenge := query("code_challenge")
	if !base64URL43.MatchString(challenge) || query("code_challenge_method") != "S256" {
		return pendingRequest{}, nil, refusal(CodeInvalidRequest, "PKCE is required: code_challenge (S256, base64url) and code_challenge_method=S256.")
	}
	scopes, err := a.scopes.parse(query("scope"), c)
	if err != nil {
		return pendingRequest{}, nil, err
	}
	resource := query("resource")
	if resource != "" && !resourceFormat.MatchString(resource) {
		return pendingRequest{}, nil, refusal(CodeInvalidTarget, "resource must be an absolute URI without a fragment.")
	}
	jkt := query("dpop_jkt")
	if jkt != "" && !base64URL43.MatchString(jkt) {
		return pendingRequest{}, nil, refusal(CodeInvalidRequest, "dpop_jkt is a base64url SHA-256 thumbprint.")
	}
	for _, limit := range []struct {
		field string
		max   int
	}{{"state", 512}, {"nonce", 512}, {"resource", 2048}, {"redirect_uri", 2048}} {
		if len(query(limit.field)) > limit.max {
			return pendingRequest{}, nil, refusal(CodeInvalidRequest, limit.field+" is too long.")
		}
	}
	prompt := query("prompt")
	if prompt != "" && !slices.Contains([]string{"none", "login", "consent"}, prompt) {
		return pendingRequest{}, nil, refusal(CodeInvalidRequest, "prompt is none, login or consent.")
	}
	id := make([]byte, 24)
	_, _ = rand.Read(id)
	req := pendingRequest{
		ID: b64(id), ClientID: c.ClientID, RedirectURI: redirect, Scopes: scopes, State: query("state"),
		CodeChallenge: challenge, Nonce: query("nonce"), Resource: resource, DPoPJKT: jkt, Prompt: prompt,
		CreatedAt: a.clock.Now().Unix(),
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return pendingRequest{}, nil, err
	}
	if err := a.cache.Set(ctx, requestCache+req.ID, raw, requestTTL); err != nil {
		return pendingRequest{}, nil, err
	}
	return req, c, nil
}

// pending returns a parked request and its client.
func (a *authorization) pending(ctx context.Context, id string) (pendingRequest, *Client, error) {
	unknown := refusal(CodeInvalidRequest, "The authorization request is unknown or expired; start again.")
	if !requestIDFormat.MatchString(id) {
		return pendingRequest{}, nil, unknown
	}
	raw, found, err := a.cache.Get(ctx, requestCache+id)
	if err != nil {
		return pendingRequest{}, nil, err
	}
	var req pendingRequest
	if !found || json.Unmarshal(raw, &req) != nil {
		return pendingRequest{}, nil, unknown
	}
	c, err := a.clients.find(ctx, req.ClientID)
	if err != nil {
		return pendingRequest{}, nil, err
	}
	if c == nil {
		return pendingRequest{}, nil, refusal(CodeInvalidClient, "Unknown client.")
	}
	return req, c, nil
}

func (a *authorization) trusted(c *Client) bool {
	return c.Trusted || slices.Contains(a.settings.trustedClients, c.ClientID)
}

// needsConsent: never for a trusted client or scopes already granted, always for prompt=consent.
func (a *authorization) needsConsent(ctx context.Context, req pendingRequest, c *Client, userID string) (bool, error) {
	if req.Prompt == "consent" {
		return true, nil
	}
	if a.trusted(c) {
		return false, nil
	}
	covered, err := a.consents.covers(ctx, userID, c.ClientID, req.Scopes)
	return !covered, err
}

// decide records the user's decision and returns where the browser goes next, and whether a
// consent was recorded.
func (a *authorization) decide(ctx context.Context, req pendingRequest, c *Client, userID, organizationID string, approve bool, authTime *int64) (string, bool, error) {
	if err := a.cache.Delete(ctx, requestCache+req.ID); err != nil {
		return "", false, err
	}
	if !approve {
		return redirectWith(req.RedirectURI, "error", CodeAccessDenied, "error_description", "The user refused.", "state", req.State), false, nil
	}
	recorded := false
	if !a.trusted(c) {
		if err := a.consents.grant(ctx, userID, c.ClientID, organizationID, req.Scopes); err != nil {
			return "", false, err
		}
		recorded = true
	}
	value, err := a.codes.issue(ctx, *c, userID, organizationID, req, authTime)
	if err != nil {
		return "", false, err
	}
	// RFC 9207: the response names its issuer.
	return redirectWith(req.RedirectURI, "code", value, "state", req.State, "iss", a.issuer), recorded, nil
}

// redirectWith appends the non-empty name/value pairs to uri as a form-encoded query, joined with
// "&" (after "?", or after "&" when uri already has a query).
func redirectWith(uri string, pairs ...string) string {
	var parts []string
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i+1] != "" {
			parts = append(parts, formEncode(pairs[i])+"="+formEncode(pairs[i+1]))
		}
	}
	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	return uri + sep + strings.Join(parts, "&")
}

// formEncode percent-encodes every byte but ASCII letters, digits and -_. (upper-case hex), and
// writes a space as +. Unlike url.QueryEscape it also escapes ~, so the redirect URIs keep the
// bytes earlier releases sent.
func formEncode(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '-', ch == '_', ch == '.':
			b.WriteByte(ch)
		case ch == ' ':
			b.WriteByte('+')
		default:
			b.WriteByte('%')
			b.WriteByte(hex[ch>>4])
			b.WriteByte(hex[ch&15])
		}
	}
	return b.String()
}
