package agents

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/token"
)

// Claims the agent principal carries on every Polaris route.
const (
	ClaimActorType = "actor_type" // "agent"
	ClaimAgentID   = "agent_id"
)

// Tag marks the agent-facing routes: the request reaches the endpoint, which authenticates the
// agent itself (auth: public), with its raw body kept for the request JWT's body_hash.
const Tag = "agents"

// The ways an agent authenticated.
const (
	ViaJWT   = "jwt"
	ViaOAuth = "oauth"
)

var credentialScheme = regexp.MustCompile(`(?i)^(Bearer|DPoP)\s+(\S+)$`)

// principal is the agent a request authenticated as, and through which credential: a request JWT
// (with the capabilities it may use, when it restricts them) or one of its OAuth access tokens
// (whose delegated permissions bound what it may execute).
type principal struct {
	agent        Agent
	via          string
	capabilities []string // nil: no restriction
	delegated    []string // the token's permissions; nil for a JWT
}

func (p principal) mayUse(capability string) bool {
	return p.capabilities == nil || slices.Contains(p.capabilities, capability)
}

func (p principal) carries(permission string) bool {
	return p.via == ViaJWT || slices.Contains(p.delegated, permission)
}

func assertActive(a Agent) error {
	if a.Active() {
		return nil
	}
	code := ErrAgentSuspended
	switch a.Status {
	case StatusRevoked:
		code = ErrAgentRevoked
	case StatusPending:
		code = ErrAgentPending
	case StatusRejected:
		code = ErrAgentRejected
	}
	return &Error{Type: ErrAgentInactive, Detail: "The agent is " + a.Status + ".", Code: code}
}

// authenticate is who an agent-facing route (or a guarded host route) talks to: an agent with a
// signed request JWT, or one of its OAuth access tokens (verified by the oauth plugin, DPoP binding
// included). body is the raw request body; url is what a request JWT's aud must name (ownURL on
// the plugin's routes, requestURL on a host's).
func (s *service) authenticate(r *http.Request, body []byte, url string) (principal, error) {
	return s.authenticateWith(s.jwts, r, body, url)
}

// authenticateWith is authenticate with the rules jwts holds a request JWT to.
func (s *service) authenticateWith(jwts *requestJWTs, r *http.Request, body []byte, url string) (principal, error) {
	m := credentialScheme.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil {
		return principal{}, refuse(ErrUnauthorized, "An agent credential is required: a signed request JWT or an access token as a bearer.")
	}
	raw := m[2]
	if peeked, ok := peekRequestJWT(raw); ok {
		return s.byJWT(jwts, r, raw, peeked, body, url)
	}
	if h := oauth.JWTHeader(raw); h != nil && h["typ"] == oauth.AccessTokenType {
		tok, err := s.oauth.ResolveBearer(r)
		if err != nil {
			return principal{}, invalidJWT("The access token does not authenticate: " + strings.TrimPrefix(err.Error(), "oauth: "))
		}
		if tok != nil {
			p, err := s.fromToken(r.Context(), tok)
			if err != nil || p != nil {
				return deref(p), err
			}
		}
		return principal{}, invalidJWT("The access token is not an agent's.")
	}
	return principal{}, invalidJWT("The credential is neither an agent JWT (typ agent+jwt) nor an access token (typ at+jwt).")
}

func deref(p *principal) principal {
	if p == nil {
		return principal{}
	}
	return *p
}

func (s *service) byJWT(jwts *requestJWTs, r *http.Request, raw string, peeked peekedJWT, body []byte, url string) (principal, error) {
	a, err := s.named(r.Context(), peeked.sub)
	if err != nil {
		return principal{}, err
	}
	return s.signedBy(a, jwts, r, raw, peeked, body, url)
}

// named is the agent a JWT's sub names, or the one an unknown host's registration may become.
func (s *service) named(ctx context.Context, sub string) (Agent, error) {
	a, ok, err := s.agent(ctx, sub)
	if err != nil || ok {
		return a, err
	}
	reg, ok, err := s.registration(ctx, sub)
	if err != nil {
		return Agent{}, err
	}
	if !ok {
		return Agent{}, invalidJWT("sub does not name a registered agent.")
	}
	return reg.agent(), nil // never active
}

// signedBy is the principal of a request whose JWT a signed, by the rules of jwts.
func (s *service) signedBy(a Agent, jwts *requestJWTs, r *http.Request, raw string, peeked peekedJWT, body []byte, url string) (principal, error) {
	ctx := r.Context()
	if err := assertActive(a); err != nil {
		return principal{}, err
	}
	caps, err := jwts.verify(ctx, raw, a, r.Method, url, body)
	if err != nil {
		return principal{}, err
	}
	if jwts.audience != "" { // an Agent Auth Protocol route
		if err := s.checkHost(ctx, a, peeked.iss, peeked.hasISS); err != nil {
			return principal{}, err
		}
	}
	// A JWT for one capability's location may not open the door to several.
	if located, ambiguous := s.caps.at(r, url); len(caps) > 1 && (located != nil || ambiguous) {
		return principal{}, refuse(ErrAudMismatch, "A JWT listing several capabilities cannot use a capability location as its aud.")
	}
	return principal{agent: a, via: ViaJWT, capabilities: caps}, nil
}

// fromToken is the agent behind a principal a bearer resolver built (an OAuth access token whose
// client is an agent), nil when it is not an agent's. The token's subject must be the agent
// (client credentials) or the user the agent acts for: the exchange is open to any session, so
// anyone else's token naming the agent's client is refused rather than driving the agent.
func (s *service) fromToken(ctx context.Context, tok *token.Token) (*principal, error) {
	delegated, ok := tok.Delegation()
	clientID, _ := tok.Claim(oauth.ClaimClientID).(string)
	if !ok || clientID == "" {
		return nil, nil
	}
	a, found, err := s.agent(ctx, clientID)
	if err != nil || !found {
		return nil, err
	}
	if err := assertActive(a); err != nil {
		return nil, err
	}
	if sub := tok.Subject(); sub != a.ID && sub != a.Subject() {
		return nil, invalidJWT("The token's subject is neither the agent nor the user the agent acts for.")
	}
	return &principal{agent: a, via: ViaOAuth, delegated: append([]string{}, delegated...)}, nil
}

// agentPrincipal is an agent's token as the rest of the pipeline sees it: delegated to the token's
// permissions intersected with the agent's live grants (a revoked grant takes effect at the next
// request), marked actor_type agent with act naming the agent; client credentials act as the
// agent's owner in the agent's organization.
func (s *service) agentPrincipal(ctx context.Context, tok *token.Token, a Agent) (*token.Token, error) {
	held, err := s.permissionsOf(ctx, a)
	if err != nil {
		return nil, err
	}
	delegated, _ := tok.Delegation()
	kept := []string{}
	for _, p := range delegated {
		if slices.Contains(held, p) {
			kept = append(kept, p)
		}
	}
	claims := tok.Claims()
	claims[ClaimActorType] = "agent"
	claims[ClaimAgentID] = a.ID
	claims[oauth.ClaimAct] = map[string]any{"sub": a.ID, "type": "agent"}
	if claims["sub"] == a.ID {
		claims["sub"], claims["org"] = a.Subject(), null(a.OrganizationID)
	}
	return token.NewPrincipal(claims).Delegate(kept), nil
}

type bodyKey struct{}

// middleware runs on every Polaris route after bearer authentication: it keeps the raw body of
// the agent-facing routes, refuses a token naming an agent that is inactive or that the token's
// subject may not drive, and replaces an agent's token with the agent principal.
func (p *Plugin) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if rt := endpoint.Route(ctx); rt != nil && slices.Contains(rt.Tags, Tag) {
			body, err := readBody(w, r, p.s.settings.maxBody)
			if err != nil {
				p.answer(w, r, err)
				return
			}
			ctx = context.WithValue(ctx, bodyKey{}, body)
		}
		tok := endpoint.Token(ctx)
		if tok == nil {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		pr, err := p.s.fromToken(ctx, tok)
		if err != nil {
			p.answer(w, r, err)
			return
		}
		if pr != nil {
			if tok, err = p.s.agentPrincipal(ctx, tok, pr.agent); err != nil {
				p.serverError(w, r, "resolving the agent principal", err)
				return
			}
			ctx = endpoint.WithToken(ctx, tok)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// readBody reads at most limit bytes of the body and puts it back for the next reader; a larger
// body is refused with agents/payload_too_large (413).
func readBody(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return nil, refuse(ErrPayloadTooLarge, fmt.Sprintf("The request body exceeds the limit of %d bytes.", limit))
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, err
}

// rawBody is the body the middleware kept for an agent-facing route.
func rawBody(ctx context.Context) []byte {
	b, _ := ctx.Value(bodyKey{}).([]byte)
	return b
}

// answer writes err: its problem for an *Error, a logged 500 otherwise.
func (p *Plugin) answer(w http.ResponseWriter, r *http.Request, err error) {
	if e, ok := asError(err); ok {
		endpoint.Write(w, e.result())
		return
	}
	p.serverError(w, r, "serving an agent request", err)
}

func (p *Plugin) serverError(w http.ResponseWriter, r *http.Request, what string, err error) {
	p.s.log.ErrorContext(r.Context(), "agents: "+what+" failed", "error", err)
	endpoint.Write(w, endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request."))
}
