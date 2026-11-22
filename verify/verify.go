// Package verify checks Polaris access tokens in a Go service that is not the Polaris host: a
// microservice with no access to the auth database. It verifies a token's signature against the
// issuer's published JWK Set, its type, issuer, audience and validity window, and the scopes a
// route requires, all locally; nothing is asked of the issuer per request.
//
//	v, err := verify.New(verify.Config{
//		Issuer:  "https://auth.example.com",                          // Polaris's AUTH_ISSUER
//		JWKSURL: "https://auth.example.com/auth/.well-known/jwks.json", // Polaris's JWK Set route
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//	mux.Handle("GET /invoices", v.Require("invoices.read")(invoices))
//	// in invoices: c, _ := verify.ClaimsFrom(r.Context()); c.Subject, c.OrganizationID, c.Scopes
//
// # What it accepts
//
// Polaris session access tokens (typ JWT) and the oauth plugin's access tokens (typ at+jwt),
// signed with RS256 or EdDSA (never none, never an HMAC, never another algorithm), whose iss is
// Config.Issuer, whose exp has not passed and whose nbf and iat have (a minute's leeway), and
// whose aud names one of Config.Audiences, or, with no Audiences, that carry no aud at all (a
// session token while AUTH_AUDIENCE is unset). Single-purpose tickets (login MFA, step-up), DPoP
// proofs, agent request JWTs and receipts are refused even though the same key signs them. A
// DPoP-bound token (cnf) is refused: without its proof it would be a bearer token. API keys and
// agent request signatures are not JWT access tokens; only the Polaris host can check them.
//
// # What it cannot know
//
// A remote verifier sees the token and nothing else. Until the token expires it cannot know that:
//
//   - the session was signed out, every session was ended (the denylist), the refresh family was
//     revoked, or an OAuth token was revoked;
//   - the user was disabled or deleted, a membership suspended, an agent revoked (the kill
//     switch) or its grants withdrawn;
//   - the roles or permissions changed: Claims.Scopes are the permissions the token was issued
//     with, not the ones the database holds now. The host's polaris.Protect resolves them from
//     the database on every request; this package cannot.
//
// The access token lifetime bounds every one of these: AUTH_ACCESS_TOKEN_TTL (15 minutes by
// default) for session tokens, the provider's access token lifetime for OAuth tokens. Keep it
// short. For an action that must see a revocation at once (moving money, deleting data, changing
// who can do what), route the request through the Polaris host and guard it with polaris.Protect,
// or ask the host.
//
// # Keys
//
// The JWK Set is fetched from Config.JWKSURL only (never a URL a token names), bounded in size,
// and cached for Config.JWKSTTL. A token naming an unknown kid fetches it again, at most once a
// minute, which is how a key rotation reaches the service; a retired key stops verifying once
// the cached set expires. When the issuer cannot be reached, a cached set keeps verifying until
// it expires, and is never used past it: requests then fail with ErrUnavailable (503), not as
// invalid tokens.
package verify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/jwtverify"
	"github.com/univeros/polaris.go/internal/netguard"
)

var (
	// ErrInvalidToken is a token this service must not accept: malformed, badly signed, from
	// another issuer or for another audience, expired, not yet valid, or not an access token.
	ErrInvalidToken = errors.New("verify: invalid token")
	// ErrUnavailable is the issuer's JWK Set out of reach (and no unexpired cached copy): the
	// token could not be checked either way.
	ErrUnavailable = errors.New("verify: the issuer's keys are unavailable")
)

// algorithms are what Polaris signs access tokens with (config.SignerRS256, config.SignerEdDSA).
var algorithms = []string{"RS256", "EdDSA"}

// Config configures [New]. Issuer and JWKSURL are required.
type Config struct {
	// Issuer is the iss every token must carry: the Polaris host's AUTH_ISSUER
	// ("https://auth.example.com").
	Issuer string
	// JWKSURL is the issuer's JWK Set, an https URL: the Polaris route
	// /auth/.well-known/jwks.json under the host's base URL.
	JWKSURL string
	// Audiences are the aud values naming this service; a token must name one. Set them to
	// accept OAuth access tokens issued for this service (its resource URL), or session tokens
	// when the host sets AUTH_AUDIENCE. Empty: only tokens without an aud are accepted.
	Audiences []string

	// HTTPClient fetches the JWK Set; redirects are never followed. Default: a client that
	// connects to public addresses only (10 s timeout). Pass your own to reach an issuer on a
	// private network.
	HTTPClient *http.Client
	// JWKSTTL is how long a fetched JWK Set is used; default one hour.
	JWKSTTL time.Duration
	// Clock checks exp and nbf; default the system clock.
	Clock clock.Clock
	// Logger records why a JWK Set fetch failed; default slog.Default().
	Logger *slog.Logger
}

// Verifier verifies Polaris access tokens against one issuer. Build it with [New]; it is safe for
// concurrent use, and keeps the JWK Set it fetched, so build one per issuer and share it.
type Verifier struct {
	v *jwtverify.Verifier
}

// Claims are a verified token's claims.
type Claims struct {
	// Subject is sub: the user, or the OAuth client acting for itself (client credentials).
	Subject string
	// OrganizationID is org, the active organization; "" when none.
	OrganizationID string
	// Scopes are what the token was issued with: a session token's permissions in
	// OrganizationID at sign-in or refresh, an OAuth token's granted scopes. They are not
	// re-read from the database (see the package documentation).
	Scopes []string
	// ExpiresAt is exp.
	ExpiresAt time.Time
	// All is every claim, numbers as json.Number: client_id, roles, amr, auth_time, the
	// application's own claims.
	All map[string]any
}

// New validates cfg; every problem is reported at once, naming its fix.
func New(cfg Config) (*Verifier, error) {
	var errs []error
	if cfg.Issuer == "" {
		errs = append(errs, errors.New("verify: Config.Issuer is empty: set the Polaris issuer URL (its AUTH_ISSUER)"))
	}
	switch {
	case cfg.JWKSURL == "":
		errs = append(errs, errors.New(`verify: Config.JWKSURL is empty: set the issuer's JWK Set URL, e.g. "https://auth.example.com/auth/.well-known/jwks.json"`))
	case !strings.HasPrefix(cfg.JWKSURL, "https://"):
		errs = append(errs, fmt.Errorf("verify: Config.JWKSURL %q must be an https URL", cfg.JWKSURL))
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	clk := cfg.Clock
	if clk == nil {
		clk = clock.System{}
	}
	ttl := cfg.JWKSTTL
	if ttl <= 0 {
		ttl = jwtverify.DefaultTTL
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Verifier{v: &jwtverify.Verifier{
		Issuer:     cfg.Issuer,
		Audiences:  slices.Clone(cfg.Audiences),
		Algorithms: algorithms,
		RequireTyp: true,
		Clock:      clk,
		JWKS: &jwtverify.JWKS{URL: cfg.JWKSURL, Client: netguard.NoRedirects(cfg.HTTPClient), TTL: ttl, Clock: clk,
			Log: func(msg string, args ...any) { logger.Warn("polaris verify: "+msg, args...) }},
	}}, nil
}

// Verify checks raw, a compact access token (without "Bearer "), and returns its claims. A
// refusal wraps ErrInvalidToken with the reason; an unreachable issuer wraps ErrUnavailable.
func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	c, err := v.verify(ctx, raw)
	var inv jwtverify.Invalid
	switch {
	case err == nil:
		return c, nil
	case errors.As(err, &inv):
		return Claims{}, fmt.Errorf("%w: %s", ErrInvalidToken, string(inv))
	default:
		return Claims{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
}

func (v *Verifier) verify(ctx context.Context, raw string) (Claims, error) {
	m, err := v.v.Verify(ctx, raw)
	if err != nil {
		return Claims{}, err
	}
	if m["cnf"] != nil {
		return Claims{}, jwtverify.Invalid("The token is bound to a DPoP key; it cannot be used as a bearer token.")
	}
	sub, _ := m["sub"].(string)
	org, _ := m["org"].(string)
	exp, _ := jwtverify.Number(m["exp"])
	return Claims{Subject: sub, OrganizationID: org, Scopes: jwtverify.Scopes(m["scope"]), ExpiresAt: time.Unix(int64(exp), 0), All: m}, nil
}

var bearer = regexp.MustCompile(`(?i)^Bearer\s+(\S+)$`)

type claimsKey struct{}

// ClaimsFrom returns the claims of a request [Verifier.Require] let through; ok is false outside it.
func ClaimsFrom(ctx context.Context) (Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(Claims)
	return c, ok
}

// Require returns middleware that lets a request through only with a valid access token in
// "Authorization: Bearer" holding every one of scopes (none: any valid token); next reads the
// claims with [ClaimsFrom]. It answers as the Polaris host does, with the RFC 6750 challenge:
//
//   - 401 {"error":"unauthorized"} with WWW-Authenticate: Bearer, without a bearer token;
//   - 401 {"error":"unauthorized"} with Bearer error="invalid_token", for a token Verify refuses;
//   - 403 {"error":"forbidden"} with Bearer error="insufficient_scope" scope="<missing>";
//   - 503 {"error":"unavailable"} when the issuer's keys cannot be read (logged).
//
// It has the shape routers chain: r.Use(v.Require()), mux.Handle(p, v.Require("x")(h)).
func (v *Verifier) Require(scopes ...string) func(http.Handler) http.Handler {
	required := slices.Clone(scopes)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			m := bearer.FindStringSubmatch(r.Header.Get("Authorization"))
			if m == nil {
				endpoint.Write(w, endpoint.Unauthorized().WithHeader("WWW-Authenticate", "Bearer"))
				return
			}
			c, err := v.verify(r.Context(), m[1])
			var inv jwtverify.Invalid
			switch {
			case errors.As(err, &inv):
				endpoint.Write(w, endpoint.Error(http.StatusUnauthorized, "unauthorized", string(inv)).
					WithHeader("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+string(inv)+`"`))
				return
			case err != nil:
				endpoint.Write(w, endpoint.Error(http.StatusServiceUnavailable, "unavailable", "The token could not be checked; try again later."))
				return
			}
			var missing []string
			for _, s := range required {
				if !slices.Contains(c.Scopes, s) {
					missing = append(missing, s)
				}
			}
			if len(missing) > 0 {
				scope := strings.Join(missing, " ")
				endpoint.Write(w, endpoint.Forbidden("The token lacks the scopes "+scope+".").
					WithHeader("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`))
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, c)))
		})
	}
}
