package apikeys

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/ratelimit"
	"github.com/univeros/polaris-go/token"
)

// Header carries a key as an alternative to "Authorization: Bearer".
const Header = "x-api-key"

// Claims of a key's principal.
const (
	ClaimKey       = "api_key"            // the key id
	ClaimRateLimit = "api_key_rate_limit" // {window, max} or nil
	AMR            = "api_key"
)

// ErrRefused is returned by the resolver for a key that does not authenticate: unknown, revoked,
// expired, past its rotation grace, or whose subject is gone or cannot sign in.
var ErrRefused = errors.New("apikeys: the API key is unknown, revoked or expired, or its subject cannot sign in")

var bearer = regexp.MustCompile(`(?i)^Bearer\s+(\S.*)$`)

// Presented returns the key secret r carries (x-api-key first, then the bearer), "" when none.
func Presented(r *http.Request) string {
	secret := r.Header.Get(Header)
	if secret == "" {
		m := bearer.FindStringSubmatch(r.Header.Get("Authorization"))
		if m == nil {
			return ""
		}
		secret = m[1]
	}
	secret = strings.TrimSpace(secret)
	if !strings.HasPrefix(secret, "pk_") {
		return ""
	}
	return secret
}

// resolver authenticates a pk_ secret as the key's subject in the key's organization, delegated
// the key's permissions; any other bearer is not its business.
type resolver struct{ p *Plugin }

func (res resolver) Resolve(r *http.Request) (*token.Token, error) {
	secret := Presented(r)
	if secret == "" {
		return nil, nil
	}
	ctx := r.Context()
	key, ok, err := res.p.keys.Authenticate(ctx, secret)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrRefused
	}
	user, err := res.p.g.Repos.Users.Get(ctx, key.Subject())
	if err != nil || user.Status != model.UserStatusActive && user.Status != "" {
		return nil, errors.Join(ErrRefused, err)
	}
	now := res.p.keys.now()
	exp := now.Add(time.Hour)
	if key.ExpiresAt != nil {
		exp = *key.ExpiresAt
	}
	var limit any
	if key.RateLimit != nil {
		limit = map[string]any{"window": int64(key.RateLimit.Window), "max": int64(key.RateLimit.Max)}
	}
	claims := map[string]any{
		"sub":            user.ID,
		"org":            null(key.OrganizationID),
		"jti":            key.ID,
		"iat":            now,
		"exp":            exp,
		"roles":          []any{},
		"email_verified": user.EmailVerifiedAt != nil,
		"mfa":            false,
		"amr":            []any{AMR},
		ClaimKey:         key.ID,
		ClaimRateLimit:   limit,
	}
	return token.NewPrincipal(claims).Delegate(key.Permissions), nil
}

// keyID is the id of the API key that authenticated tok, "" for any other principal.
func keyID(tok *token.Token) string {
	if tok == nil {
		return ""
	}
	if _, delegated := tok.Delegation(); !delegated {
		return ""
	}
	id, _ := tok.Claim(ClaimKey).(string)
	return id
}

// middleware runs on requests a key authenticated: a step-up route is refused (a key cannot
// re-authenticate, and a stolen key must not add credentials), and the key's own rate limit
// applies, its X-RateLimit-* headers winning over core's.
func (p *Plugin) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := endpoint.Token(r.Context())
		id := keyID(tok)
		if id == "" {
			next.ServeHTTP(w, r)
			return
		}
		if rt := endpoint.Route(r.Context()); rt != nil && rt.StepUp {
			const detail = "This route requires a recent re-authentication, which an API key cannot provide."
			endpoint.Write(w, endpoint.Problem(http.StatusForbidden, "api-keys/not_allowed", "Not allowed with an API key", detail, nil))
			return
		}
		limit, _ := tok.Claim(ClaimRateLimit).(map[string]any)
		window, okW := limit["window"].(int64)
		maxHits, okM := limit["max"].(int64)
		if !okW || !okM {
			next.ServeHTTP(w, r)
			return
		}
		res, err := p.g.RateStore.Hit(r.Context(), "api_keys.key."+id, int(maxHits), time.Duration(window)*time.Second)
		if err != nil {
			p.g.Logger.ErrorContext(r.Context(), "apikeys: rate limit failed", "error", err)
			endpoint.Write(w, endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request."))
			return
		}
		headers := ratelimit.Headers(res, p.g.Clock.Now())
		if !res.Allowed {
			for name, values := range headers {
				w.Header()[name] = values
			}
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		hw := &headerWriter{ResponseWriter: w, extra: headers}
		next.ServeHTTP(hw, r)
		if !hw.wrote {
			hw.WriteHeader(http.StatusOK)
		}
	})
}

// headerWriter sets the key's rate-limit headers over the inner handler's when the status is written.
type headerWriter struct {
	http.ResponseWriter
	extra http.Header
	wrote bool
}

func (h *headerWriter) WriteHeader(code int) {
	if !h.wrote {
		h.wrote = true
		for name, values := range h.extra {
			h.ResponseWriter.Header()[name] = values
		}
	}
	h.ResponseWriter.WriteHeader(code)
}

func (h *headerWriter) Write(b []byte) (int, error) {
	if !h.wrote {
		h.WriteHeader(http.StatusOK)
	}
	return h.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (h *headerWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }
