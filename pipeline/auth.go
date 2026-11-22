package pipeline

import (
	"net"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/strutil"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/token"
)

// maxUserAgent bounds the recorded User-Agent to the user_agent column size, in characters.
const maxUserAgent = 255

// stepUpEndpoint is where a client re-authenticates after a step_up_required answer.
const stepUpEndpoint = "/auth/mfa/step-up"

// clientContext records the caller's IP (the remote address, unless an outer layer already set
// one) and its User-Agent without control characters, bounded to 255 characters.
func clientContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := endpoint.Client(r.Context())
		if c.IP == "" {
			c.IP = remoteIP(r)
		}
		if ua := sanitizeUserAgent(r.Header.Get("User-Agent")); ua != "" {
			c.UserAgent = ua
		}
		next.ServeHTTP(w, r.WithContext(endpoint.WithClient(r.Context(), c)))
	})
}

func remoteIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func sanitizeUserAgent(ua string) string {
	ua = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, ua)
	if utf8.RuneCountInString(ua) > maxUserAgent {
		ua = string([]rune(ua)[:maxUserAgent])
	}
	return ua
}

// clientIP is the rate-limit key of an anonymous caller: the recorded IP, else "unknown".
func clientIP(r *http.Request) string {
	if ip := endpoint.Client(r.Context()).IP; ip != "" {
		return ip
	}
	if ip := remoteIP(r); ip != "" {
		return ip
	}
	return "unknown"
}

var bearerPattern = regexp.MustCompile(`(?i)^Bearer\s+(\S.*)$`)

// bearerToken extracts the credential of an "Authorization: Bearer" header (scheme in any case),
// "" when there is none.
func bearerToken(r *http.Request) string {
	m := bearerPattern.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil {
		return ""
	}
	return strutil.Trim(m[1])
}

// unauthorized answers the 401 every authentication step answers, with its Bearer challenge.
func unauthorized(w http.ResponseWriter) {
	endpoint.Write(w, endpoint.Unauthorized().WithHeader("WWW-Authenticate", "Bearer"))
}

// mfaTicket authenticates the login_mfa ticket of an auth: mfa_token route.
func (p *Pipeline) mfaTicket(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt := endpoint.Route(r.Context()); rt == nil || rt.Auth != manifest.AuthMfaToken {
			next.ServeHTTP(w, r)
			return
		}
		raw := bearerToken(r)
		if raw == "" {
			unauthorized(w)
			return
		}
		ctx := r.Context()
		var userID string
		var err error
		if restricted, ok := p.opts.MFATickets.(MFATicketFactors); ok {
			var factors []string
			userID, factors, err = restricted.AuthenticateFactors(ctx, raw)
			if factors != nil {
				ctx = endpoint.WithMFATicketFactors(ctx, factors)
			}
		} else {
			userID, err = p.opts.MFATickets.Authenticate(ctx, raw)
		}
		if err != nil {
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(endpoint.WithMFATicket(ctx, userID)))
	})
}

// bearer authenticates an auth: bearer route.
func (p *Pipeline) bearer(next http.Handler) http.Handler {
	auth := p.authenticate(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt := endpoint.Route(r.Context()); rt == nil || rt.Auth != manifest.AuthBearer {
			next.ServeHTTP(w, r)
			return
		}
		auth.ServeHTTP(w, r)
	})
}

// authenticate requires a principal: the first bearer resolver that recognises the request, else
// the Authorization bearer parsed as a Polaris access token.
func (p *Pipeline) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := p.resolve(r)
		if err != nil || tok == nil {
			unauthorized(w)
			return
		}
		next.ServeHTTP(w, r.WithContext(endpoint.WithToken(r.Context(), tok)))
	})
}

// mayAuthenticate is authenticate for a route open to anonymous callers: no credential passes
// without a principal; a credential that does not verify is refused like authenticate refuses it.
func (p *Pipeline) mayAuthenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := p.resolve(r)
		switch {
		case err == nil && tok != nil:
			next.ServeHTTP(w, r.WithContext(endpoint.WithToken(r.Context(), tok)))
		case err == nil && !tokenScheme.MatchString(r.Header.Get("Authorization")):
			next.ServeHTTP(w, r)
		default:
			unauthorized(w)
		}
	})
}

// tokenScheme matches an Authorization header presenting a token (Bearer or DPoP, any case).
var tokenScheme = regexp.MustCompile(`(?i)^(Bearer|DPoP)(\s|$)`)

func (p *Pipeline) resolve(r *http.Request) (*token.Token, error) {
	for _, resolver := range p.opts.BearerResolvers {
		if tok, err := resolver.Resolve(r); err != nil || tok != nil {
			return tok, err
		}
	}
	raw := bearerToken(r)
	if raw == "" {
		return nil, nil
	}
	return p.opts.Tokens.Parse(raw)
}

// stepUp requires, on a step_up route, a recent authentication (auth_time within
// Auth.StepUpMaxAge) from a user with a confirmed MFA factor.
func (p *Pipeline) stepUp(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rt := endpoint.Route(r.Context()); rt == nil || !rt.StepUp {
			next.ServeHTTP(w, r)
			return
		}
		tok := endpoint.Token(r.Context())
		if tok == nil {
			unauthorized(w)
			return
		}
		if tok.Subject() == "" || p.recentAuth(tok) {
			next.ServeHTTP(w, r)
			return
		}
		hasFactor, err := p.opts.StepUp.HasConfirmedFactor(r.Context(), tok.Subject())
		if err != nil {
			p.fail(w, r, "step-up factor lookup", err)
			return
		}
		if !hasFactor {
			next.ServeHTTP(w, r)
			return
		}
		endpoint.Write(w, endpoint.JSON(http.StatusUnauthorized, map[string]any{
			"error":   "step_up_required",
			"message": "This operation requires a recent re-authentication.",
			"step_up": stepUpEndpoint,
		}).WithHeader("WWW-Authenticate", `Bearer error="step_up_required"`))
	})
}

func (p *Pipeline) recentAuth(tok *token.Token) bool {
	authTime, ok := tok.Claim("auth_time").(int64)
	return ok && p.clock.Now().Unix()-authTime <= int64(p.opts.Auth.StepUpMaxAge.Seconds())
}

// denylist rejects, when the denylist is on, an access token issued before its user's last
// logout-everywhere.
func (p *Pipeline) denylist(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := endpoint.Token(r.Context())
		if !p.opts.Auth.AccessToken.Denylist || tok == nil {
			next.ServeHTTP(w, r)
			return
		}
		revoked := tok.Subject() == "" || tok.IssuedAt().IsZero()
		if !revoked {
			var err error
			if revoked, err = p.opts.Denylist.Revoked(r.Context(), tok.Subject(), tok.IssuedAt()); err != nil {
				p.fail(w, r, "denylist lookup", err)
				return
			}
		}
		if revoked {
			endpoint.Write(w, endpoint.Error(http.StatusUnauthorized, "session_ended", "The session is no longer active."))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// authorize enforces the route's requires_permissions through the Gate, and keeps delegated
// credentials off the routes reserved to the account holder.
func (p *Pipeline) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := endpoint.Route(r.Context())
		if rt == nil {
			next.ServeHTTP(w, r)
			return
		}
		if tok := endpoint.Token(r.Context()); tok != nil && DeniesDelegate(rt, tok) {
			endpoint.Write(w, endpoint.Forbidden("This action is for the account holder, not for a delegated credential."))
			return
		}
		p.permit(w, r, rt.RequiresPermissions, next, false)
	})
}

// DeniesDelegate: a delegated credential may read, and may do what a permission it holds allows;
// it may not call a step-up route, nor a write or destructive route that needs no permission
// (self-service: enrolling a factor, creating an organization, minting a key).
//
// The MCP server filters tools with it.
func DeniesDelegate(rt *manifest.Route, tok *token.Token) bool {
	if _, ok := tok.Delegation(); !ok {
		return false
	}
	return rt.StepUp || (len(rt.RequiresPermissions) == 0 && rt.Effect != manifest.EffectRead)
}

// permit runs next when the principal's authority grants every required permission, recording
// the authority; no permissions means no check. With lazy set and no permissions, the authority is
// recorded unresolved: the database is asked only if next reads it (once per request; a failure
// is logged).
func (p *Pipeline) permit(w http.ResponseWriter, r *http.Request, required []string, next http.Handler, lazy bool) {
	if len(required) == 0 {
		tok := endpoint.Token(r.Context())
		if lazy && tok != nil {
			ctx := r.Context()
			r = r.WithContext(endpoint.WithLazyAuthority(ctx, func() (any, error) {
				a, err := p.opts.Gate.Authority(ctx, tok)
				if err != nil {
					p.log.ErrorContext(ctx, "polaris pipeline: authority resolution failed", "method", r.Method, "path", r.URL.Path, "error", err)
					return nil, err
				}
				return a, nil
			}))
		}
		next.ServeHTTP(w, r)
		return
	}
	tok := endpoint.Token(r.Context())
	if tok == nil {
		unauthorized(w)
		return
	}
	authority, err := p.opts.Gate.Authority(r.Context(), tok)
	if err != nil {
		p.fail(w, r, "authority resolution", err)
		return
	}
	if !authority.Allows(required...) {
		endpoint.Write(w, endpoint.Forbidden("You do not have permission to perform this action."))
		return
	}
	next.ServeHTTP(w, r.WithContext(endpoint.WithAuthority(r.Context(), authority)))
}
