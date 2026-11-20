package pipeline

import (
	"net/http"

	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/ratelimit"
)

// ipRateLimit spends the per-IP budget of the route's rate_limit group. A group the config does
// not know is not limited, as upstream.
func (p *Pipeline) ipRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt := endpoint.Route(r.Context())
		if rt == nil {
			next.ServeHTTP(w, r)
			return
		}
		policy, ok := group(p.opts.Auth.RateLimits, rt.RateLimit)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		p.limit(w, r, policy, clientIP(r), next)
	})
}

// principalRateLimit spends the per-user budget of every authenticated request.
func (p *Pipeline) principalRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := endpoint.Token(r.Context())
		if tok == nil {
			next.ServeHTTP(w, r)
			return
		}
		key := clientIP(r)
		if sub := tok.Subject(); sub != "" {
			key = "user:" + sub
		}
		p.limit(w, r, p.opts.Auth.RateLimits.Authenticated, key, next)
	})
}

func group(l config.RateLimits, name string) (config.RateLimit, bool) {
	switch name {
	case "login":
		return l.Login, true
	case "register":
		return l.Register, true
	case "password_forgot":
		return l.PasswordForgot, true
	case "token_refresh":
		return l.TokenRefresh, true
	case "mfa_enroll":
		return l.MFAEnroll, true
	case "mfa_confirm":
		return l.MFAConfirm, true
	case "mfa_send":
		return l.MFASend, true
	case "token_consume":
		return l.TokenConsume, true
	case "authenticated":
		return l.Authenticated, true
	}
	return config.RateLimit{}, false
}

// limit spends one hit of policy under key: 429 with Retry-After when the budget is spent, else
// next, its response carrying the X-RateLimit-* headers. An outer limiter's headers win over an
// inner one's, as upstream's response decoration does.
func (p *Pipeline) limit(w http.ResponseWriter, r *http.Request, policy config.RateLimit, key string, next http.Handler) {
	res, err := ratelimit.Check(r.Context(), p.rates, policy, key)
	if err != nil {
		p.fail(w, r, "rate limit", err)
		return
	}
	headers := ratelimit.Headers(res, p.clock.Now())
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
}

// headerWriter sets extra headers when the response header is written, over what the inner
// handler set.
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

// Flush sends the headers first, so a streaming handler still reports its budget.
func (h *headerWriter) Flush() {
	if !h.wrote {
		h.WriteHeader(http.StatusOK)
	}
	_ = http.NewResponseController(h.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (h *headerWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }
