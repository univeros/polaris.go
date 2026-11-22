package pipeline

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/ratelimit"
)

// fixedStore answers like RouterTest's stub RateStore: hits <= limit allowed, resetting at a fixed
// instant.
type fixedStore struct{ hits int }

func (s *fixedStore) Hit(_ context.Context, _ string, limit int, _ time.Duration) (ratelimit.Result, error) {
	s.hits++
	return ratelimit.Result{Allowed: s.hits <= limit, Limit: limit, Remaining: max(0, limit-s.hits), ResetAt: time.Unix(1_700_000_300, 0)}, nil
}

type failingStore struct{}

func (failingStore) Hit(context.Context, string, int, time.Duration) (ratelimit.Result, error) {
	return ratelimit.Result{}, errors.New("cache down")
}

func TestRateLimiterAnswers429WithTheHeadersOf10(t *testing.T) {
	core, _ := manifests(t)
	o := options(t, core)
	o.RateStore = &fixedStore{}
	o.Auth.RateLimits.Login = config.RateLimit{Limit: 2, Window: 300 * time.Second, KeyPrefix: "login"}
	o.Clock = fixedClock(time.Unix(1_700_000_000, 0))
	mw := newPipeline(t, o).ipRateLimit(&counting{})

	first := serve(mw, routed(t, core, "POST", "/auth/login"))
	serve(mw, routed(t, core, "POST", "/auth/login"))
	blocked := serve(mw, routed(t, core, "POST", "/auth/login"))

	h := first.Header()
	if h.Get("X-RateLimit-Limit") != "2" || h.Get("X-RateLimit-Remaining") != "1" || h.Get("X-RateLimit-Reset") != "1700000300" {
		t.Fatalf("first: %v", h)
	}
	if blocked.Code != 429 || blocked.Header().Get("Retry-After") != "300" || blocked.Header().Get("X-RateLimit-Remaining") != "0" || blocked.Header().Get("Content-Type") != "application/json" ||
		!strings.Contains(blocked.Body.String(), `"error":"too_many_requests"`) || !strings.Contains(blocked.Body.String(), `"message":`) {
		t.Fatalf("blocked: %d %v %q", blocked.Code, blocked.Header(), blocked.Body)
	}
}

// A plugin route's 429 is an RFC 9457 problem, as every other refusal of a plugin route.
func TestA429OnAPluginRouteIsAProblem(t *testing.T) {
	_, all := manifests(t)
	o := options(t, all)
	o.RateStore = &fixedStore{}
	o.Auth.RateLimits.Login = config.RateLimit{Limit: 1, Window: 300 * time.Second, KeyPrefix: "login"}
	o.Clock = fixedClock(time.Unix(1_700_000_000, 0))
	mw := newPipeline(t, o).ipRateLimit(&counting{})
	serve(mw, routed(t, all, "POST", "/passkey/authenticate/verify"))
	blocked := serve(mw, routed(t, all, "POST", "/passkey/authenticate/verify"))
	body := blocked.Body.String()
	if blocked.Code != 429 || blocked.Header().Get("Retry-After") != "300" || blocked.Header().Get("Content-Type") != "application/problem+json" ||
		!strings.Contains(body, `"type":"https://polaris.univeros.io/problems/too_many_requests"`) || !strings.Contains(body, `"error":"too_many_requests"`) || !strings.Contains(body, `"status":429`) {
		t.Fatalf("blocked: %d %v %q", blocked.Code, blocked.Header(), body)
	}
}

type fixedClock time.Time

func (c fixedClock) Now() time.Time { return time.Time(c) }

// RateLimitMiddlewareTest
func TestRateLimitMiddleware(t *testing.T) {
	core, _ := manifests(t)
	pipeline := func() *Pipeline {
		o := options(t, core)
		o.Auth.RateLimits.Login = config.RateLimit{Limit: 2, Window: time.Minute, KeyPrefix: "auth.login"}
		o.Auth.RateLimits.Register = config.RateLimit{Limit: 5, Window: time.Minute, KeyPrefix: "auth.register"}
		o.Auth.RateLimits.Authenticated = config.RateLimit{Limit: 2, Window: time.Minute, KeyPrefix: "auth.authenticated"}
		return newPipeline(t, o)
	}

	t.Run("testAuthBudgetsFollowTheSpecGroupAndAreCountedIndependently", func(t *testing.T) {
		c := &counting{}
		mw := pipeline().ipRateLimit(c)
		first := serve(mw, routed(t, core, "POST", "/auth/login"))
		if first.Header().Get("X-RateLimit-Limit") != "2" || first.Header().Get("X-RateLimit-Remaining") != "1" {
			t.Fatal(first.Header())
		}
		serve(mw, routed(t, core, "POST", "/auth/login"))
		blocked := serve(mw, routed(t, core, "POST", "/auth/login"))
		if blocked.Code != 429 || blocked.Header().Get("Retry-After") == "" || c.calls != 2 {
			t.Fatalf("%d %v %d", blocked.Code, blocked.Header(), c.calls)
		}
		if w := serve(mw, routed(t, core, "POST", "/auth/register")); w.Code != 200 {
			t.Fatal(w.Code)
		}
	})
	t.Run("testARouteWithoutARateLimitGroupPassesThroughUntouched", func(t *testing.T) {
		w := serve(pipeline().ipRateLimit(&counting{}), routed(t, core, "GET", "/auth/me"))
		if w.Code != 200 || w.Header().Get("X-RateLimit-Limit") != "" {
			t.Fatal(w.Header())
		}
	})
	t.Run("testAuthenticatedUsersAreBudgetedPerSubjectAcrossEndpoints", func(t *testing.T) {
		c := &counting{}
		mw := pipeline().principalRateLimit(c)
		authed := func(sub, path string) *http.Request {
			return withToken(routed(t, core, "GET", path), issue(t, sub, nil))
		}
		for i, tc := range []struct {
			sub, path string
			want      int
		}{{"user-1", "/auth/me", 200}, {"user-1", "/orgs", 200}, {"user-1", "/auth/sessions", 429}, {"user-2", "/auth/me", 200}} {
			if w := serve(mw, authed(tc.sub, tc.path)); w.Code != tc.want {
				t.Fatalf("request %d: %d", i, w.Code)
			}
		}
		if c.calls != 3 {
			t.Fatal(c.calls)
		}
	})
	t.Run("testARequestWithoutATokenPassesThroughUntouched", func(t *testing.T) {
		w := serve(pipeline().principalRateLimit(&counting{}), routed(t, core, "POST", "/auth/login"))
		if w.Code != 200 || w.Header().Get("X-RateLimit-Limit") != "" {
			t.Fatal(w.Header())
		}
	})
	t.Run("every manifest group maps to its budget", func(t *testing.T) {
		l := config.DefaultRateLimits()
		for _, name := range []string{"login", "register", "password_forgot", "token_refresh", "mfa_enroll", "mfa_confirm", "mfa_send", "token_consume", "authenticated"} {
			if p, ok := group(l, name); !ok || p.KeyPrefix != "auth."+name {
				t.Errorf("%s: %+v", name, p)
			}
		}
		if _, ok := group(l, "unknown"); ok {
			t.Error("unknown group limited")
		}
	})
	t.Run("a store failure answers 500", func(t *testing.T) {
		o := options(t, core)
		o.RateStore = failingStore{}
		if w := serve(newPipeline(t, o).ipRateLimit(&counting{}), routed(t, core, "POST", "/auth/login")); w.Code != 500 {
			t.Fatal(w.Code)
		}
	})
}

// The per-IP limiter wraps the per-user one: on a route with both, the outer (per-IP) headers win,
// and an inner 429 still carries the outer headers.
func TestOuterLimiterHeadersWin(t *testing.T) {
	core, _ := manifests(t)
	o := options(t, core)
	o.Auth.RateLimits.MFAEnroll = config.RateLimit{Limit: 5, Window: time.Minute, KeyPrefix: "auth.mfa_enroll"}
	o.Auth.RateLimits.Authenticated = config.RateLimit{Limit: 1, Window: time.Minute, KeyPrefix: "auth.authenticated"}
	p := newPipeline(t, o)
	h := p.ipRateLimit(p.principalRateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("{}"))
	})))
	var method, path string
	for _, rt := range core.Routes() {
		if rt.RateLimit == "mfa_enroll" && rt.Auth == "bearer" {
			method, path = rt.Method, rt.Path
			break
		}
	}
	tok := issue(t, "user-1", nil)
	req := func() *http.Request { return withToken(routed(t, core, method, path), tok) }

	first := serve(h, req())
	if first.Code != 200 || first.Header().Get("X-RateLimit-Limit") != "5" || first.Header().Get("X-RateLimit-Remaining") != "4" {
		t.Fatalf("first: %d %v", first.Code, first.Header())
	}
	second := serve(h, req())
	if second.Code != 429 || second.Header().Get("X-RateLimit-Limit") != "5" || second.Header().Get("Retry-After") == "" {
		t.Fatalf("second: %d %v", second.Code, second.Header())
	}
}

// An IPv6 client is budgeted by its /64: one subscriber holds at least that many addresses, so a
// budget per address is no budget (decision 76). IPv4 stays per address.
func TestAnIPv6ClientIsLimitedByItsNetwork(t *testing.T) {
	core, _ := manifests(t)
	o := options(t, core)
	o.Auth.RateLimits.Login = config.RateLimit{Limit: 2, Window: time.Minute, KeyPrefix: "auth.login"}
	mw := newPipeline(t, o).ipRateLimit(&counting{})
	from := func(addr string) int {
		r := routed(t, core, "POST", "/auth/login")
		r.RemoteAddr = addr
		return serve(mw, r).Code
	}
	for i, tc := range []struct {
		addr string
		want int
	}{
		{"[2001:db8:1:2::1]:1000", 200}, {"[2001:db8:1:2:ffff:ffff:ffff:9]:1000", 200}, {"[2001:db8:1:2:abcd::7]:1000", 429},
		{"[2001:db8:1:3::1]:1000", 200}, // another /64
		{"198.51.100.1:1000", 200}, {"198.51.100.1:1000", 200}, {"198.51.100.1:1000", 429}, {"198.51.100.2:1000", 200},
		{"[::ffff:198.51.100.2]:1000", 200}, {"[::ffff:198.51.100.2]:1000", 429}, // the same IPv4 client, mapped
	} {
		if got := from(tc.addr); got != tc.want {
			t.Errorf("request %d from %s: %d, want %d", i, tc.addr, got, tc.want)
		}
	}
}
