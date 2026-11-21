package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/token"
)

const authMiddlewareTest = `Polaris\Tests\Functional\AuthMiddlewareTest`

// AuthMiddlewareTest: the middleware-level assertions, against stub endpoints. The fixtures whose
// steps the pipeline alone answers are replayed.
func TestAuthMiddleware(t *testing.T) {
	core, _ := manifests(t)
	dir := contracttest.Fixtures(t, "core")
	newHandler := func(t *testing.T) http.Handler {
		o := options(t, core)
		o.Endpoints["polaris.auth.me"] = endpoint.Func(func(ctx context.Context, _ *endpoint.Input) endpoint.Result {
			return endpoint.Data(200, map[string]any{"id": endpoint.Token(ctx).Subject()})
		})
		return newPipeline(t, o).Handler()
	}

	t.Run("testAPublicPathSkipsAuthentication", func(t *testing.T) {
		if w := serve(newHandler(t), httptest.NewRequest("GET", "/auth/.well-known/jwks.json", nil)); w.Code != 200 {
			t.Fatal(w.Code)
		}
	})
	t.Run("testAProtectedPathWithoutATokenIsRejectedByTheMiddleware", func(t *testing.T) {
		c := contracttest.NewClient(t, newHandler(t), contracttest.For(t, dir, authMiddlewareTest, "testAProtectedPathWithoutATokenIsRejectedByTheMiddleware"))
		c.Get("/auth/me")
	})
	t.Run("testAProtectedPathWithAnInvalidBearerIsUnauthorized", func(t *testing.T) {
		c := contracttest.NewClient(t, newHandler(t), contracttest.For(t, dir, authMiddlewareTest, "testAProtectedPathWithAnInvalidBearerIsUnauthorized"))
		c.Get("/auth/me", contracttest.Bearer("not-a-real-jwt"))
	})
	t.Run("testEveryProtectedRouteIsRejectedByTheMiddlewareWithoutAToken", func(t *testing.T) {
		c := contracttest.NewClient(t, newHandler(t), contracttest.For(t, dir, authMiddlewareTest, "testEveryProtectedRouteIsRejectedByTheMiddlewareWithoutAToken"))
		c.Get("/auth/me")
		c.Get("/auth/sessions")
		c.Post("/auth/logout", map[string]any{})
		c.Post("/auth/logout-all", map[string]any{})
		c.Post("/auth/password/change", map[string]any{})
		c.Delete("/auth/sessions/abc")
	})
	t.Run("testAProtectedPathWithAValidBearerReachesTheDomain", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/auth/me", nil)
		r.Header.Set("Authorization", "Bearer "+issue(t, "user-1", nil).Raw())
		w := serve(newHandler(t), r)
		if w.Code != 200 || w.Body.String() != `{"data":{"id":"user-1"}}` {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
	t.Run("testLoginIsRateLimited", func(t *testing.T) {
		h := newHandler(t)
		login := func() *httptest.ResponseRecorder {
			return serve(h, httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{}`)))
		}
		for i := range 10 {
			if w := login(); w.Code == 429 {
				t.Fatalf("request %d should be within budget", i)
			}
		}
		w := login()
		if w.Code != 429 || w.Header().Get("X-RateLimit-Limit") != "10" || w.Header().Get("Retry-After") == "" {
			t.Fatalf("%d %v", w.Code, w.Header())
		}
	})
}

// The contractual order: plugin middleware sees the principal before step-up, the denylist, the
// per-user limiter and the gate; the per-user limiter wraps authorization, so a 403 carries the
// rate-limit headers; the per-IP limiter runs before bearer authentication.
func TestOrder(t *testing.T) {
	core, _ := manifests(t)
	var trace []string
	o := options(t, core)
	o.PluginMiddleware = []func(http.Handler) http.Handler{
		func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				trace = append(trace, "plugin:"+endpoint.Token(r.Context()).Subject())
				next.ServeHTTP(w, r)
			})
		},
	}
	o.Gate = stubGate{grants: grants{}}
	p := newPipeline(t, o)
	tok := issue(t, "user-1", nil)

	r := httptest.NewRequest("DELETE", "/orgs/o1/roles/r1", nil)
	r.Header.Set("Authorization", "Bearer "+tok.Raw())
	w := serve(p.Handler(), r)
	if w.Code != 403 || w.Header().Get("X-RateLimit-Limit") != "600" {
		t.Fatalf("403 with the per-user headers: %d %v", w.Code, w.Header())
	}
	if strings.Join(trace, ",") != "plugin:user-1" {
		t.Fatalf("trace %v", trace)
	}

	// mfa enroll: bearer + per-IP group; an anonymous 401 still spends and reports the IP budget.
	for _, rt := range core.Routes() {
		if rt.RateLimit == "mfa_enroll" && rt.Auth == "bearer" && !strings.Contains(rt.Path, "{") {
			w := serve(p.Handler(), httptest.NewRequest(rt.Method, rt.Path, nil))
			if w.Code != 401 || w.Header().Get("X-RateLimit-Limit") != "5" {
				t.Fatalf("%s: %d %v", rt.Pattern(), w.Code, w.Header())
			}
			break
		}
	}

	if n := len(p.Middleware()); n != 10 {
		t.Fatalf("body delivery: %d middleware", n)
	}
	o.Auth.Flows.TokenDelivery = config.DeliveryCookie
	if n := len(newPipeline(t, o).Middleware()); n != 11 {
		t.Fatalf("cookie delivery: %d middleware", n)
	}
}

type countingGate struct {
	calls *atomic.Int32
	err   error
}

func (g countingGate) Authority(context.Context, *token.Token) (Authority, error) {
	g.calls.Add(1)
	return grants{"invoices.read"}, g.err
}

// Protect without permissions resolves nothing unless the handler asks, then once per request;
// with permissions it resolves once, up front, and the handler reuses it.
func TestProtectResolvesTheAuthorityLazilyOnce(t *testing.T) {
	core, _ := manifests(t)
	calls := &atomic.Int32{}
	o := options(t, core)
	o.Gate = countingGate{calls: calls}
	p := newPipeline(t, o)
	tok := issue(t, "user-1", nil)
	req := func() *http.Request {
		r := httptest.NewRequest("GET", "/api", nil)
		r.Header.Set("Authorization", "Bearer "+tok.Raw())
		return r
	}
	reads := 0
	reader := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for range reads {
			if a, err := endpoint.ResolveAuthority(r.Context()); err != nil || a == nil {
				t.Errorf("authority %v %v", a, err)
			}
		}
	})
	for _, c := range []struct {
		perms []string
		reads int
		want  int32
	}{{nil, 0, 0}, {nil, 2, 1}, {[]string{"invoices.read"}, 0, 1}, {[]string{"invoices.read"}, 2, 1}} {
		calls.Store(0)
		reads = c.reads
		if w := serve(p.Protect(reader, c.perms...), req()); w.Code != 200 || calls.Load() != c.want {
			t.Errorf("perms %v, %d reads: %d, %d gate calls, want %d", c.perms, c.reads, w.Code, calls.Load(), c.want)
		}
	}

	o.Gate = countingGate{calls: calls, err: errors.New("db down")}
	p = newPipeline(t, o)
	failed := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := endpoint.ResolveAuthority(r.Context()); err == nil || endpoint.Authority(r.Context()) != nil {
			t.Error("a failed resolution is an error, and no authority")
		}
	})
	serve(p.Protect(failed), req())
}

func TestProtect(t *testing.T) {
	core, _ := manifests(t)
	host := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, _ := endpoint.Authority(r.Context()).(grants)
		_, _ = w.Write([]byte(endpoint.Token(r.Context()).Subject() + " " + strings.Join(a, ",") + " " + endpoint.Client(r.Context()).IP))
	})
	o := options(t, core)
	o.Gate = stubGate{grants: grants{"invoices.read"}}
	p := newPipeline(t, o)
	tok := issue(t, "user-1", nil)
	req := func(bearer string) *http.Request {
		r := httptest.NewRequest("GET", "/api/invoices", nil)
		r.RemoteAddr = "203.0.113.7:1"
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		return r
	}

	if w := serve(p.Protect(host), req("")); w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("anonymous: %d", w.Code)
	}
	// Without permissions the authority is resolved when the handler reads it.
	if w := serve(p.Protect(host), req(tok.Raw())); w.Code != 200 || w.Body.String() != "user-1 invoices.read 203.0.113.7" {
		t.Fatalf("authenticated: %d %q", w.Code, w.Body)
	}
	if w := serve(p.Protect(host, "invoices.read"), req(tok.Raw())); w.Code != 200 || w.Body.String() != "user-1 invoices.read 203.0.113.7" {
		t.Fatalf("granted: %d %q", w.Code, w.Body)
	}
	if w := serve(p.Protect(host, "invoices.write"), req(tok.Raw())); w.Code != 403 {
		t.Fatalf("forbidden: %d", w.Code)
	}

	o.Auth.AccessToken.Denylist = true
	o.Denylist = stubDenylist{revoked: true}
	if w := serve(newPipeline(t, o).Protect(host), req(tok.Raw())); w.Code != 401 || !strings.Contains(w.Body.String(), "session_ended") {
		t.Fatalf("denylisted: %d", w.Code)
	}

	o.BearerResolvers = []BearerResolver{resolverFunc(func(*http.Request) (*token.Token, error) { return issue(t, "agent-1", nil), nil })}
	o.Denylist = stubDenylist{}
	if w := serve(newPipeline(t, o).Protect(host), req("")); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "agent-1") {
		t.Fatalf("resolver: %d %q", w.Code, w.Body)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("Protect with permissions and no Gate must panic")
		}
	}()
	(&Pipeline{}).Protect(host, "x")
}

func TestNewReportsEveryProblem(t *testing.T) {
	core, _ := manifests(t)
	o := options(t, core)
	delete(o.Endpoints, "polaris.auth.login")
	delete(o.Endpoints, "polaris.auth.me")
	o.Tokens, o.MFATickets, o.StepUp, o.Gate = nil, nil, nil, nil
	o.Auth.AccessToken.Denylist = true
	o.Denylist = nil
	o.Auth.Issuer = ""
	_, err := New(o)
	if err == nil {
		t.Fatal("New accepted broken options")
	}
	for _, want := range []string{"Options.Auth", "Options.Tokens", "Options.Denylist", "Options.MFATickets", "Options.StepUp", "Options.Gate",
		"2 route(s)", "polaris.auth.login (POST /auth/login)", "polaris.auth.me (GET /auth/me)"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q: %v", want, err)
		}
	}
	if _, err := New(Options{}); err == nil || !strings.Contains(err.Error(), "manifest.Load") {
		t.Fatalf("nil manifest: %v", err)
	}

	o = options(t, core)
	o.Clock, o.Logger, o.RateStore = nil, nil, nil
	if p := newPipeline(t, o); p.clock == nil || p.log == nil || p.rates == nil {
		t.Fatal("defaults not applied")
	}
}

// Every route-driven middleware passes a request without a route through untouched.
func TestUnroutedRequestsPassThrough(t *testing.T) {
	core, _ := manifests(t)
	o := options(t, core)
	o.Auth.Flows.TokenDelivery = config.DeliveryCookie
	p := newPipeline(t, o)
	for i, mw := range p.Middleware()[1:] {
		c := &counting{}
		if w := serve(mw(c), httptest.NewRequest("POST", "/host", nil)); w.Code != 200 || c.calls != 1 {
			t.Errorf("middleware %d: %d", i+1, w.Code)
		}
	}
}

// The limiter's writer flushes with its headers, and an inner handler that writes nothing still
// gets them.
func TestLimiterWriter(t *testing.T) {
	core, _ := manifests(t)
	p := newPipeline(t, options(t, core))
	flushed := serve(p.ipRateLimit(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
	})), routed(t, core, "POST", "/auth/login"))
	if !flushed.Flushed || flushed.Result().Header.Get("X-RateLimit-Limit") != "10" {
		t.Fatalf("%v %v", flushed.Flushed, flushed.Header())
	}
	silent := serve(p.ipRateLimit(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})), routed(t, core, "POST", "/auth/login"))
	if silent.Code != 200 || silent.Header().Get("X-RateLimit-Limit") != "10" {
		t.Fatalf("%d %v", silent.Code, silent.Header())
	}
}
