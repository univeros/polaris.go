package pipeline

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/token"
)

// BearerTokenExtractorTest
func TestBearerToken(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc.def.ghi":    "abc.def.ghi",
		"bearer abc.def.ghi":    "abc.def.ghi",
		"BEARER abc.def.ghi":    "abc.def.ghi",
		"Bearer    abc.def.ghi": "abc.def.ghi",
		"Basic dXNlcjpwYXNz":    "",
		"Bearer":                "",
		"Bearer   ":             "",
		"":                      "",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		if header != "" {
			r.Header.Set("Authorization", header)
		}
		if got := bearerToken(r); got != want {
			t.Errorf("%q: got %q, want %q", header, got, want)
		}
	}
}

// ClientContextMiddlewareTest
func TestClientContext(t *testing.T) {
	seen := func(r *http.Request) *http.Request {
		c := &counting{}
		clientContext(c).ServeHTTP(httptest.NewRecorder(), r)
		return c.last
	}
	request := func() *http.Request {
		r := httptest.NewRequest("POST", "/auth/login", nil)
		r.RemoteAddr = "203.0.113.7:51000"
		return r
	}

	t.Run("testAttachesTheUserAgentAndTheRemoteAddress", func(t *testing.T) {
		r := request()
		r.Header.Set("User-Agent", "Browser/1.0")
		got := endpoint.Client(seen(r).Context())
		if got.UserAgent != "Browser/1.0" || got.IP != "203.0.113.7" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("testStripsControlCharactersAndTruncatesToTheColumnSize", func(t *testing.T) {
		r := request()
		r.Header.Set("User-Agent", "Evil/1.0\tInjected"+strings.Repeat("a", 300))
		ua := endpoint.Client(seen(r).Context()).UserAgent
		if strings.Contains(ua, "\t") || len(ua) != 255 || !strings.HasPrefix(ua, "Evil/1.0Injected") {
			t.Fatalf("%q", ua)
		}
	})
	t.Run("testAnAbsentHeaderSetsNoAttributeAndAPresetIpIsKept", func(t *testing.T) {
		r := request()
		r = r.WithContext(endpoint.WithClient(r.Context(), token.ClientContext{IP: "198.51.100.9"}))
		got := endpoint.Client(seen(r).Context())
		if got.UserAgent != "" || got.IP != "198.51.100.9" {
			t.Fatalf("%+v", got)
		}
	})
	t.Run("no remote address is unknown for the limiter", func(t *testing.T) {
		r := request()
		r.RemoteAddr = ""
		if ip := clientIP(seen(r)); ip != "unknown" {
			t.Fatalf("%q", ip)
		}
		if ip := clientIP(request()); ip != "203.0.113.7" {
			t.Fatalf("without the middleware: %q", ip)
		}
	})
}

// The 401 JSON envelope carries a challenge.
func TestUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	unauthorized(w)
	if w.Code != 401 || w.Header().Get("Content-Type") != "application/json" || w.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if w.Body.String() != `{"error":"unauthorized","message":"Authentication is required."}` {
		t.Fatal(w.Body)
	}
}

// MfaTokenMiddlewareTest
func TestMFATicket(t *testing.T) {
	core, _ := manifests(t)
	p := newPipeline(t, options(t, core))

	t.Run("testARequestOutsideTheGatePassesThroughUntouched", func(t *testing.T) {
		c := &counting{}
		if w := serve(p.mfaTicket(c), routed(t, core, "GET", "/auth/me")); w.Code != 200 || c.calls != 1 {
			t.Fatalf("%d %d", w.Code, c.calls)
		}
	})
	t.Run("testAValidTicketAttachesTheUserIdAndDelegates", func(t *testing.T) {
		c := &counting{}
		r := routed(t, core, "POST", "/auth/mfa/verify")
		r.Header.Set("Authorization", "Bearer good-ticket")
		if w := serve(p.mfaTicket(c), r); w.Code != 200 {
			t.Fatal(w.Code)
		}
		if id, ok := endpoint.MFATicket(c.last.Context()); !ok || id != "user-1" {
			t.Fatalf("%q %v", id, ok)
		}
	})
	t.Run("testAMissingOrInvalidTicketIsRejected", func(t *testing.T) {
		c := &counting{}
		bad := routed(t, core, "POST", "/auth/mfa/verify")
		bad.Header.Set("Authorization", "Bearer bad")
		for _, r := range []*http.Request{routed(t, core, "POST", "/auth/mfa/verify"), bad} {
			if w := serve(p.mfaTicket(c), r); w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal(w.Code)
			}
		}
		if c.calls != 0 {
			t.Fatal("the gate endpoint is never reached")
		}
	})
}

func TestBearerAuthentication(t *testing.T) {
	core, _ := manifests(t)
	tok := issue(t, "user-1", nil)
	resolved := issue(t, "agent-1", nil)

	t.Run("a public route is not authenticated", func(t *testing.T) {
		c := &counting{}
		serve(newPipeline(t, options(t, core)).bearer(c), routed(t, core, "POST", "/auth/login"))
		if c.calls != 1 || endpoint.Token(c.last.Context()) != nil {
			t.Fatal("public route touched")
		}
	})
	t.Run("a valid access token becomes the principal", func(t *testing.T) {
		c := &counting{}
		r := routed(t, core, "GET", "/auth/me")
		r.Header.Set("Authorization", "Bearer "+tok.Raw())
		serve(newPipeline(t, options(t, core)).bearer(c), r)
		if c.calls != 1 || endpoint.Token(c.last.Context()).Subject() != "user-1" {
			t.Fatal("token not recorded")
		}
	})
	t.Run("missing and invalid bearers answer 401", func(t *testing.T) {
		c := &counting{}
		bad := routed(t, core, "GET", "/auth/me")
		bad.Header.Set("Authorization", "Bearer not-a-real-jwt")
		for _, r := range []*http.Request{routed(t, core, "GET", "/auth/me"), bad} {
			if w := serve(newPipeline(t, options(t, core)).bearer(c), r); w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" {
				t.Fatal(w.Code)
			}
		}
		if c.calls != 0 {
			t.Fatal("reached")
		}
	})
	t.Run("resolvers are asked first, in order", func(t *testing.T) {
		var asked []string
		o := options(t, core)
		o.BearerResolvers = []BearerResolver{
			resolverFunc(func(*http.Request) (*token.Token, error) { asked = append(asked, "first"); return nil, nil }),
			resolverFunc(func(*http.Request) (*token.Token, error) { asked = append(asked, "second"); return resolved, nil }),
			resolverFunc(func(*http.Request) (*token.Token, error) { asked = append(asked, "third"); return nil, nil }),
		}
		c := &counting{}
		r := routed(t, core, "GET", "/auth/me")
		r.Header.Set("Authorization", "Bearer "+tok.Raw())
		serve(newPipeline(t, o).bearer(c), r)
		if strings.Join(asked, ",") != "first,second" || endpoint.Token(c.last.Context()).Subject() != "agent-1" {
			t.Fatalf("asked %v", asked)
		}
	})
	t.Run("a resolver refusing its credential answers 401", func(t *testing.T) {
		o := options(t, core)
		o.BearerResolvers = []BearerResolver{resolverFunc(func(*http.Request) (*token.Token, error) { return nil, errors.New("revoked") })}
		c := &counting{}
		r := routed(t, core, "GET", "/auth/me")
		r.Header.Set("Authorization", "Bearer "+tok.Raw())
		if w := serve(newPipeline(t, o).bearer(c), r); w.Code != 401 || c.calls != 0 {
			t.Fatal(w.Code)
		}
	})
}

// StepUpMiddlewareTest
func TestStepUp(t *testing.T) {
	core, _ := manifests(t)
	const maxAge = 300
	step := func(has bool) func(http.Handler) http.Handler {
		o := options(t, core)
		o.StepUp = stubStepUp{has: has}
		o.Auth.StepUpMaxAge = maxAge * 1e9
		return newPipeline(t, o).stepUp
	}
	authed := func(method, path string, ago *int64) *http.Request {
		extra := map[string]any{}
		if ago != nil {
			extra["auth_time"] = now.Unix() - *ago
		}
		return withToken(routed(t, core, method, path), issue(t, "user-1", extra))
	}
	ago := func(s int64) *int64 { return &s }

	t.Run("testANonSensitiveRoutePassesThrough", func(t *testing.T) {
		c := &counting{}
		if w := serve(step(true)(c), authed("GET", "/auth/me", ago(9999))); w.Code != 200 || c.calls != 1 {
			t.Fatal(w.Code)
		}
	})
	t.Run("testAUserWithoutAConfirmedFactorPassesThroughEvenWhenStale", func(t *testing.T) {
		if w := serve(step(false)(&counting{}), authed("POST", "/auth/password/change", ago(9999))); w.Code != 200 {
			t.Fatal(w.Code)
		}
	})
	t.Run("testRecentAuthPassesThrough", func(t *testing.T) {
		if w := serve(step(true)(&counting{}), authed("POST", "/auth/password/change", ago(100))); w.Code != 200 {
			t.Fatal(w.Code)
		}
	})
	t.Run("testStaleOrMissingAuthTimeIsRejectedWithStepUpRequired", func(t *testing.T) {
		c := &counting{}
		w := serve(step(true)(c), authed("POST", "/auth/password/change", ago(600)))
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") != `Bearer error="step_up_required"` {
			t.Fatalf("%d %v", w.Code, w.Header())
		}
		body := decode(t, w.Body.Bytes())
		if body["error"] != "step_up_required" || body["step_up"] != "/auth/mfa/step-up" || body["message"] != "This operation requires a recent re-authentication." {
			t.Fatal(body)
		}
		if w := serve(step(true)(c), authed("POST", "/auth/password/change", nil)); w.Code != 401 {
			t.Fatal(w.Code)
		}
		if c.calls != 0 {
			t.Fatal("the sensitive endpoint is never reached")
		}
	})
	t.Run("testAnUnauthenticatedRequestFailsClosed", func(t *testing.T) {
		c := &counting{}
		if w := serve(step(true)(c), routed(t, core, "POST", "/auth/password/change")); w.Code != 401 || c.calls != 0 {
			t.Fatal(w.Code)
		}
	})
	t.Run("a factor lookup failure answers 500", func(t *testing.T) {
		o := options(t, core)
		o.StepUp = stubStepUp{err: errors.New("db down")}
		w := serve(newPipeline(t, o).stepUp(&counting{}), authed("POST", "/auth/password/change", nil))
		if w.Code != 500 || decode(t, w.Body.Bytes())["error"] != "server_error" {
			t.Fatal(w.Code)
		}
	})
}

func TestDenylist(t *testing.T) {
	core, _ := manifests(t)
	deny := func(on bool, d stubDenylist) http.Handler {
		o := options(t, core)
		o.Auth.AccessToken.Denylist = on
		o.Denylist = d
		return newPipeline(t, o).denylist(&counting{})
	}
	authed := withToken(routed(t, core, "GET", "/auth/me"), issue(t, "user-1", nil))

	if w := serve(deny(false, stubDenylist{revoked: true}), authed); w.Code != 200 {
		t.Fatalf("off: %d", w.Code)
	}
	if w := serve(deny(true, stubDenylist{revoked: true}), routed(t, core, "GET", "/auth/me")); w.Code != 200 {
		t.Fatalf("anonymous: %d", w.Code)
	}
	if w := serve(deny(true, stubDenylist{}), authed); w.Code != 200 {
		t.Fatalf("live: %d", w.Code)
	}
	w := serve(deny(true, stubDenylist{revoked: true}), authed)
	if w.Code != 401 || w.Body.String() != `{"error":"session_ended","message":"The session is no longer active."}` || w.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("revoked: %d %s %v", w.Code, w.Body, w.Header())
	}
	if w := serve(deny(true, stubDenylist{}), withToken(routed(t, core, "GET", "/auth/me"), issue(t, "", nil))); w.Code != 401 {
		t.Fatalf("no subject: %d", w.Code)
	}
	if w := serve(deny(true, stubDenylist{err: errors.New("cache down")}), authed); w.Code != 500 {
		t.Fatalf("error: %d", w.Code)
	}
}

// sessionDenylist is a Denylist that also knows the sessions that ended.
type sessionDenylist struct {
	stubDenylist
	ended string
	err   error
	asked *int
}

func (s sessionDenylist) SessionRevoked(_ context.Context, sessionID string) (bool, error) {
	*s.asked++
	return sessionID == s.ended, s.err
}

func TestTheDenylistRefusesTheTokensOfAnEndedSession(t *testing.T) {
	core, _ := manifests(t)
	sid := func(v any) map[string]any { return map[string]any{"sid": v} }
	for name, c := range map[string]struct {
		d     sessionDenylist
		extra map[string]any
		code  int
		asked int
	}{
		"ended":                        {sessionDenylist{ended: "s1"}, sid("s1"), 401, 1},
		"live":                         {sessionDenylist{ended: "s1"}, sid("s2"), 200, 1},
		"no session":                   {sessionDenylist{ended: ""}, nil, 200, 0},
		"a sid that is no string":      {sessionDenylist{ended: ""}, sid(int64(7)), 200, 0},
		"the user's every session":     {sessionDenylist{stubDenylist: stubDenylist{revoked: true}}, sid("s1"), 401, 0},
		"a failing lookup":             {sessionDenylist{err: errors.New("cache down")}, sid("s1"), 500, 1},
		"a failing lookup of the user": {sessionDenylist{stubDenylist: stubDenylist{err: errors.New("cache down")}}, sid("s1"), 500, 0},
	} {
		asked := 0
		c.d.asked = &asked
		o := options(t, core)
		o.Auth.AccessToken.Denylist = true
		o.Denylist = c.d
		tok := issue(t, "user-1", c.extra)
		p := newPipeline(t, o)
		bearer := httptest.NewRequest(http.MethodGet, "/api", nil)
		bearer.Header.Set("Authorization", "Bearer "+tok.Raw())
		for where, w := range map[string]*httptest.ResponseRecorder{
			"a route":      serve(p.denylist(&counting{}), withToken(routed(t, core, "GET", "/auth/me"), tok)),
			"Protect":      serve(p.Protect(&counting{}), bearer),
			"Authenticate": serve(p.Authenticate(&counting{}), bearer),
		} {
			if w.Code != c.code || c.code == 401 && w.Body.String() != `{"error":"session_ended","message":"The session is no longer active."}` {
				t.Errorf("%s, %s: %d %s, want %d", name, where, w.Code, w.Body, c.code)
			}
		}
		if asked != 3*c.asked {
			t.Errorf("%s: asked %d times, want %d", name, asked, 3*c.asked)
		}
		o.Auth.AccessToken.Denylist = false
		if w := serve(newPipeline(t, o).Protect(&counting{}), bearer); w.Code != 200 {
			t.Errorf("%s, denylist off: %d", name, w.Code)
		}
	}
}

func TestAuthorization(t *testing.T) {
	core, _ := manifests(t)
	authorize := func(g stubGate) func(http.Handler) http.Handler {
		o := options(t, core)
		o.Gate = g
		return newPipeline(t, o).authorize
	}
	user := issue(t, "user-1", nil)
	delegate := issue(t, "user-1", nil).Delegate([]string{"roles.manage"})
	// A wire claim never makes a delegate (decision #14).
	forged := issue(t, "user-1", map[string]any{"delegated": []string{"roles.manage"}})
	if _, ok := forged.Delegation(); ok {
		t.Fatal("a delegated claim must not mark delegation")
	}
	rt, ok := core.Find("DELETE", "/orgs/{id}/roles/{roleId}")
	if !ok {
		t.Fatal("role delete route")
	}
	req := func(method, path string, tok *token.Token) *http.Request {
		r := httptest.NewRequest(method, "/", nil)
		route, ok := core.Find(method, path)
		if !ok {
			t.Fatalf("%s %s", method, path)
		}
		r = r.WithContext(endpoint.WithRoute(r.Context(), route))
		if tok != nil {
			r = withToken(r, tok)
		}
		return r
	}

	t.Run("no permissions, no check", func(t *testing.T) {
		if w := serve(authorize(stubGate{err: errors.New("never asked")})(&counting{}), req("GET", "/auth/me", user)); w.Code != 200 {
			t.Fatal(w.Code)
		}
	})
	t.Run("required permissions need a principal", func(t *testing.T) {
		w := serve(authorize(stubGate{})(&counting{}), req("DELETE", rt.Path, nil))
		if w.Code != 401 || w.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Fatal(w.Code)
		}
	})
	t.Run("an authority without the permission is forbidden", func(t *testing.T) {
		w := serve(authorize(stubGate{grants: grants{"members.read"}})(&counting{}), req("DELETE", rt.Path, user))
		if w.Code != 403 || w.Body.String() != `{"error":"forbidden","message":"You do not have permission to perform this action."}` {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
	t.Run("the granted authority is recorded", func(t *testing.T) {
		c := &counting{}
		if w := serve(authorize(stubGate{grants: grants{"roles.manage"}})(c), req("DELETE", rt.Path, user)); w.Code != 200 {
			t.Fatal(w.Code)
		}
		if a, ok := endpoint.Authority(c.last.Context()).(grants); !ok || a[0] != "roles.manage" {
			t.Fatalf("%v", endpoint.Authority(c.last.Context()))
		}
	})
	t.Run("a gate failure answers 500", func(t *testing.T) {
		if w := serve(authorize(stubGate{err: errors.New("db")})(&counting{}), req("DELETE", rt.Path, user)); w.Code != 500 {
			t.Fatal(w.Code)
		}
	})
	t.Run("a delegated credential may read and use its permissions", func(t *testing.T) {
		if w := serve(authorize(stubGate{grants: grants{"roles.manage"}})(&counting{}), req("DELETE", rt.Path, delegate)); w.Code != 200 {
			t.Fatal(w.Code)
		}
		if w := serve(authorize(stubGate{})(&counting{}), req("GET", "/auth/me", delegate)); w.Code != 200 {
			t.Fatal(w.Code)
		}
	})
	t.Run("a delegated credential may not self-serve nor step up", func(t *testing.T) {
		const msg = `{"error":"forbidden","message":"This action is for the account holder, not for a delegated credential."}`
		for _, r := range []*http.Request{req("POST", "/orgs", delegate), req("POST", "/auth/password/change", delegate)} {
			if w := serve(authorize(stubGate{})(&counting{}), r); w.Code != 403 || w.Body.String() != msg {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		}
		if w := serve(authorize(stubGate{})(&counting{}), req("POST", "/orgs", user)); w.Code != 200 {
			t.Fatal("the account holder may")
		}
	})
	t.Run("a session an identity provider opened stays off the account's own routes", func(t *testing.T) {
		bound := issue(t, "user-1", map[string]any{"amr": []string{"sso"}})
		if !bound.OrganizationBound() || user.OrganizationBound() || issue(t, "user-1", map[string]any{"amr": []string{"pwd", "otp"}}).OrganizationBound() {
			t.Fatal("amr sso, and only it, binds a session to its organization")
		}
		msg := `{"error":"forbidden","message":"` + MsgOrganizationBound + `"}`
		for _, r := range []*http.Request{
			req("POST", "/auth/switch-org", bound), req("POST", "/auth/password/change", bound), req("POST", "/auth/mfa/totp/enroll", bound),
			req("DELETE", "/auth/mfa/factors/{id}", bound), req("POST", "/auth/mfa/step-up", bound), req("POST", "/auth/logout-all", bound),
			req("POST", "/orgs", bound), req("POST", "/auth/invites/accept", bound), req("DELETE", "/users/{id}", bound), req("PATCH", "/users/{id}", bound),
		} {
			if w := serve(authorize(stubGate{})(&counting{}), r); w.Code != 403 || w.Body.String() != msg {
				t.Errorf("%s %s: %d %s", r.Method, r.URL.Path, w.Code, w.Body)
			}
		}
		// It reads, ends itself, and does what its organization's permissions allow.
		for _, r := range []*http.Request{req("GET", "/auth/me", bound), req("POST", "/auth/logout", bound), req("GET", "/orgs", bound)} {
			if w := serve(authorize(stubGate{})(&counting{}), r); w.Code != 200 {
				t.Errorf("%s %s: %d", r.Method, r.URL.Path, w.Code)
			}
		}
		if w := serve(authorize(stubGate{grants: grants{"roles.manage"}})(&counting{}), req("DELETE", rt.Path, bound)); w.Code != 200 {
			t.Errorf("a permission of its organization: %d", w.Code)
		}
	})
}
