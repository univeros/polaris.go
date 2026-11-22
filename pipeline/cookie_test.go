package pipeline

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/manifest"
)

const (
	secret       = "rt_abc-DEF_123"
	deviceCookie = "polaris_ms_device=d1; Path=/; HttpOnly; SameSite=Lax"
	clearCookie  = "__Secure-polaris_refresh=; Path=/auth/token/refresh; Max-Age=0; HttpOnly; Secure; SameSite=Strict"
)

// inner is CookieInnerHandler: it answers status with body, a stale Content-Length and a cookie
// of its own, and records the request it saw.
type inner struct {
	status int
	body   any
	called bool
	seen   *http.Request
	raw    []byte
}

func (h *inner) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called, h.seen = true, r
	if r.Body != nil {
		h.raw, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(h.raw))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", "999")
	w.Header().Add("Set-Cookie", deviceCookie)
	status := h.status
	if status == 0 {
		status = 200
	}
	w.WriteHeader(status)
	body := h.body
	if body == nil {
		body = []any{}
	}
	b, _ := json.Marshal(body)
	_, _ = w.Write(b)
}

type cookieRequest struct {
	body    map[string]any
	cookie  string
	headers map[string]string // nil means the CSRF header and this origin
	scheme  string
	query   string
}

func cookieReq(rt *manifest.Route, o cookieRequest) *http.Request {
	if o.scheme == "" {
		o.scheme = "https"
	}
	if o.headers == nil {
		o.headers = map[string]string{CSRFHeader: "1", "Origin": "https://auth.example.com"}
	}
	if o.body == nil {
		o.body = map[string]any{}
	}
	b, _ := json.Marshal(o.body)
	r := httptest.NewRequest(rt.Method, o.scheme+"://auth.example.com"+rt.Path+o.query, bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	for k, v := range o.headers {
		r.Header.Set(k, v)
	}
	if o.cookie != "" {
		r.AddCookie(&http.Cookie{Name: RefreshCookie, Value: o.cookie})
	}
	return r.WithContext(endpoint.WithRoute(r.Context(), rt))
}

func cookieMiddleware(t *testing.T, prefix string, trusted ...string) func(http.Handler) http.Handler {
	t.Helper()
	_, all := manifests(t)
	o := options(t, all)
	o.PathPrefix = prefix
	o.Auth.Flows.TokenDelivery = config.DeliveryCookie
	o.Auth.Flows.CookieTrustedOrigins = trusted
	return newPipeline(t, o).refreshCookie
}

func spec(t *testing.T, method, path string) *manifest.Route {
	t.Helper()
	_, all := manifests(t)
	rt, ok := all.Find(method, path)
	if !ok {
		t.Fatalf("%s %s is not in the manifest", method, path)
	}
	return rt
}

func guarded(t *testing.T) []*manifest.Route {
	_, all := manifests(t)
	var out []*manifest.Route
	for _, rt := range all.Routes() {
		if rt.Session == manifest.SessionIssue || rt.Session == manifest.SessionRefresh {
			out = append(out, rt)
		}
	}
	if len(out) < 2 || !slices.ContainsFunc(out, func(rt *manifest.Route) bool { return rt.Plugin != "" }) {
		t.Fatalf("expected core and plugin guarded routes, got %d", len(out))
	}
	return out
}

func assertEnvelope(t *testing.T, rt *manifest.Route, code string, w *httptest.ResponseRecorder) {
	t.Helper()
	body := decode(t, w.Body.Bytes())
	if rt.Plugin == "" {
		if w.Header().Get("Content-Type") != "application/json" || len(body) != 2 || body["error"] != code || body["message"] == nil {
			t.Fatalf("%s: %v %v", rt.Pattern(), w.Header(), body)
		}
		return
	}
	if w.Header().Get("Content-Type") != "application/problem+json" || body["type"] != "https://polaris.univeros.io/problems/cookie/"+code ||
		body["status"] != float64(403) || body["error"] != code || body["detail"] != body["message"] || body["title"] == nil {
		t.Fatalf("%s: %v %v", rt.Pattern(), w.Header(), body)
	}
}

func TestRefreshCookie(t *testing.T) {
	mw := cookieMiddleware(t, "/")

	t.Run("testEveryGuardedRouteRefusesAMissingHeaderInItsOwnEnvelope", func(t *testing.T) {
		for _, rt := range guarded(t) {
			h := &inner{}
			w := serve(mw(h), cookieReq(rt, cookieRequest{headers: map[string]string{}}))
			if w.Code != 403 || h.called {
				t.Fatalf("%s: %d", rt.Pattern(), w.Code)
			}
			assertEnvelope(t, rt, "csrf_failed", w)
		}
	})
	t.Run("testEveryGuardedRouteRefusesPlaintextInItsOwnEnvelope", func(t *testing.T) {
		for _, rt := range guarded(t) {
			h := &inner{}
			w := serve(mw(h), cookieReq(rt, cookieRequest{scheme: "http"}))
			if w.Code != 403 || h.called {
				t.Fatalf("%s: %d", rt.Pattern(), w.Code)
			}
			assertEnvelope(t, rt, "insecure_transport", w)
		}
	})
	t.Run("testEveryGuardedRouteMovesTheRefreshTokenToTheCookie", func(t *testing.T) {
		prefixed := cookieMiddleware(t, "/api")
		for _, rt := range guarded(t) {
			h := &inner{body: map[string]any{"data": map[string]any{"access_token": "jwt", "refresh_token": secret, "user": map[string]any{"id": "u1", "meta": map[string]any{}}}}}
			w := serve(prefixed(h), cookieReq(rt, cookieRequest{}))
			if w.Code != 200 || w.Body.String() != `{"data":{"access_token":"jwt","user":{"id":"u1","meta":{}}}}` {
				t.Fatalf("%s: %d %s", rt.Pattern(), w.Code, w.Body)
			}
			if w.Header().Get("Content-Length") != "" || w.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("%s: %v", rt.Pattern(), w.Header())
			}
			want := []string{deviceCookie, "__Secure-polaris_refresh=" + secret + "; Path=/api/auth/token/refresh; Max-Age=2592000; HttpOnly; Secure; SameSite=Strict"}
			if !slices.Equal(w.Header().Values("Set-Cookie"), want) {
				t.Fatalf("%s: %v", rt.Pattern(), w.Header().Values("Set-Cookie"))
			}
		}
	})
	t.Run("testAnMfaTicketOrAnErrorPassesUnchanged", func(t *testing.T) {
		login := spec(t, "POST", "/auth/login")
		ticket := map[string]any{"data": map[string]any{"factors": []any{}, "mfa_required": true, "mfa_token": "t"}}
		passed := serve(mw(&inner{body: ticket}), cookieReq(login, cookieRequest{}))
		failed := serve(mw(&inner{status: 401, body: map[string]any{"error": "invalid_credentials", "message": "x"}}), cookieReq(login, cookieRequest{}))
		want, _ := json.Marshal(ticket)
		if passed.Body.String() != string(want) || !slices.Equal(passed.Header().Values("Set-Cookie"), []string{deviceCookie}) {
			t.Fatalf("%s %v", passed.Body, passed.Header())
		}
		if failed.Code != 401 || !slices.Equal(failed.Header().Values("Set-Cookie"), []string{deviceCookie}) {
			t.Fatalf("%d %v", failed.Code, failed.Header())
		}
	})
	t.Run("testTheRefreshReadsTheCookieOnlyWhenNoInputCarriesAToken", func(t *testing.T) {
		refresh := spec(t, "POST", "/auth/token/refresh")
		fromCookie, fromBody, fromQuery := &inner{}, &inner{}, &inner{}
		serve(mw(fromCookie), cookieReq(refresh, cookieRequest{cookie: "from-cookie", body: map[string]any{"device": "d"}}))
		serve(mw(fromBody), cookieReq(refresh, cookieRequest{cookie: "from-cookie", body: map[string]any{"refresh_token": "from-body"}}))
		serve(mw(fromQuery), cookieReq(refresh, cookieRequest{cookie: "from-cookie", query: "?refresh_token=from-query"}))

		if string(fromCookie.raw) != `{"device":"d","refresh_token":"from-cookie"}` {
			t.Fatalf("cookie: %s", fromCookie.raw)
		}
		if string(fromBody.raw) != `{"refresh_token":"from-body"}` || string(fromQuery.raw) != `{}` {
			t.Fatalf("body %s, query %s", fromBody.raw, fromQuery.raw)
		}
		if got := endpoint.NewInput(fromCookie.seen, nil).String("refresh_token"); got != "from-cookie" {
			t.Fatalf("input: %q", got)
		}
	})
	t.Run("a form-encoded refresh gets the cookie as a form field", func(t *testing.T) {
		refresh := spec(t, "POST", "/auth/token/refresh")
		for body, want := range map[string]string{"device=d": "from-cookie", "refresh_token=from-form": "from-form"} {
			r := cookieReq(refresh, cookieRequest{cookie: "from-cookie"})
			r.Body = io.NopCloser(strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			h := &inner{}
			serve(mw(h), r)
			if got := endpoint.NewInput(h.seen, nil).String("refresh_token"); got != want {
				t.Fatalf("%s: %q", body, got)
			}
		}
	})
	t.Run("testAFailedRefreshClearsTheCookieOnlyWhenTheCookieWasTheCredential", func(t *testing.T) {
		refresh := spec(t, "POST", "/auth/token/refresh")
		invalid := map[string]any{"error": "invalid_grant", "message": "x"}
		byCookie := serve(mw(&inner{status: 401, body: invalid}), cookieReq(refresh, cookieRequest{cookie: "dead"}))
		byBody := serve(mw(&inner{status: 401, body: invalid}), cookieReq(refresh, cookieRequest{cookie: "dead", body: map[string]any{"refresh_token": "bad"}}))
		if !slices.Contains(byCookie.Header().Values("Set-Cookie"), clearCookie) {
			t.Fatal(byCookie.Header())
		}
		if !slices.Equal(byBody.Header().Values("Set-Cookie"), []string{deviceCookie}) {
			t.Fatal(byBody.Header())
		}
	})
	t.Run("testAnEndRouteClearsTheCookieOnSuccessOnly", func(t *testing.T) {
		logout := spec(t, "POST", "/sso/logout")
		ok := serve(mw(&inner{body: map[string]any{"data": []any{}}}), cookieReq(logout, cookieRequest{headers: map[string]string{}, scheme: "http"}))
		refused := serve(mw(&inner{status: 401, body: map[string]any{"error": "unauthorized", "message": "x"}}), cookieReq(logout, cookieRequest{}))
		if !slices.Contains(ok.Header().Values("Set-Cookie"), clearCookie) {
			t.Fatal("no guard, no scheme check: ending a session is always allowed")
		}
		if !slices.Equal(refused.Header().Values("Set-Cookie"), []string{deviceCookie}) {
			t.Fatal(refused.Header())
		}
	})
	t.Run("testATrustedOriginPassesTheGuard", func(t *testing.T) {
		trustedMW := cookieMiddleware(t, "/", "https://app.example.com")
		login := spec(t, "POST", "/auth/login")
		trusted := &inner{}
		serve(trustedMW(trusted), cookieReq(login, cookieRequest{headers: map[string]string{CSRFHeader: "1", "Origin": "https://app.example.com"}}))
		other := serve(trustedMW(&inner{}), cookieReq(login, cookieRequest{headers: map[string]string{CSRFHeader: "1", "Origin": "https://other.example.com"}}))
		if !trusted.called || other.Code != 403 {
			t.Fatal(other.Code)
		}
	})
	t.Run("testTheOAuthTokenEndpointIsNotTouched", func(t *testing.T) {
		tok := spec(t, "POST", "/oauth2/token")
		body := map[string]any{"access_token": "a", "refresh_token": "prt_x", "token_type": "Bearer"}
		w := serve(mw(&inner{body: body}), cookieReq(tok, cookieRequest{headers: map[string]string{}, scheme: "http"}))
		want, _ := json.Marshal(body)
		if w.Body.String() != string(want) || !slices.Equal(w.Header().Values("Set-Cookie"), []string{deviceCookie}) {
			t.Fatalf("%s %v", w.Body, w.Header())
		}
	})
	t.Run("Sec-Fetch-Site decides without an Origin", func(t *testing.T) {
		login := spec(t, "POST", "/auth/login")
		for site, want := range map[string]int{"same-origin": 200, "cross-site": 403} {
			w := serve(mw(&inner{}), cookieReq(login, cookieRequest{headers: map[string]string{CSRFHeader: "1", "Sec-Fetch-Site": site}}))
			if w.Code != want {
				t.Fatalf("%s: %d", site, w.Code)
			}
		}
		if w := serve(mw(&inner{}), cookieReq(login, cookieRequest{headers: map[string]string{CSRFHeader: "1"}})); w.Code != 200 {
			t.Fatalf("neither header: %d", w.Code)
		}
	})
}

func TestRequestOrigin(t *testing.T) {
	for target, want := range map[string]string{
		"https://Auth.Example.com/x":      "https://auth.example.com",
		"https://auth.example.com:443/x":  "https://auth.example.com",
		"https://auth.example.com:8443/x": "https://auth.example.com:8443",
		"http://auth.example.com:80/x":    "http://auth.example.com",
		"https://[::1]:8443/x":            "https://[::1]:8443",
	} {
		if got := requestOrigin(httptest.NewRequest("GET", target, nil)); got != want {
			t.Errorf("%s: %s", target, got)
		}
	}
}
