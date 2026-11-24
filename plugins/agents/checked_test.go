package agents_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/agents"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
)

// noting is an agent v1.0.0 already had, one no host's JWT registered, granted a capability at the location
// that takes any arguments.
func noting(t *testing.T) (a *agentsCase, jwt func() string, session string) {
	t.Helper()
	p := agents.New(agents.Config{ApprovalURL: approveURL, Capabilities: []agents.Capability{
		{Name: "note", Description: "Take a note", Permission: "members.read", Risk: agents.RiskLow, Location: location}}})
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(oauth.Config{BaseURL: base}), p))
	a = &agentsCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), plugin: p, ctx: t.Context()}
	_, session = a.login("grace@example.com")
	_, session = a.organization(session, "Acme")
	key := newKey("ES256")
	agent := a.registerAgent(session, map[string]any{"name": "Noter", "auth": "private_key_jwt", "jwk": key.jwk(), "capabilities": []any{"note"}})
	a.equal(at(agent["grants"], 0)["status"], "active", "granted")
	return a, func() string { return key.requestJWT(str(agent["id"]), location, nil, nil) }, session
}

const aForm = "application/x-www-form-urlencoded"

// The constraints are checked on the JSON body, so nothing else of the request may say otherwise to the
// handler, whichever agent it is: FormValue reads a query, and a JSON text as a form when its type says so.
func TestWhatAnyAgentsHandlerReadsWasChecked(t *testing.T) {
	a, jwt, _ := noting(t)
	const bob, polyglot = `{"email":"bob@acme.test"}`, `{"email":"&email=mallory@evil.test&x="}`
	ran, read := 0, ""
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ran++
		read = fmt.Sprintf("%q %q %q %d %v", r.FormValue("email"), r.Header.Get("Content-Type"), r.Header.Get("Content-Encoding"), len(r.Trailer), r.GetBody == nil)
	})
	for name, guarded := range map[string]http.Handler{"Protect": a.plugin.Protect("note", handler), "Guard": a.plugin.Guard(handler)} {
		send := func(query, body string, types ...string) string {
			r := httptest.NewRequest(http.MethodPost, location+query, strings.NewReader(body))
			r.Header["Content-Type"] = types
			r.Header.Set("Content-Encoding", "gzip")
			r.Header.Set("Authorization", "Bearer "+jwt())
			r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(polyglot)), nil }
			r.Trailer = http.Header{"Email": {"mallory@evil.test"}}
			w := httptest.NewRecorder()
			guarded.ServeHTTP(w, r)
			return fmt.Sprint(w.Code, " ", problemOf(w)["error"])
		}
		for what, got := range map[string]string{
			"a query":               send("?email=mallory@evil.test", bob, "application/json"),
			"a query and no body":   send("?email=mallory@evil.test", "", "application/json"),
			"JSON as a form":        send("", polyglot, aForm),
			"JSON as text":          send("", bob, "text/plain"),
			"JSON as two types":     send("", polyglot, "application/json", aForm),
			"JSON as a broken type": send("", bob, "application/json; charset"),
			"JSON in UTF-7":         send("", bob, "application/json; charset=utf-7"),
			"JSON in UTF-16":        send("", bob, "application/json; charset*=utf-16''x"), // RFC 2231: no parameter to Go
			"bytes not UTF-8":       send("", "{\"email\":\"bob@acme.test\xff\"}", "application/json"),
			"JSON as an empty type": send("", bob, ""),
			"a form as nothing":     send("", "email=mallory@evil.test"),
			"a form":                send("", "email=mallory@evil.test", aForm),
			"a form as JSON":        send("", "email=mallory@evil.test", "application/json"),
			"XML":                   send("", "<email>mallory@evil.test</email>", "application/xml"),
			"an array":              send("", `[{"email":"mallory@evil.test"}]`, "application/json"),
			"null":                  send("", `null`, "application/json"),
			"a byte order mark":     send("", "\xef\xbb\xbf"+bob, "application/json"),
		} {
			a.equal(got, "422 agents_invalid_arguments", name+": "+what)
		}
		a.equal(ran, 0, name+": nothing ran")
		for _, media := range []string{"application/json", "application/json; charset=UTF-8", "Application/JSON", "application/vnd.acme+json"} {
			a.equal(send("", bob, media), "200 <nil>", name+": "+media)
			a.equal(read, fmt.Sprintf(`"" %q "" 0 true`, media), name+": what the handler reads")
		}
		a.equal(send("", polyglot), "200 <nil>", name+": no type, as v1.0.0 clients may send it")
		a.equal(read, `"" "application/json" "" 0 true`, name+": the handler is told what was checked")
		a.equal([]any{send("", ""), send("", " \n", "text/plain")}, []any{"200 <nil>", "200 <nil>"}, name+": no body")
		a.equal(read, `"" "text/plain" "" 0 true`, name+": and is told nothing new of no body")
		a.equal(ran, 7, name+": ran")
		ran = 0
	}
	a.equal(len(a.audited(agents.EventExecutionDenied)), 34, "refusals are audited")
}

// An agent's access token is held to it as its JWT is.
func TestWhatAnAccessTokensHandlerReadsWasChecked(t *testing.T) {
	a, _, session := noting(t)
	agent := a.registerAgent(session, map[string]any{"name": "Helper", "auth": "delegated_token", "capabilities": []any{"note"}})
	minted := a.exchangeFor(str(agent["id"]), session)
	a.status(minted, 200, "exchange")
	token := str(a.json(minted)["access_token"])
	ran := 0
	guarded := a.plugin.Protect("note", http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran++ }))
	send := func(query, media string) int {
		r := httptest.NewRequest(http.MethodPost, location+query, strings.NewReader(`{"email":"bob@acme.test"}`))
		r.Header.Set("Content-Type", media)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)
		return w.Code
	}
	a.equal([]any{send("?email=mallory@evil.test", "application/json"), send("", aForm), ran}, []any{422, 422, 0}, "refused")
	a.equal([]any{send("", "application/json"), ran}, []any{200, 1}, "served")
}

// Nor is a form that something before Protect parsed, which left no body to check.
func TestAFormParsedBeforeProtectIsNotRead(t *testing.T) {
	a, jwt, _ := noting(t)
	read := "not called"
	guarded := a.plugin.Protect("note", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		read = fmt.Sprintf("%v %v %v", r.Form["email"], r.PostForm["email"], r.MultipartForm)
	}))
	multipart := "--b\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\nmallory@evil.test\r\n--b--\r\n"
	for media, body := range map[string]string{aForm: "email=mallory@evil.test", "multipart/form-data; boundary=b": multipart} {
		r := httptest.NewRequest(http.MethodPost, location, strings.NewReader(body))
		r.Header.Set("Content-Type", media)
		r.Header.Set("Authorization", "Bearer "+jwt())
		if r.FormValue("email") != "mallory@evil.test" {
			t.Fatal("not parsed")
		}
		w := httptest.NewRecorder()
		guarded.ServeHTTP(w, r)
		a.equal([]any{w.Code, read}, []any{200, "[] [] <nil>"}, media)
	}
}

// The path is the route's, and what it names stays readable: only a query, a form and a body that is no JSON
// object are not.
func TestAGuardedRouteKeepsItsPathValues(t *testing.T) {
	a, jwt, _ := noting(t)
	read := ""
	mux := http.NewServeMux()
	mux.Handle("POST /{name}", a.plugin.Protect("note", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		read = r.PathValue("name") + r.Pattern + r.Header.Get("Content-Type")
	})))
	r := httptest.NewRequest(http.MethodPost, location, nil)
	r.Header.Set("Authorization", "Bearer "+jwt())
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	a.equal([]any{w.Code, read}, []any{200, "invitePOST /{name}"}, "path")
}

// The v1.0.0 routes agents call have a counter of their own, so agents do not spend the budget people at the
// same address refresh their sessions with; it is as large as that one, and answers the same headers.
func TestPolarisAgentRoutesDoNotSpendTheRefreshBudget(t *testing.T) {
	a := unrecorded(t).agentsCase
	calls := []func() *http.Response{
		func() *http.Response { return a.c.Get("/agents/session") },
		func() *http.Response { return a.c.Post("/agents/execute", nil) },
		func() *http.Response { return a.c.Post("/agents/enroll", nil) },
		func() *http.Response { return a.c.Post("/agents/grants/request", nil) },
	}
	for i := range 60 {
		resp := calls[i%len(calls)]()
		a.equal([]any{resp.StatusCode != 429, resp.Header.Get("X-RateLimit-Limit"), resp.Header.Get("X-RateLimit-Remaining")}, []any{true, "60", fmt.Sprint(59 - i)}, fmt.Sprint(i))
	}
	for _, call := range calls {
		a.equal(call().StatusCode, 429, "they share one")
	}
	resp := a.c.Post("/auth/token/refresh", map[string]any{"refresh_token": strings.Repeat("x", 43)})
	a.equal([]any{resp.StatusCode != 429, resp.Header.Get("X-RateLimit-Remaining")}, []any{true, "59"}, "a refresh has its own")
}
