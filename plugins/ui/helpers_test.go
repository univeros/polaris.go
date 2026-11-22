package ui_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/plugins/ui"
	"github.com/univeros/polaris.go/polaristest"
)

const (
	origin   = "https://example.com"
	password = "correct horse battery staple"
)

// app is a host: Polaris with the pages, a protected /dashboard and a protected POST /notes.
type app struct {
	t   *testing.T
	srv *polaristest.Server
	web *ui.Plugin
	h   http.Handler
}

func newApp(t *testing.T, cfg ui.Config, opts ...polaristest.Option) *app {
	t.Helper()
	web := ui.New(cfg)
	srv := polaristest.New(t, append([]polaristest.Option{polaristest.WithPlugins(web)}, opts...)...)
	return mount(t, srv, web)
}

func mount(t *testing.T, srv *polaristest.Server, web *ui.Plugin) *app {
	whoami := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		_, _ = io.WriteString(w, "hello "+who.UserID)
	})
	mux := http.NewServeMux()
	mux.Handle("/", srv.Handler())
	mux.Handle("GET /dashboard", web.RequireSignIn(srv.Protect(whoami)))
	mux.Handle("POST /notes", web.RequireSignIn(srv.Protect(whoami)))
	return &app{t: t, srv: srv, web: web, h: mux}
}

// browser keeps cookies and the last CSRF token, like a browser without JavaScript.
type browser struct {
	a    *app
	jar  map[string]string
	csrf string
	last *httptest.ResponseRecorder
}

func (a *app) browser() *browser { return &browser{a: a, jar: map[string]string{}} }

var csrfField = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// do sends a request from origin (https), with the jar's cookies; mods adjust it.
func (b *browser) do(method, target string, form url.Values, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	b.a.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	if !strings.HasPrefix(target, "http") {
		target = origin + target
	}
	r := httptest.NewRequest(method, target, body)
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", origin)
	}
	for name, value := range b.jar {
		r.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	for _, m := range mods {
		m(r)
	}
	rec := httptest.NewRecorder()
	b.a.h.ServeHTTP(rec, r)
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.jar, c.Name)
		} else {
			b.jar[c.Name] = c.Value
		}
	}
	if m := csrfField.FindStringSubmatch(rec.Body.String()); m != nil {
		b.csrf = m[1]
	}
	b.last = rec
	return rec
}

func (b *browser) get(target string, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	return b.do(http.MethodGet, target, nil, mods...)
}

// post submits a form with the CSRF token of the last page, unless the form carries its own.
func (b *browser) post(target string, form url.Values, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	if !form.Has("csrf") {
		form.Set("csrf", b.csrf)
	}
	return b.do(http.MethodPost, target, form, mods...)
}

// follow GETs the Location of a redirect.
func (b *browser) follow(rec *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	b.a.t.Helper()
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
		b.a.t.Fatalf("want a redirect, got %d: %s", rec.Code, rec.Body)
	}
	return b.get(rec.Header().Get("Location"))
}

func (b *browser) signIn(email string) *httptest.ResponseRecorder {
	b.get("/auth/ui/sign-in")
	return b.post("/auth/ui/sign-in", url.Values{"email": {email}, "password": {password}})
}

// account registers and verifies email through the JSON routes.
func (a *app) account(email string) {
	a.t.Helper()
	a.json(http.MethodPost, "/auth/register", map[string]any{"email": email, "password": password}, "")
	for _, m := range a.srv.Mailer.Sent() {
		if m.To == email && m.Template == "verify_email" {
			a.json(http.MethodPost, "/auth/email/verify", map[string]any{"token": m.Data["token"]}, "")
		}
	}
}

// json calls a JSON route: status and body.
func (a *app) json(method, path string, body map[string]any, bearer string) (int, map[string]any) {
	a.t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, origin+path, strings.NewReader(string(raw)))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, r)
	out := map[string]any{}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// lastMail is the newest mail of template to email.
func (a *app) lastMail(email, template string) map[string]any {
	a.t.Helper()
	sent := a.srv.Mailer.Sent()
	for i := len(sent) - 1; i >= 0; i-- {
		if sent[i].To == email && sent[i].Template == template {
			return sent[i].Data
		}
	}
	a.t.Fatalf("no %s mail to %s", template, email)
	return nil
}

func expect(t *testing.T, rec *httptest.ResponseRecorder, status int, contains ...string) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status %d, want %d: %s", rec.Code, status, rec.Body)
	}
	for _, s := range contains {
		if !strings.Contains(rec.Body.String(), s) {
			t.Fatalf("body lacks %q:\n%s", s, rec.Body)
		}
	}
}

func location(t *testing.T, rec *httptest.ResponseRecorder, want string) {
	t.Helper()
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != want {
		t.Fatalf("got %d to %q, want 303 to %q: %s", rec.Code, rec.Header().Get("Location"), want, rec.Body)
	}
}
