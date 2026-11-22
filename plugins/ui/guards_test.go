package ui_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/sentinel"
	"github.com/univeros/polaris.go/plugins/ui"
	"github.com/univeros/polaris.go/polaristest"
)

// TestRateLimitsAreTheRoutes shows the pages spend the JSON route's budget: one bucket per client
// for /auth/login, whichever way the attempt came in.
func TestRateLimitsAreTheRoutes(t *testing.T) {
	a := newApp(t, ui.Config{}, polaristest.WithAuth(func(c *config.Auth) { c.RateLimits.Login.Limit = 2 }))
	a.account("ada@example.com")
	if status, _ := a.json(http.MethodPost, "/auth/login", map[string]any{"email": "ada@example.com", "password": "wrong"}, ""); status != 401 {
		t.Fatalf("JSON login: %d", status)
	}
	b := a.browser()
	b.get("/auth/ui/sign-in")
	expect(t, b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {"wrong"}}), 401)
	limited := b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {password}})
	expect(t, limited, 429, "Too many attempts. Wait ")
	if status, _ := a.json(http.MethodPost, "/auth/login", map[string]any{"email": "ada@example.com", "password": password}, ""); status != 429 {
		t.Fatalf("the JSON route kept its budget after the pages spent it: %d", status)
	}
}

// blockEmail is a sentinel signal that blocks one address.
type blockEmail string

func (blockEmail) Name() string { return "block_email" }

func (s blockEmail) Evaluate(_ context.Context, a sentinel.Attempt) (sentinel.Verdict, error) {
	if a.Email == string(s) {
		return sentinel.Verdict{Signal: "block_email", Score: 100, Reasons: []string{"blocked in the test"}}, nil
	}
	return sentinel.Verdict{Signal: "block_email"}, nil
}

// TestSentinelJudgesThePages runs sentinel's middleware on the pages' sign-in and sign-up.
func TestSentinelJudgesThePages(t *testing.T) {
	web := ui.New(ui.Config{BaseURL: origin})
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}), web, sentinel.New(sentinel.Config{
		Mode: sentinel.Enforce, NoBuiltIn: true, Signals: []sentinel.Signal{blockEmail("mallory@example.com")},
	})))
	a := mount(t, srv, web)
	a.account("mallory@example.com")
	b := a.browser()
	expect(t, b.signIn("mallory@example.com"), 403, "The request was refused.")
	expect(t, b.post("/auth/ui/sign-up", url.Values{"email": {"mallory@example.com"}, "password": {password}}), 403, "The request was refused.")
	a.account("ada@example.com")
	location(t, b.signIn("ada@example.com"), "/")
	if _, ok := b.jar[sentinel.DeviceCookie]; !ok {
		t.Error("sentinel's device cookie does not reach the browser")
	}
}

// TestSessionCookieOnHostRoutes: the cookie authenticates a safe request, and a state-changing one
// only from this origin; an Authorization header wins over it.
func TestSessionCookieOnHostRoutes(t *testing.T) {
	a := newApp(t, ui.Config{})
	a.account("ada@example.com")
	a.account("grace@example.com")
	b := a.browser()
	location(t, b.signIn("ada@example.com"), "/")
	ada, _ := a.srv.Users().ByEmail(t.Context(), "ada@example.com")

	expect(t, b.do(http.MethodPost, "/notes", url.Values{}), 200, "hello "+ada.ID)
	crossSite := b.do(http.MethodPost, "/notes", url.Values{}, func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") })
	expect(t, crossSite, 401)
	noOrigin := b.do(http.MethodPost, "/notes", url.Values{}, func(r *http.Request) { r.Header.Del("Origin") })
	expect(t, noOrigin, 401)
	if loc := crossSite.Header().Get("Location"); loc != "" {
		t.Errorf("a refused POST is redirected to %q", loc)
	}

	_, login := a.json(http.MethodPost, "/auth/login", map[string]any{"email": "grace@example.com", "password": password}, "")
	grace, _ := login["data"].(map[string]any)["access_token"].(string)
	asGrace := b.get("/dashboard", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+grace) })
	if strings.Contains(asGrace.Body.String(), ada.ID) {
		t.Error("the cookie won over an Authorization header")
	}
	b.jar["__Host-polaris_session"] = "not-a-jwt"
	location(t, b.get("/dashboard"), "/auth/ui/refresh?return_to=%2Fdashboard")
}
