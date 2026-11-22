package ui_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/plugins/ui"
)

const public = "https://app.example.com"

// TestBehindATLSTerminatingProxy runs the whole journey as most deployments see it: r.TLS nil, an
// internal Host, the browser's Origin the configured public origin.
func TestBehindATLSTerminatingProxy(t *testing.T) {
	for _, host := range []string{"10.0.0.5:8080", "web:8080"} {
		t.Run(host, func(t *testing.T) {
			a := newApp(t, ui.Config{BaseURL: public, AfterSignIn: "/dashboard"})
			b := a.proxied(host)

			b.get("/auth/ui/sign-up")
			location(t, b.post("/auth/ui/sign-up", url.Values{"email": {"ada@example.com"}, "password": {password}}), "/auth/ui/check-email")
			token, _ := a.lastMail("ada@example.com", "verify_email")["token"].(string)
			link := a.web.VerifyEmailURL(token)
			if !strings.HasPrefix(link, public+"/auth/ui/verify?token=") {
				t.Fatalf("the email link follows the connection: %q", link)
			}
			u, _ := url.Parse(link)
			expect(t, b.get(u.RequestURI()), 200, "Email verified")

			location(t, b.signIn("ada@example.com"), "/dashboard")
			user, _ := a.srv.Users().ByEmail(t.Context(), "ada@example.com")
			expect(t, b.get("/dashboard"), 200, "hello "+user.ID)
			expect(t, b.do(http.MethodPost, "/notes", url.Values{}), 200, "hello "+user.ID)

			b.get("/auth/ui/sign-out")
			location(t, b.post("/auth/ui/sign-out", url.Values{}), "/auth/ui/sign-in")
			location(t, b.get("/dashboard"), "/auth/ui/refresh?return_to=%2Fdashboard")
		})
	}
}

// TestOriginIsTheConfiguredOne: the same-origin check compares the browser's Origin with
// Config.BaseURL's origin, never with one built from the Host header.
func TestOriginIsTheConfiguredOne(t *testing.T) {
	a := newApp(t, ui.Config{BaseURL: public})
	a.account("ada@example.com")
	creds := func() url.Values { return url.Values{"email": {"ada@example.com"}, "password": {password}} }

	cross := a.proxied("web:8080")
	cross.get("/auth/ui/sign-in")
	cross.from = "https://evil.example"
	expect(t, cross.post("/auth/ui/sign-in", creds()), 403, "This form only works at https://app.example.com")

	// A forged Host matching a cross-site Origin does not make it same-origin, with or without TLS.
	for _, base := range []string{"https://evil.example", "http://evil.example"} {
		forged := a.browser()
		forged.url, forged.from = base, base
		forged.get("/auth/ui/sign-in")
		expect(t, forged.post("/auth/ui/sign-in", creds()), 403)
		if _, ok := forged.jar["__Host-polaris_session"]; ok {
			t.Fatalf("%s: a session for a forged Host", base)
		}
	}

	// Another name for the same service: the pages are served on the configured origin only.
	other := a.browser()
	other.url, other.from = "https://www.app.example.com", "https://www.app.example.com"
	other.get("/auth/ui/sign-in")
	expect(t, other.post("/auth/ui/sign-in", creds()), 403, `href="https://app.example.com/auth/ui/sign-in"`)

	// The session cookie on a host route follows the same rule.
	b := a.proxied("web:8080")
	location(t, b.signIn("ada@example.com"), "/")
	b.from = "https://evil.example"
	expect(t, b.do(http.MethodPost, "/notes", url.Values{}), 401)
	b.from = public
	expect(t, b.do(http.MethodPost, "/notes", url.Values{}), 200)

	// return_to may name the configured origin, not the Host's.
	b.get("/auth/ui/sign-in")
	for target, want := range map[string]string{public + "/x": public + "/x", "http://web:8080/x": "/"} {
		rec := b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {password}, "return_to": {target}})
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("return_to %q: %q, want %q", target, got, want)
		}
	}
}

// TestSessionsNeedAnHTTPSOrigin: an https origin issues sessions whatever the connection; a
// loopback http origin too (development); any other http origin never.
func TestSessionsNeedAnHTTPSOrigin(t *testing.T) {
	for base, ok := range map[string]bool{"https://app.example.com": true, "http://localhost:8080": true, "http://127.0.0.1:8080": true, "http://app.example.com": false} {
		a := newApp(t, ui.Config{BaseURL: base})
		a.account("ada@example.com")
		b := a.browser()
		b.url, b.from = base, base
		rec := b.signIn("ada@example.com")
		if got := rec.Code == http.StatusSeeOther; got != ok {
			t.Errorf("%s: signed in %v, want %v: %d %s", base, got, ok, rec.Code, rec.Body)
		}
		if !ok && !strings.Contains(rec.Body.String(), "needs a secure (HTTPS) connection") {
			t.Errorf("%s: %s", base, rec.Body)
		}
	}
}
