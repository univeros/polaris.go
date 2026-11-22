package ui_test

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/plugins/ui"
	"github.com/univeros/polaris.go/polaristest"
)

// TestHappyPath is the whole journey of a browser without JavaScript: sign up, verify through the
// emailed token, sign in, use a protected route with the cookie, sign out.
func TestHappyPath(t *testing.T) {
	a := newApp(t, ui.Config{AppName: "Acme", AfterSignIn: "/dashboard"})
	b := a.browser()

	expect(t, b.get("/auth/ui/sign-up"), 200, "Create your account", `autocomplete="new-password"`)
	rec := b.post("/auth/ui/sign-up", url.Values{"email": {"ada@example.com"}, "password": {password}})
	location(t, rec, "/auth/ui/check-email")
	expect(t, b.follow(rec), 200, "Check your email")

	token, _ := a.lastMail("ada@example.com", "verify_email")["token"].(string)
	link := a.web.VerifyEmailURL(token)
	if !strings.HasPrefix(link, origin+"/auth/ui/verify?token=") {
		t.Fatalf("verify link %q", link)
	}
	u, _ := url.Parse(link)
	expect(t, b.get(u.RequestURI()), 200, "Confirm that this email address is yours")
	expect(t, b.post("/auth/ui/verify", url.Values{"token": {token}}), 200, "Email verified")

	location(t, b.signIn("ada@example.com"), "/dashboard")
	if b.jar["__Host-polaris_session"] == "" || b.jar["__Secure-polaris_ui_refresh"] == "" {
		t.Fatalf("session cookies: %v", b.jar)
	}
	user, _ := a.srv.Users().ByEmail(t.Context(), "ada@example.com")
	expect(t, b.get("/dashboard"), 200, "hello "+user.ID)
	status, me := a.json(http.MethodGet, "/auth/me", nil, "")
	if status != 401 {
		t.Fatalf("no cookie, /auth/me: %d %v", status, me)
	}
	expect(t, b.get("/auth/me"), 200, "ada@example.com") // a bearer route takes the cookie too

	refresh := b.jar["__Secure-polaris_ui_refresh"]
	expect(t, b.get("/auth/ui/sign-out"), 200, "Sign out of this browser?")
	location(t, b.post("/auth/ui/sign-out", url.Values{}), "/auth/ui/sign-in")
	if len(b.jar) != 1 { // only the CSRF cookie is left
		t.Fatalf("cookies after sign-out: %v", b.jar)
	}
	if status, _ := a.json(http.MethodPost, "/auth/token/refresh", map[string]any{"refresh_token": refresh}, ""); status != 401 {
		t.Fatalf("the session survived sign-out: refresh %d", status)
	}
	rec = b.get("/dashboard")
	location(t, rec, "/auth/ui/refresh?return_to=%2Fdashboard")
	location(t, b.follow(rec), "/auth/ui/sign-in?return_to=%2Fdashboard")
}

func TestRefreshRenewsAnExpiredSession(t *testing.T) {
	a := newApp(t, ui.Config{})
	a.account("ada@example.com")
	b := a.browser()
	location(t, b.signIn("ada@example.com"), "/")
	delete(b.jar, "__Host-polaris_session") // the access cookie expired
	rec := b.get("/dashboard?tab=1")
	location(t, rec, "/auth/ui/refresh?return_to=%2Fdashboard%3Ftab%3D1")
	location(t, b.follow(rec), "/dashboard?tab=1")
	expect(t, b.get("/dashboard?tab=1"), 200, "hello ")

	b.jar["__Secure-polaris_ui_refresh"] = "spent"
	delete(b.jar, "__Host-polaris_session")
	location(t, b.get("/auth/ui/refresh?return_to=/dashboard"), "/auth/ui/sign-in?return_to=%2Fdashboard")
	if _, ok := b.jar["__Secure-polaris_ui_refresh"]; ok {
		t.Fatal("a refused refresh cookie is kept")
	}
}

func TestSignInRefusals(t *testing.T) {
	a := newApp(t, ui.Config{}, polaristest.WithAuth(func(c *config.Auth) { c.Lockout.MaxAttempts = 2 }))
	a.account("ada@example.com")
	b := a.browser()
	b.get("/auth/ui/sign-in")

	wrong := b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {"wrong"}})
	unknown := b.post("/auth/ui/sign-in", url.Values{"email": {"nobody@example.com"}, "password": {"wrong"}})
	expect(t, wrong, 401, "Incorrect email or password.", `role="alert"`, `value="ada@example.com"`)
	expect(t, unknown, 401, "Incorrect email or password.")
	b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {"wrong"}})
	locked := b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {password}})
	expect(t, locked, 401, "Incorrect email or password.") // a locked account reads as bad credentials
	if _, ok := b.jar["__Host-polaris_session"]; ok {
		t.Fatal("a locked account got a session")
	}

	expect(t, b.post("/auth/ui/sign-in", url.Values{"email": {""}, "password": {""}}), 422, "An email and password are required.")
	insecure := b.post("http://example.com/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {password}},
		func(r *http.Request) { r.Header.Set("Origin", "http://example.com") })
	expect(t, insecure, 403, "This form only works at https://example.com") // plaintext is another origin
}

func TestUnverifiedEmailAndDisabledAccount(t *testing.T) {
	a := newApp(t, ui.Config{}, polaristest.WithAuth(func(c *config.Auth) { c.Flows.RequireVerifiedEmail = true }))
	a.json(http.MethodPost, "/auth/register", map[string]any{"email": "ada@example.com", "password": password}, "")
	expect(t, a.browser().signIn("ada@example.com"), 403, "Verify your email address before signing in.")

	a.account("grace@example.com")
	user, _ := a.srv.Users().ByEmail(t.Context(), "grace@example.com")
	if err := a.srv.Users().Disable(t.Context(), user.ID); err != nil {
		t.Fatal(err)
	}
	expect(t, a.browser().signIn("grace@example.com"), 403, "This account is disabled.")
}

func TestCSRF(t *testing.T) {
	a := newApp(t, ui.Config{})
	a.account("ada@example.com")
	creds := func() url.Values { return url.Values{"email": {"ada@example.com"}, "password": {password}} }

	b := a.browser()
	expect(t, b.post("/auth/ui/sign-in", creds()), 403, "This form expired") // no CSRF cookie yet
	b.get("/auth/ui/sign-in")
	bad := creds()
	bad.Set("csrf", strings.Repeat("0", 64))
	expect(t, b.post("/auth/ui/sign-in", bad), 403, "This form expired")
	missing := creds()
	missing.Set("csrf", "")
	expect(t, b.post("/auth/ui/sign-in", missing), 403)
	expect(t, b.post("/auth/ui/sign-in", creds(), func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }), 403)
	expect(t, b.post("/auth/ui/sign-in", creds(), func(r *http.Request) {
		r.Header.Del("Origin")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	}), 403)

	other := a.browser() // a token from another browser does not fit this one's cookie
	other.get("/auth/ui/sign-in")
	stolen := creds()
	stolen.Set("csrf", other.csrf)
	expect(t, b.post("/auth/ui/sign-in", stolen), 403)

	location(t, b.post("/auth/ui/sign-in", creds()), "/")
}

func TestOpenRedirectsAreRefused(t *testing.T) {
	a := newApp(t, ui.Config{AfterSignIn: "/home", RedirectOrigins: []string{"https://app.example.com"}},
		polaristest.WithAuth(func(c *config.Auth) { c.RateLimits.Login.Limit = 100 })) // one sign-in per case
	a.account("ada@example.com")
	for target, want := range map[string]string{
		"/settings?tab=1":                       "/settings?tab=1",
		"https://example.com/x":                 "https://example.com/x",
		"https://app.example.com/welcome":       "https://app.example.com/welcome",
		"//evil.example/":                       "/home",
		"/\\evil.example":                       "/home",
		"https://evil.example/":                 "/home",
		"https://app.example.com@evil.example/": "/home",
		"javascript:alert(1)":                   "/home",
		"http://example.com/downgrade":          "/home",
		"/\t/evil.example":                      "/home",
		"settings":                              "/home",
	} {
		b := a.browser()
		b.get("/auth/ui/sign-in?return_to=" + url.QueryEscape(target))
		rec := b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {password}, "return_to": {target}})
		if got := rec.Header().Get("Location"); got != want {
			t.Errorf("return_to %q: redirected to %q, want %q", target, got, want)
		}
	}
	b := a.browser()
	page := b.get("/auth/ui/sign-in?return_to=" + url.QueryEscape("//evil.example"))
	if strings.Contains(page.Body.String(), "evil.example") {
		t.Error("a refused return_to is echoed into the form")
	}
}

func TestEnumerationSafeAnswers(t *testing.T) {
	a := newApp(t, ui.Config{})
	a.account("ada@example.com")
	b := a.browser()
	b.get("/auth/ui/forgot")
	known := b.post("/auth/ui/forgot", url.Values{"email": {"ada@example.com"}}).Body.String()
	unknown := b.post("/auth/ui/forgot", url.Values{"email": {"nobody@example.com"}}).Body.String()
	if known != unknown || !strings.Contains(known, "If an account exists") {
		t.Fatalf("forgot answers differ:\n%s\n%s", known, unknown)
	}
	taken := b.post("/auth/ui/sign-up", url.Values{"email": {"ada@example.com"}, "password": {password}})
	free := b.post("/auth/ui/sign-up", url.Values{"email": {"new@example.com"}, "password": {password}})
	if taken.Code != free.Code || taken.Header().Get("Location") != free.Header().Get("Location") {
		t.Fatalf("sign-up answers differ: %d %q / %d %q", taken.Code, taken.Header().Get("Location"), free.Code, free.Header().Get("Location"))
	}
	b.get("/auth/ui/check-email")
	expect(t, b.post("/auth/ui/check-email", url.Values{"email": {"nobody@example.com"}}), 202, "If the address is registered")
	expect(t, b.post("/auth/ui/sign-up", url.Values{"email": {"short@example.com"}, "password": {"short"}}), 422, `role="alert"`)
}

// A mail scanner follows the links of a message with GET: opening the verification link verifies
// nothing. The page it answers posts the token back when the person presses its button.
func TestOpeningTheVerificationLinkVerifiesNothing(t *testing.T) {
	a := newApp(t, ui.Config{})
	a.json(http.MethodPost, "/auth/register", map[string]any{"email": "ada@example.com", "password": password}, "")
	token, _ := a.lastMail("ada@example.com", "verify_email")["token"].(string)
	link, _ := url.Parse(a.web.VerifyEmailURL(token))
	verified := func() bool {
		u, err := a.srv.Graph().Repos().Users.ByEmail(t.Context(), "ada@example.com")
		if err != nil {
			t.Fatal(err)
		}
		return u.EmailVerifiedAt != nil
	}

	scanner := a.browser()
	for range 2 {
		rec := scanner.get(link.RequestURI())
		expect(t, rec, 200, `method="post"`, `name="csrf"`, `type="hidden" name="token" value="`+token+`"`)
		if strings.Contains(rec.Body.String(), "Email verified") {
			t.Fatal("the GET verified the address")
		}
	}
	if verified() {
		t.Fatal("opening the link verified the account")
	}
	// A post without the page's CSRF cookie and token (a form replayed blind) is refused.
	if rec := a.browser().post("/auth/ui/verify", url.Values{"token": {token}, "csrf": {"forged"}}); rec.Code == 200 || verified() {
		t.Fatalf("a post without the CSRF token verified: %d", rec.Code)
	}

	b := a.browser()
	b.get(link.RequestURI())
	expect(t, b.post("/auth/ui/verify", url.Values{"token": {token}}), 200, "Email verified")
	if !verified() {
		t.Fatal("pressing the button verifies")
	}
}

func TestVerifyAndResetPassword(t *testing.T) {
	a := newApp(t, ui.Config{})
	b := a.browser()
	expect(t, b.get("/auth/ui/verify?token=forged"), 200, `name="token" value="forged"`)
	expect(t, b.post("/auth/ui/verify", url.Values{"token": {"forged"}}), 400, "invalid or has expired")
	expect(t, b.get("/auth/ui/verify"), 200, `name="token"`)
	a.json(http.MethodPost, "/auth/register", map[string]any{"email": "ada@example.com", "password": password}, "")
	token, _ := a.lastMail("ada@example.com", "verify_email")["token"].(string)
	expect(t, b.post("/auth/ui/verify", url.Values{"token": {token}}), 200, "Email verified")

	location(t, b.signIn("ada@example.com"), "/")
	b.get("/auth/ui/forgot")
	b.post("/auth/ui/forgot", url.Values{"email": {"ada@example.com"}})
	reset, _ := a.lastMail("ada@example.com", "password_reset")["token"].(string)
	u, _ := url.Parse(a.web.ResetPasswordURL(reset))
	expect(t, b.get(u.RequestURI()), 200, `type="hidden" name="token"`)
	if a.srv.Graph() == nil || b.last.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("a page with a reset token in its URL leaks the referrer")
	}
	expect(t, b.post("/auth/ui/reset", url.Values{"token": {reset}, "new_password": {"short"}}), 422, `role="alert"`)
	expect(t, b.post("/auth/ui/reset", url.Values{"token": {"expired-or-forged"}, "new_password": {"another long passphrase"}}), 401, "invalid or has expired")
	expect(t, b.post("/auth/ui/reset", url.Values{"token": {reset}, "new_password": {"another long passphrase"}}), 200, "Password changed")
	if _, ok := b.jar["__Host-polaris_session"]; ok {
		t.Fatal("the session cookie outlives the reset")
	}
	expect(t, b.post("/auth/ui/reset", url.Values{"token": {reset}, "new_password": {"yet another passphrase"}}), 401, "invalid or has expired")
	b.get("/auth/ui/sign-in")
	location(t, b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {"another long passphrase"}}), "/")
}

func TestMFAChallenge(t *testing.T) {
	a := newApp(t, ui.Config{})
	a.account("ada@example.com")
	_, login := a.json(http.MethodPost, "/auth/login", map[string]any{"email": "ada@example.com", "password": password}, "")
	access, _ := login["data"].(map[string]any)["access_token"].(string)
	_, enrolled := a.json(http.MethodPost, "/auth/mfa/email/enroll", map[string]any{}, access)
	factorID, _ := enrolled["data"].(map[string]any)["factor_id"].(string)
	code, _ := a.lastMail("ada@example.com", "otp_code")["code"].(string)
	if status, body := a.json(http.MethodPost, "/auth/mfa/email/confirm", map[string]any{"factor_id": factorID, "code": code}, access); status != 200 {
		t.Fatalf("confirm: %d %v", status, body)
	}

	b := a.browser()
	expect(t, b.get("/auth/ui/mfa"), 303) // no sign-in under way
	b.get("/auth/ui/sign-in?return_to=/dashboard")
	rec := b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {password}, "return_to": {"/dashboard"}})
	location(t, rec, "/auth/ui/mfa")
	if _, ok := b.jar["__Host-polaris_session"]; ok {
		t.Fatal("a session before the second factor")
	}
	expect(t, b.follow(rec), 200, "Two-step verification", `value="`+factorID+`" checked`, `autocomplete="one-time-code"`)

	expect(t, b.post("/auth/ui/mfa", url.Values{"factor_id": {factorID}, "action": {"send"}}), 200, "A code is on its way")
	expect(t, b.post("/auth/ui/mfa", url.Values{"factor_id": {factorID}, "code": {"000000"}}), 422, "That code is not correct")
	code, _ = a.lastMail("ada@example.com", "otp_code")["code"].(string)
	location(t, b.post("/auth/ui/mfa", url.Values{"factor_id": {factorID}, "code": {code}}), "/dashboard")
	expect(t, b.get("/dashboard"), 200, "hello ")
	if _, ok := b.jar["__Secure-polaris_ui_mfa"]; ok {
		t.Fatal("the MFA ticket outlives the sign-in")
	}

	late := a.browser()
	late.get("/auth/ui/sign-in")
	late.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {password}})
	late.jar["__Secure-polaris_ui_mfa"] = "eyJ0IjoiZm9yZ2VkIn0" // {"t":"forged"}: not a ticket
	expect(t, late.post("/auth/ui/mfa", url.Values{"factor_id": {factorID}, "code": {"123456"}}), 401, "took too long")
}

func TestSecurityHeadersOnEveryPage(t *testing.T) {
	a := newApp(t, ui.Config{LogoURL: "https://cdn.example.net/logo.svg"})
	for _, path := range []string{"/auth/ui/sign-in", "/auth/ui/sign-up", "/auth/ui/check-email", "/auth/ui/verify", "/auth/ui/forgot",
		"/auth/ui/reset?token=x", "/auth/ui/sign-out", "/auth/ui/style.css", "/auth/ui/nowhere", "/auth/ui/consent"} {
		rec := a.browser().get(path)
		h := rec.Header()
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"default-src 'none'", "style-src 'self'", "img-src 'self' https://cdn.example.net", "form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s: CSP %q lacks %q", path, csp, want)
			}
		}
		if strings.Contains(csp, "unsafe") || h.Get("Cache-Control") != "no-store" || h.Get("X-Frame-Options") != "DENY" ||
			h.Get("Referrer-Policy") != "no-referrer" || h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: headers %v", path, h)
		}
	}
	location(t, a.browser().get("/auth/ui"), "/auth/ui/sign-in")
	expect(t, a.browser().get("/auth/ui/nowhere"), 404, "Page not found")
}

var (
	inputID  = regexp.MustCompile(`<input id="([^"]+)"`)
	inlineJS = regexp.MustCompile(`(?i)<script|\son[a-z]+=|style=`)
)

// TestPagesAreAccessibleAndEscaped checks every rendered page: a language, a label for every
// field, no script or inline style, and user input escaped.
func TestPagesAreAccessibleAndEscaped(t *testing.T) {
	a := newApp(t, ui.Config{})
	for _, path := range []string{"/auth/ui/sign-in", "/auth/ui/sign-up", "/auth/ui/check-email", "/auth/ui/verify",
		"/auth/ui/forgot", "/auth/ui/reset", "/auth/ui/sign-out"} {
		body := a.browser().get(path).Body.String()
		if !strings.HasPrefix(body, "<!doctype html>") || !strings.Contains(body, `<html lang="en">`) || inlineJS.MatchString(body) {
			t.Errorf("%s: not a script-free document:\n%s", path, body)
		}
		for _, m := range inputID.FindAllStringSubmatch(body, -1) {
			if !strings.Contains(body, `<label for="`+m[1]+`">`) {
				t.Errorf("%s: input %s has no label", path, m[1])
			}
		}
	}
	b := a.browser()
	b.get("/auth/ui/sign-in")
	evil := `<script>alert(1)</script>"@example.com`
	rec := b.post("/auth/ui/sign-in", url.Values{"email": {evil}, "password": {"x"}, "return_to": {`/"><script>alert(2)</script>`}})
	if body := rec.Body.String(); strings.Contains(body, "<script") || !strings.Contains(body, "&lt;script&gt;alert(1)&lt;/script&gt;&#34;@example.com") {
		t.Fatalf("unescaped input:\n%s", body)
	}
}

func TestThemingAndMessages(t *testing.T) {
	a := newApp(t, ui.Config{
		AppName: "Acme <Inc>", PrimaryColor: "#123456", TermsURL: "https://example.com/terms",
		Messages: map[string]map[string]string{"pt": {"sign_in_title": "Entrar"}},
	})
	page := a.browser().get("/auth/ui/sign-in", func(r *http.Request) { r.Header.Set("Accept-Language", "pt-BR,pt;q=0.9,en;q=0.8") })
	expect(t, page, 200, `<html lang="pt">`, "<h1>Entrar</h1>", "Acme &lt;Inc&gt;", `href="https://example.com/terms"`, "Forgot your password?")
	expect(t, a.browser().get("/auth/ui/sign-in", func(r *http.Request) { r.Header.Set("Accept-Language", "de, pt;q=0") }), 200, "<h1>Sign in</h1>")
	css := a.browser().get("/auth/ui/style.css")
	if css.Header().Get("Content-Type") != "text/css; charset=utf-8" || !strings.Contains(css.Body.String(), "--accent: #123456") {
		t.Fatalf("stylesheet: %s", css.Body)
	}
}

func TestBadConfigurationFailsAtStartup(t *testing.T) {
	for name, cfg := range map[string]ui.Config{
		"colour":         {PrimaryColor: "red; background: url(x)"},
		"after sign-in":  {AfterSignIn: "https://evil.example/"},
		"after sign-out": {AfterSignOut: "//evil.example"},
		"origin":         {RedirectOrigins: []string{"https://app.example.com/path"}},
		"logo":           {LogoURL: "http://cdn.example.net/logo.png"},
		"terms":          {TermsURL: "javascript:alert(1)"},
		"base URL":       {BaseURL: "app.example.com"},
		"template":       {Templates: fstest.MapFS{"sign-in.html": {Data: []byte(`{{define "content"}}{{.Nope}`)}}},
	} {
		srv := polaristest.New(t)
		c := srv.Graph().Config()
		c.Plugins = []polaris.Plugin{ui.New(cfg)}
		if _, err := polaris.New(c); err == nil || !strings.Contains(err.Error(), "ui: ") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTemplatesOverrideByFileName(t *testing.T) {
	a := newApp(t, ui.Config{Templates: fstest.MapFS{
		"sign-in.html": {Data: []byte(`{{define "content"}}<p class="mine">{{.T.sign_in}} {{.Email}}</p>{{end}}`)},
		"style.css":    {Data: []byte("body { color: rebeccapurple; }\n")},
	}})
	expect(t, a.browser().get("/auth/ui/sign-in"), 200, `<p class="mine">Sign in </p>`, "<h1>Sign in</h1>")
	expect(t, a.browser().get("/auth/ui/forgot"), 200, `name="email"`) // the built-in page
	expect(t, a.browser().get("/auth/ui/style.css"), 200, "rebeccapurple")

	broken := newApp(t, ui.Config{Templates: fstest.MapFS{"forgot.html": {Data: []byte(`{{define "content"}}{{.Email.Nope}}{{end}}`)}}})
	expect(t, broken.browser().get("/auth/ui/forgot"), 500, "could not be rendered")
}

func TestSignOutWithAnExpiredAccessCookie(t *testing.T) {
	a := newApp(t, ui.Config{AfterSignOut: "/goodbye"})
	a.account("ada@example.com")
	b := a.browser()
	location(t, b.signIn("ada@example.com"), "/")
	refresh := b.jar["__Secure-polaris_ui_refresh"]
	delete(b.jar, "__Host-polaris_session")
	b.get("/auth/ui/sign-out")
	location(t, b.post("/auth/ui/sign-out", url.Values{}), "/goodbye")
	if status, _ := a.json(http.MethodPost, "/auth/token/refresh", map[string]any{"refresh_token": refresh}, ""); status != 401 {
		t.Fatalf("the session survived sign-out: refresh %d", status)
	}
}
