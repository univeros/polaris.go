package passwordless_test

import (
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/passwordless"
	"github.com/univeros/polaris.go/polaristest"
)

const (
	// flowFixtures is the file-name prefix of the recorded fixture set under
	// internal/apispec/fixtures/passwordless.
	flowFixtures = "Polaris.Passwordless.Tests.Functional.PasswordlessFlowTest"
	password     = "correct horse battery staple"
	base         = "https://app.example/auth"
	done         = "https://app.example/signed-in"
)

type flow struct {
	t   *testing.T
	srv *polaristest.Server
	c   *contracttest.Client
}

func newFlow(t *testing.T, method string) *flow {
	t.Helper()
	f := &flow{t: t}
	f.srv = polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}),
		passwordless.New(passwordless.Config{BaseURL: base, RedirectURIs: []string{done}})))
	f.c = contracttest.NewClient(t, f.srv.Handler(), contracttest.For(t, contracttest.Fixtures(t, "passwordless"), flowFixtures, method))
	return f
}

func data(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	return d
}

func status(t *testing.T, resp *http.Response, want int, msg ...string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d %v", resp.Request.Method, resp.Request.URL, resp.StatusCode, want, msg)
	}
}

// problem asserts a passwordless problem document.
func problem(t *testing.T, resp *http.Response, want int, code string, msg ...string) {
	t.Helper()
	status(t, resp, want, append(msg, code)...)
	body := contracttest.JSON(t, resp)
	if resp.Header.Get("Content-Type") != "application/problem+json" || body["error"] != code ||
		body["type"] != "https://polaris.univeros.io/problems/"+strings.Replace(code, "_", "/", 1) {
		t.Fatalf("problem %v, want %s", body, code)
	}
}

// login registers, verifies and logs email in: its access token.
func (f *flow) login(email string) string {
	f.t.Helper()
	f.c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var reg event.UserRegistered
	for _, e := range f.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			reg = r
		}
	}
	f.c.Post("/auth/email/verify", map[string]any{"token": reg.VerificationToken})
	access, _ := data(f.t, f.c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return access
}

// mail is the data of the last email sent.
func (f *flow) mail() map[string]any {
	sent := f.srv.Mailer.Sent()
	if len(sent) == 0 {
		f.t.Fatal("no mail sent")
	}
	return sent[len(sent)-1].Data
}

func (f *flow) mailCode() string {
	code, _ := f.mail()["code"].(string)
	return code
}

var digits = regexp.MustCompile(`\d{6,10}`)

func (f *flow) smsCode() string {
	sent := f.srv.SMS.Sent()
	if len(sent) == 0 {
		f.t.Fatal("no SMS sent")
	}
	return digits.FindString(sent[len(sent)-1].Message)
}

func param(t *testing.T, raw, name string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(name)
}

// amr is the amr claim of an access token.
func (f *flow) amr(access string) []string {
	f.t.Helper()
	tok, err := f.srv.Graph().Tokens().Parse(access)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, m := range tok.Claim("amr").([]any) {
		out = append(out, m.(string))
	}
	return out
}

func TestPasswordlessFlow(t *testing.T) {
	t.Run("testAMagicLinkSignsUpRedirectsWithACodeAndExchangesItOnce", func(t *testing.T) {
		f := newFlow(t, "testAMagicLinkSignsUpRedirectsWithACodeAndExchangesItOnce")
		problem(t, f.c.Post("/magic-link/send", map[string]any{"email": "not an email"}), 422, "passwordless_invalid_input")
		problem(t, f.c.Post("/magic-link/send", map[string]any{"email": "ada@example.com", "redirect_uri": "https://evil.example/"}), 422, "passwordless_redirect_not_allowed")
		unknown := f.c.Post("/magic-link/send", map[string]any{"email": "Ada@Example.com"})
		status(t, unknown, 202)
		link, _ := f.mail()["link"].(string)
		if !strings.HasPrefix(link, base+"/magic-link/verify?token=") {
			t.Fatalf("link %q", link)
		}

		problem(t, f.c.Get("/magic-link/verify"), 422, "passwordless_invalid_input")
		verify := f.c.Get("/magic-link/verify?token=" + param(t, link, "token"))
		status(t, verify, 302)
		location := verify.Header.Get("Location")
		if !strings.HasPrefix(location, done+"?code=") {
			t.Fatalf("location %q", location)
		}
		problem(t, f.c.Get("/magic-link/verify?token="+param(t, link, "token")), 422, "passwordless_token_invalid", "a link works once")

		code := param(t, location, "code")
		problem(t, f.c.Post("/magic-link/exchange", nil), 422, "passwordless_invalid_input")
		problem(t, f.c.Post("/magic-link/exchange", map[string]any{"code": "nope"}), 422, "passwordless_token_invalid")
		session := data(t, f.c.Post("/magic-link/exchange", map[string]any{"code": code}))
		user, _ := session["user"].(map[string]any)
		if session["token_type"] != "Bearer" || user["email"] != "ada@example.com" || user["email_verified"] != true {
			t.Fatalf("session %v", session)
		}
		access := session["access_token"].(string)
		if got := f.amr(access); !slices.Equal(got, []string{"magic_link"}) {
			t.Fatalf("amr %v", got)
		}
		problem(t, f.c.Post("/magic-link/exchange", map[string]any{"code": code}), 422, "passwordless_token_invalid", "a code works once")
		if me := data(t, f.c.Get("/auth/me", contracttest.Bearer(access))); me["email"] != "ada@example.com" {
			t.Fatalf("me %v", me)
		}

		known := f.c.Post("/magic-link/send", map[string]any{"email": "ada@example.com"})
		status(t, known, 202, "a known address gets the same answer")
	})

	t.Run("testEmailCodesSignInVerifyTheEmailAndResetThePassword", func(t *testing.T) {
		f := newFlow(t, "testEmailCodesSignInVerifyTheEmailAndResetThePassword")
		f.c.Post("/auth/register", map[string]any{"email": "ada@example.com", "password": password})

		status(t, f.c.Post("/email-otp/send", map[string]any{"email": "ada@example.com", "purpose": "verify-email"}), 202)
		code := f.mailCode()
		problem(t, f.c.Post("/email-otp/verify-email", map[string]any{"email": "ada@example.com", "code": "000000"}), 422, "passwordless_code_invalid")
		if d := data(t, f.c.Post("/email-otp/verify-email", map[string]any{"email": "ada@example.com", "code": code})); d["status"] != "verified" {
			t.Fatalf("verify-email %v", d)
		}
		problem(t, f.c.Post("/email-otp/verify-email", map[string]any{"email": "ada@example.com", "code": code}), 422, "passwordless_code_invalid", "once")

		f.c.Post("/email-otp/send", map[string]any{"email": "ada@example.com"})
		code = f.mailCode()
		problem(t, f.c.Post("/email-otp/verify", map[string]any{"email": "ada@example.com", "code": "000000"}), 422, "passwordless_code_invalid")
		session := data(t, f.c.Post("/email-otp/verify", map[string]any{"email": "ada@example.com", "code": code}))
		if got := f.amr(session["access_token"].(string)); !slices.Equal(got, []string{"email_otp"}) {
			t.Fatalf("amr %v", got)
		}
		problem(t, f.c.Post("/email-otp/verify", map[string]any{"email": "ada@example.com", "code": code}), 422, "passwordless_code_invalid", "once")

		f.c.Post("/email-otp/send", map[string]any{"email": "ada@example.com", "purpose": "reset-password"})
		code = f.mailCode()
		problem(t, f.c.Post("/email-otp/reset-password", map[string]any{"email": "ada@example.com", "code": code, "password": "short"}), 422, "passwordless_password_invalid")
		if d := data(t, f.c.Post("/email-otp/reset-password", map[string]any{"email": "ada@example.com", "code": code, "password": "a brand new passphrase"})); d["status"] != "password_reset" {
			t.Fatalf("reset %v", d)
		}
		status(t, f.c.Post("/auth/token/refresh", map[string]any{"refresh_token": session["refresh_token"]}), 401, "every session ended")
		status(t, f.c.Post("/auth/login", map[string]any{"email": "ada@example.com", "password": "a brand new passphrase"}), 200)

		problem(t, f.c.Post("/email-otp/send", map[string]any{"email": "ada@example.com", "purpose": "unlock"}), 422, "passwordless_invalid_input")
		sent := len(f.srv.Mailer.Sent())
		status(t, f.c.Post("/email-otp/send", map[string]any{"email": "nobody@example.com", "purpose": "reset-password"}), 202, "an unknown address gets the same answer")
		if len(f.srv.Mailer.Sent()) != sent {
			t.Fatal("an unknown address was sent a reset code")
		}
		problem(t, f.c.Post("/email-otp/verify", map[string]any{"email": "nobody@example.com", "code": "123456"}), 422, "passwordless_code_invalid", "an unknown address answers as a wrong code")
	})

	t.Run("testAVerifiedPhoneSignsItsOwnerIn", func(t *testing.T) {
		f := newFlow(t, "testAVerifiedPhoneSignsItsOwnerIn")
		access := f.login("ada@example.com")
		as := contracttest.Bearer(access)

		status(t, f.c.Post("/phone/add", map[string]any{"phone": "+15551234567"}), 401)
		status(t, f.c.Post("/phone/add", map[string]any{"phone": "+1 (555) 123-4567"}, as), 202)
		code := f.smsCode()
		problem(t, f.c.Post("/phone/confirm", map[string]any{"phone": "+15551234567"}, as), 422, "passwordless_invalid_input")
		if d := data(t, f.c.Post("/phone/confirm", map[string]any{"phone": "+15551234567", "code": code}, as)); d["phone"] != "+15551234567" || d["verified"] != true {
			t.Fatalf("confirm %v", d)
		}

		status(t, f.c.Post("/phone/send", map[string]any{"phone": "+15551234567"}), 202)
		code = f.smsCode()
		status(t, f.c.Post("/phone/send", map[string]any{"phone": "+15550000000"}), 202, "an unknown number gets the same answer")
		problem(t, f.c.Post("/phone/send", map[string]any{"phone": "call me"}), 422, "passwordless_invalid_input")
		problem(t, f.c.Post("/phone/verify", map[string]any{"phone": "+15550000000", "code": code}), 422, "passwordless_code_invalid", "an unknown number answers as a wrong code")
		session := data(t, f.c.Post("/phone/verify", map[string]any{"phone": "+15551234567", "code": code}))
		if user, _ := session["user"].(map[string]any); user["email"] != "ada@example.com" {
			t.Fatalf("session %v", session)
		}
		if got := f.amr(session["access_token"].(string)); !slices.Equal(got, []string{"phone"}) {
			t.Fatalf("amr %v", got)
		}
		problem(t, f.c.Post("/phone/verify", map[string]any{"phone": "+15551234567", "code": code}), 422, "passwordless_code_invalid", "once")
	})

	t.Run("testAOneTimeTokenHandsTheSessionToAnotherDeviceOnce", func(t *testing.T) {
		f := newFlow(t, "testAOneTimeTokenHandsTheSessionToAnotherDeviceOnce")
		access := f.login("ada@example.com")

		status(t, f.c.Post("/one-time-token/generate", map[string]any{}), 401)
		generated := data(t, f.c.Post("/one-time-token/generate", map[string]any{}, contracttest.Bearer(access)))
		if generated["expires_in"] != float64(180) {
			t.Fatalf("generated %v", generated)
		}
		problem(t, f.c.Post("/one-time-token/verify", map[string]any{}), 422, "passwordless_invalid_input")
		session := data(t, f.c.Post("/one-time-token/verify", map[string]any{"token": generated["token"]}))
		if got := f.amr(session["access_token"].(string)); !slices.Equal(got, []string{"pwd"}) {
			t.Fatalf("amr %v, want the generating session's", got)
		}
		if me := data(t, f.c.Get("/auth/me", contracttest.Bearer(session["access_token"].(string)))); me["email"] != "ada@example.com" {
			t.Fatalf("me %v", me)
		}
		problem(t, f.c.Post("/one-time-token/verify", map[string]any{"token": generated["token"]}), 422, "passwordless_token_invalid", "once")
	})
}

func TestEveryPasswordlessFixtureHasAGoTest(t *testing.T) {
	var covered []string
	for _, m := range []string{
		"testAMagicLinkSignsUpRedirectsWithACodeAndExchangesItOnce", "testEmailCodesSignInVerifyTheEmailAndResetThePassword",
		"testAVerifiedPhoneSignsItsOwnerIn", "testAOneTimeTokenHandsTheSessionToAnotherDeviceOnce",
	} {
		covered = append(covered, flowFixtures+"::"+m)
	}
	missing, err := contracttest.Uncovered(contracttest.Fixtures(t, "passwordless"), covered)
	if err != nil || len(missing) > 0 {
		t.Fatalf("fixtures without a Go test: %v %v", missing, err)
	}
}
