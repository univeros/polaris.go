package passwordless

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/notify/notifytest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// Port of upstream packages/passwordless/tests/PluginTest.php (the sentinel test waits for the
// sentinel plugin), plus the Go-only concurrency checks.

const (
	tBase  = "https://app.example/auth"
	tDone  = "https://app.example/signed-in"
	tOther = "https://app.example/other?tab=1"
	tPass  = "correct horse battery staple"
)

var tNow = time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)

type recorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recorder) Dispatch(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *recorder) count(name string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.EventName() == name {
			n++
		}
	}
	return n
}

type env struct {
	t      *testing.T
	g      *wiring.Graph
	v      *service
	clk    *clock.Frozen
	mail   *notifytest.Mailer
	sms    *notifytest.SMSSender
	events *recorder
	ctx    context.Context
}

func boot(t *testing.T, cfg Config) env {
	t.Helper()
	if cfg.BaseURL == "" {
		cfg.BaseURL = tBase
	}
	if cfg.RedirectURIs == nil {
		cfg.RedirectURIs = []string{tDone, tOther}
	}
	e, err := tryBoot(cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.t = t
	return e
}

func tryBoot(cfg Config) (env, error) {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	e := env{clk: clock.NewFrozen(tNow), mail: &notifytest.Mailer{}, sms: &notifytest.SMSSender{}, events: &recorder{}}
	plugin := New(cfg)
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: memstore.New(append(schema.Core(), Models()...)...), Clock: e.clk, Events: e.events,
		Mailer: e.mail, SMS: e.sms, Hasher: security.Argon2id{Memory: 1024, Time: 1}, Plugins: []polaris.Plugin{plugin},
	})
	if err != nil {
		return env{}, err
	}
	e.g, e.v = p.Graph(), plugin.svc
	e.ctx = endpoint.WithClient(context.Background(), token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"})
	return e, nil
}

func (e env) user(email string, verified bool) model.User {
	e.t.Helper()
	hash, _ := e.g.Hasher().Hash(tPass)
	now := e.clk.Now()
	u := model.User{ID: repository.NewID(), Email: email, PasswordHash: &hash, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if verified {
		u.EmailVerifiedAt = &now
	}
	if err := e.g.Repos().Users.Insert(context.Background(), u); err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e env) reload(id string) model.User {
	e.t.Helper()
	u, err := e.g.Repos().Users.Get(context.Background(), id)
	if err != nil {
		e.t.Fatal(err)
	}
	return u
}

func (e env) factor(userID string) {
	e.t.Helper()
	addr := "ada@example.com"
	now := e.clk.Now()
	if err := e.g.Repos().MFAFactors.Insert(context.Background(), model.MFAFactor{ID: "factor-" + userID, UserID: userID, Type: "email", Email: &addr, IsDefault: true, ConfirmedAt: &now, CreatedAt: now, UpdatedAt: now}); err != nil {
		e.t.Fatal(err)
	}
}

func (e env) linkToken() string {
	e.t.Helper()
	sent := e.mail.Sent()
	link, _ := sent[len(sent)-1].Data["link"].(string)
	if !strings.HasPrefix(link, tBase+"/magic-link/verify?token=") {
		e.t.Fatalf("link %q", link)
	}
	return query(e.t, link)["token"]
}

func (e env) mailCode() string {
	sent := e.mail.Sent()
	code, _ := sent[len(sent)-1].Data["code"].(string)
	return code
}

var smsDigits = regexp.MustCompile(`\d{6,10}`)

func (e env) smsCode() string {
	sent := e.sms.Sent()
	return smsDigits.FindString(sent[len(sent)-1].Message)
}

func (e env) claims(data envelope) map[string]any {
	e.t.Helper()
	tok, err := e.g.Tokens().Parse(data["access_token"].(string))
	if err != nil {
		e.t.Fatal(err)
	}
	return tok.Claims()
}

func query(t *testing.T, raw string) map[string]string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for k, v := range u.Query() {
		out[k] = v[0]
	}
	return out
}

func amr(claims map[string]any) []string {
	var out []string
	for _, m := range claims["amr"].([]any) {
		out = append(out, m.(string))
	}
	return out
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func refused(t *testing.T, err error, want error, msg string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", msg, err, want)
	}
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func TestPlugin(t *testing.T) {
	t.Run("testEverythingIsWiredThroughTheGraph", func(t *testing.T) {
		e := boot(t, Config{})
		tables := map[string]bool{}
		for _, m := range e.g.Schema() {
			tables[m.Table] = true
		}
		if !tables[TableSecrets] || !tables[TablePhones] {
			t.Fatal("tables missing")
		}
		var routes []string
		for _, rt := range e.g.Manifest().Routes() {
			if slices.Contains(rt.Tags, ID) {
				routes = append(routes, rt.Method+" "+rt.Path)
			}
		}
		want := []string{"POST /magic-link/send", "GET /magic-link/verify", "POST /magic-link/exchange", "POST /email-otp/send", "POST /email-otp/verify", "POST /email-otp/verify-email", "POST /email-otp/reset-password", "POST /phone/send", "POST /phone/verify", "POST /phone/add", "POST /phone/confirm", "POST /one-time-token/generate", "POST /one-time-token/verify"}
		if len(routes) != 13 {
			t.Fatalf("routes %v", routes)
		}
		for _, r := range want {
			if !slices.Contains(routes, r) {
				t.Fatalf("route %s missing", r)
			}
		}
		for path := range SentinelRoutes {
			if !slices.Contains(routes, "POST "+path) {
				t.Fatalf("sentinel guards %s, which the plugin does not have", path)
			}
		}
		if e.v.s.baseURL != tBase {
			t.Fatalf("base %q", e.v.s.baseURL)
		}
		for _, bad := range []Config{
			{BaseURL: "/auth"}, {BaseURL: tBase, OTPLength: 4}, {BaseURL: tBase, OTPLength: 11},
			{BaseURL: tBase, MaxAttempts: -1}, {BaseURL: tBase, OTPTTL: 1500 * time.Millisecond}, {BaseURL: tBase, MagicLinkTTL: -time.Second},
			{BaseURL: tBase, OneTimeTokenTTL: time.Millisecond},
		} {
			if _, err := tryBoot(bad); err == nil || !strings.Contains(err.Error(), "passwordless: Config.") {
				t.Fatalf("%+v accepted: %v", bad, err)
			}
		}
	})

	t.Run("BaseURLDefaultsToTheIssuer", func(t *testing.T) {
		e, err := tryBoot(Config{})
		if err != nil {
			t.Fatal(err)
		}
		if e.v.s.baseURL != "https://issuer.test" || !e.v.s.signUp || !e.v.s.respectMFA || e.v.s.otpLength != 6 || e.v.s.maxAttempts != 5 {
			t.Fatalf("defaults %+v", e.v.s)
		}
	})

	t.Run("testAMagicLinkSignsUpOnceAndRedirectsWithAOneUseCode", func(t *testing.T) {
		e := boot(t, Config{})
		ctx := e.ctx
		if err := e.v.sendMagicLink(ctx, "Ada@Example.com", ""); err != nil {
			t.Fatal(err)
		}
		tok := e.linkToken()
		if e.mail.Sent()[0].To != "ada@example.com" || e.mail.Sent()[0].Template != TemplateMagicLink || e.mail.Sent()[0].Data["ttl"] != 900 {
			t.Fatalf("mail %+v", e.mail.Sent()[0])
		}
		redirect := must[string](t)(e.v.verifyMagicLink(ctx, tok))
		if !strings.HasPrefix(redirect, tDone+"?code=") {
			t.Fatalf("redirect %q", redirect)
		}
		data := must[envelope](t)(e.v.exchange(ctx, query(t, redirect)["code"]))
		user := data["user"].(map[string]any)
		if data["token_type"] != "Bearer" || user["email"] != "ada@example.com" || user["email_verified"] != true {
			t.Fatalf("data %v", data)
		}
		if got := amr(e.claims(data)); !slices.Equal(got, []string{AMRMagicLink}) {
			t.Fatalf("amr %v", got)
		}
		u, err := e.g.Repos().Users.ByEmail(ctx, "ada@example.com")
		if err != nil || u.PasswordHash != nil {
			t.Fatalf("signed up %+v %v", u, err)
		}
		if e.events.count("user.registered") != 0 || e.events.count("user.logged_in") != 1 {
			t.Fatal("a proven mailbox gets no verification mail; the sign-in is logged")
		}

		_, err = e.v.verifyMagicLink(ctx, tok)
		refused(t, err, ErrTokenInvalid, "a link works once")
		_, err = e.v.exchange(ctx, query(t, redirect)["code"])
		refused(t, err, ErrTokenInvalid, "a code works once")
		refused(t, e.v.sendMagicLink(ctx, "ada@example.com", "https://evil.example/"), ErrRedirectNotAllowed, "the allow-list")

		ok(t, e.v.sendMagicLink(ctx, "ada@example.com", tOther))
		if r := must[string](t)(e.v.verifyMagicLink(ctx, e.linkToken())); !strings.HasPrefix(r, tOther+"&code=") {
			t.Fatalf("the allowed redirect, its query kept: %q", r)
		}
		ok(t, e.v.sendMagicLink(ctx, "ada@example.com", ""))
		e.clk.Advance(16 * time.Minute)
		_, err = e.v.verifyMagicLink(ctx, e.linkToken())
		refused(t, err, ErrTokenInvalid, "a link lives 15 minutes")

		if _, err := e.g.DB().Update(ctx, "auth_users", store.Criteria{"id": u.ID}, store.Data{"status": model.UserStatusDisabled}); err != nil {
			t.Fatal(err)
		}
		sent := len(e.mail.Sent())
		ok(t, e.v.sendMagicLink(ctx, "ada@example.com", ""))
		if len(e.mail.Sent()) != sent {
			t.Fatal("a disabled account gets nothing")
		}
	})

	t.Run("NoRedirectConfigured", func(t *testing.T) {
		e := boot(t, Config{RedirectURIs: []string{}})
		refused(t, e.v.sendMagicLink(e.ctx, "ada@example.com", ""), ErrRedirectNotAllowed, "no default")
	})

	t.Run("testWithoutSignUpAnUnknownAddressGetsNothingAndTheSameRefusal", func(t *testing.T) {
		e := boot(t, Config{DisableSignUp: true})
		ok(t, e.v.sendMagicLink(e.ctx, "nobody@example.com", ""))
		ok(t, e.v.sendEmailCode(e.ctx, "nobody@example.com", PurposeSignIn))
		if len(e.mail.Sent()) != 0 {
			t.Fatal("sent to an unknown address")
		}
		_, err := e.v.signInWithEmailCode(e.ctx, "nobody@example.com", "123456")
		refused(t, err, ErrCodeInvalid, "sign-in")
		_, err = e.v.forEmail(e.ctx, "nobody@example.com")
		refused(t, err, ErrCodeInvalid, "forEmail")
	})

	t.Run("testEmailCodesAreBoundToTheirPurposeAndAddressAndDieAfterFiveWrongGuesses", func(t *testing.T) {
		e := boot(t, Config{})
		ctx := e.ctx
		ada := e.user("ada@example.com", false)

		ok(t, e.v.sendEmailCode(ctx, "ada@example.com", PurposeSignIn))
		code := e.mailCode()
		for range 5 {
			_, err := e.v.signInWithEmailCode(ctx, "ada@example.com", "000000")
			refused(t, err, ErrCodeInvalid, "wrong")
		}
		_, err := e.v.signInWithEmailCode(ctx, "ada@example.com", code)
		refused(t, err, ErrCodeInvalid, "five wrong guesses kill the code")
		ok(t, e.v.sendEmailCode(ctx, "ada@example.com", PurposeSignIn))
		_, err = e.v.signInWithEmailCode(ctx, "ada@example.com", e.mailCode())
		refused(t, err, ErrCodeInvalid, "a code sent again inherits the spent attempts")

		e.clk.Advance(6 * time.Minute)
		ok(t, e.v.sendEmailCode(ctx, "ada@example.com", PurposeSignIn))
		code = e.mailCode()
		if !regexp.MustCompile(`^\d{6}$`).MatchString(code) {
			t.Fatalf("code %q", code)
		}
		_, err = e.v.signInWithEmailCode(ctx, "grace@example.com", code)
		refused(t, err, ErrCodeInvalid, "bound to its address")
		refused(t, e.v.resetPassword(ctx, "ada@example.com", code, tPass), ErrCodeInvalid, "bound to its purpose")
		data := must[envelope](t)(e.v.signInWithEmailCode(ctx, "ADA@example.com", code))
		if got := amr(e.claims(data)); !slices.Equal(got, []string{AMREmailOTP}) || data["user"].(map[string]any)["email_verified"] != true {
			t.Fatalf("data %v", data)
		}
		if e.reload(ada.ID).PasswordHash != nil {
			t.Fatal("a password set before anyone proved the mailbox goes")
		}
		if e.events.count("user.email_verified") != 1 {
			t.Fatal("verified once")
		}
		_, err = e.v.signInWithEmailCode(ctx, "ada@example.com", code)
		refused(t, err, ErrCodeInvalid, "once")
		_, err = e.v.signInWithEmailCode(ctx, "nobody@example.com", "123456")
		refused(t, err, ErrCodeInvalid, "an unknown address answers the same")

		sent := len(e.mail.Sent())
		ok(t, e.v.sendEmailCode(ctx, "ada@example.com", PurposeVerifyEmail))
		if len(e.mail.Sent()) != sent {
			t.Fatal("a verified address gets no verification code")
		}
		grace := e.user("grace@example.com", false)
		ok(t, e.v.sendEmailCode(ctx, "grace@example.com", PurposeVerifyEmail))
		ok(t, e.v.verifyEmail(ctx, "grace@example.com", e.mailCode()))
		if e.reload(grace.ID).EmailVerifiedAt == nil {
			t.Fatal("grace verified")
		}

		session := must[envelope](t)(e.v.open(ctx, e.reload(ada.ID), facts{amr: []string{"pwd"}, gate: true}))
		ok(t, e.v.sendEmailCode(ctx, "ada@example.com", PurposeResetPassword))
		code = e.mailCode()
		refused(t, e.v.resetPassword(ctx, "ada@example.com", code, "short"), ErrPasswordInvalid, "policy")
		ok(t, e.v.resetPassword(ctx, "ada@example.com", code, "a brand new passphrase"))
		if e.events.count("user.password_changed") != 1 {
			t.Fatal("password changed")
		}
		if n, _ := e.g.DB().Count(ctx, "auth_refresh_tokens", store.Criteria{"user_id": ada.ID, "revoked_reason": "password_change"}); n == 0 || session["refresh_token"] == "" {
			t.Fatal("every session ended")
		}
		if res, err := e.g.Identity().Login(ctx, "ada@example.com", "a brand new passphrase", token.ClientContext{}); err != nil || res.UserID != ada.ID {
			t.Fatalf("login %v", err)
		}
		refused(t, e.v.resetPassword(ctx, "ada@example.com", code, "another new passphrase"), ErrCodeInvalid, "once")
	})

	t.Run("AResetLiftsALockAndVerifies", func(t *testing.T) {
		e := boot(t, Config{})
		u := e.user("ada@example.com", false)
		until := e.clk.Now().Add(time.Hour)
		if _, err := e.g.DB().Update(e.ctx, "auth_users", store.Criteria{"id": u.ID}, store.Data{"status": model.UserStatusLocked, "locked_until": until}); err != nil {
			t.Fatal(err)
		}
		ok(t, e.v.sendEmailCode(e.ctx, "ada@example.com", PurposeResetPassword))
		ok(t, e.v.resetPassword(e.ctx, "ada@example.com", e.mailCode(), "a brand new passphrase"))
		if got := e.reload(u.ID); got.Status != model.UserStatusActive || got.LockedUntil != nil || got.EmailVerifiedAt == nil {
			t.Fatalf("user %+v", got)
		}
	})

	t.Run("testCoresMfaGateHoldsUnlessTurnedOff", func(t *testing.T) {
		e := boot(t, Config{})
		ada := e.user("ada@example.com", true)
		e.factor(ada.ID)
		ok(t, e.v.sendEmailCode(e.ctx, "ada@example.com", PurposeSignIn))
		data := must[envelope](t)(e.v.signInWithEmailCode(e.ctx, "ada@example.com", e.mailCode()))
		if data["mfa_required"] != true || data["mfa_token"] == "" || data["access_token"] != nil {
			t.Fatalf("data %v", data)
		}

		e = boot(t, Config{SkipMFAGate: true})
		ada = e.user("ada@example.com", true)
		e.factor(ada.ID)
		ok(t, e.v.sendEmailCode(e.ctx, "ada@example.com", PurposeSignIn))
		if data := must[envelope](t)(e.v.signInWithEmailCode(e.ctx, "ada@example.com", e.mailCode())); data["access_token"] == nil {
			t.Fatalf("gate off %v", data)
		}
	})

	t.Run("ADisabledAccountIsRefused", func(t *testing.T) {
		e := boot(t, Config{})
		u := e.user("ada@example.com", true)
		u.Status = model.UserStatusDisabled
		_, err := e.v.open(e.ctx, u, facts{amr: []string{"pwd"}})
		refused(t, err, ErrAccountDisabled, "disabled")
	})

	t.Run("testAPhoneIsAVerifiedSecondContactAndASignInIdentifierNeverASignUpOne", func(t *testing.T) {
		e := boot(t, Config{})
		ctx := e.ctx
		ada, grace := e.user("ada@example.com", true), e.user("grace@example.com", true)

		ok(t, e.v.addPhone(ctx, ada.ID, "+1 (555) 123-4567"))
		if e.sms.Sent()[0].To != "+15551234567" {
			t.Fatalf("sms %+v", e.sms.Sent())
		}
		code := e.smsCode()
		_, err := e.v.confirmPhone(ctx, grace.ID, "+15551234567", code)
		refused(t, err, ErrCodeInvalid, "only the user who asked")
		_, err = e.v.confirmPhone(ctx, ada.ID, "+15551234567", code)
		refused(t, err, ErrCodeInvalid, "a refused confirmation spends the code")
		ok(t, e.v.addPhone(ctx, ada.ID, "+15551234567"))
		if got := must[string](t)(e.v.confirmPhone(ctx, ada.ID, "+15551234567", e.smsCode())); got != "+15551234567" {
			t.Fatalf("confirmed %q", got)
		}
		if owner, _ := e.v.phoneOwner(ctx, "+15551234567"); owner != ada.ID {
			t.Fatal("owner")
		}
		if phone, _ := e.v.phoneOf(ctx, ada.ID); phone != "+15551234567" {
			t.Fatal("phoneOf")
		}

		ok(t, e.v.addPhone(ctx, grace.ID, "+15551234567"))
		if len(e.sms.Sent()) != 2 {
			t.Fatal("another account's number gets nothing")
		}
		refused(t, e.v.attachPhone(ctx, grace.ID, "+15551234567"), ErrPhoneTaken, "taken")
		ok(t, e.v.sendPhone(ctx, "+15550000000"))
		if len(e.sms.Sent()) != 2 {
			t.Fatal("an unknown number gets nothing")
		}
		_, err = e.v.signInWithPhone(ctx, "+15550000000", "123456")
		refused(t, err, ErrCodeInvalid, "unknown number")
		refused(t, e.v.sendPhone(ctx, "not a number"), ErrInvalidInput, "not a number")

		ok(t, e.v.sendPhone(ctx, "+1 555 123 4567"))
		code = e.smsCode()
		data := must[envelope](t)(e.v.signInWithPhone(ctx, "+15551234567", code))
		if data["user"].(map[string]any)["id"] != ada.ID || !slices.Equal(amr(e.claims(data)), []string{AMRPhone}) {
			t.Fatalf("data %v", data)
		}
		_, err = e.v.signInWithPhone(ctx, "+15551234567", code)
		refused(t, err, ErrCodeInvalid, "once")

		// A user replaces their number; a second account racing for one number loses on the index.
		ok(t, e.v.attachPhone(ctx, ada.ID, "+15557654321"))
		if phone, _ := e.v.phoneOf(ctx, ada.ID); phone != "+15557654321" {
			t.Fatal("replaced")
		}
	})

	t.Run("testAOneTimeTokenHandsASessionOverOnceWithItsAuthenticationFacts", func(t *testing.T) {
		e := boot(t, Config{})
		ctx := e.ctx
		ada := e.user("ada@example.com", true)
		authTime := int64(1760000000)
		issued := must[token.IssuedTokens](t)(e.g.Sessions().Issue(ctx, token.SessionPrincipal{UserID: ada.ID, EmailVerified: true, MFA: true, AMR: []string{"pwd", "otp"}, AuthTime: &authTime}, token.ClientContext{}))
		access := must[*token.Token](t)(e.g.Tokens().Parse(issued.AccessToken))

		generated := must[map[string]any](t)(e.v.generateOneTimeToken(ctx, access))
		if generated["expires_in"] != 180 {
			t.Fatalf("generated %v", generated)
		}
		data := must[envelope](t)(e.v.verifyOneTimeToken(ctx, generated["token"].(string)))
		claims := e.claims(data)
		if !slices.Equal(amr(claims), []string{"pwd", "otp"}) || claims["mfa"] != true || claims["auth_time"] != authTime {
			t.Fatalf("inherited %v", claims)
		}
		if claims["sid"] == issued.SessionID {
			t.Fatal("a new session")
		}
		_, err := e.v.verifyOneTimeToken(ctx, generated["token"].(string))
		refused(t, err, ErrTokenInvalid, "once")
		generated = must[map[string]any](t)(e.v.generateOneTimeToken(ctx, access))
		e.clk.Advance(4 * time.Minute)
		_, err = e.v.verifyOneTimeToken(ctx, generated["token"].(string))
		refused(t, err, ErrTokenInvalid, "three minutes")

		e.clk.Advance(-4 * time.Minute)
		generated = must[map[string]any](t)(e.v.generateOneTimeToken(ctx, access))
		if err := e.g.Sessions().RevokeFamily(ctx, issued.SessionID, model.RevokedLogout); err != nil {
			t.Fatal(err)
		}
		_, err = e.v.verifyOneTimeToken(ctx, generated["token"].(string))
		refused(t, err, ErrTokenInvalid, "the token dies with its session")

		minted := must[string](t)(e.g.Sessions().Mint(context.Background(), token.SessionPrincipal{UserID: ada.ID}, "", token.Claims{}))
		_, err = e.v.generateOneTimeToken(ctx, must[*token.Token](t)(e.g.Tokens().Parse(minted)))
		refused(t, err, ErrSessionRequired, "no session behind the token")
		_, err = e.v.generateOneTimeToken(ctx, access)
		refused(t, err, ErrSessionRequired, "the session ended")
	})

	t.Run("AOneTimeTokenWithoutAmrSaysSo", func(t *testing.T) {
		e := boot(t, Config{})
		ada := e.user("ada@example.com", true)
		issued := must[token.IssuedTokens](t)(e.g.Sessions().Issue(e.ctx, token.SessionPrincipal{UserID: ada.ID}, token.ClientContext{}))
		claims := map[string]any{"sub": ada.ID, "sid": issued.SessionID, "org": "org-1"}
		generated := must[map[string]any](t)(e.v.generateOneTimeToken(e.ctx, token.NewPrincipal(claims)))
		data := must[envelope](t)(e.v.verifyOneTimeToken(e.ctx, generated["token"].(string)))
		if c := e.claims(data); !slices.Equal(amr(c), []string{AMROneTimeToken}) || c["org"] != "org-1" {
			t.Fatalf("claims %v", c)
		}
	})
}

// Go-only: the single-use and attempt checks hold under concurrency.
func TestConcurrency(t *testing.T) {
	t.Run("ACodeIsSpentOnce", func(t *testing.T) {
		e := boot(t, Config{})
		e.user("ada@example.com", true)
		ok(t, e.v.sendEmailCode(e.ctx, "ada@example.com", PurposeSignIn))
		code := e.mailCode()
		var wins atomic.Int32
		parallel(8, func() {
			if _, err := e.v.signInWithEmailCode(e.ctx, "ada@example.com", code); err == nil {
				wins.Add(1)
			}
		})
		if wins.Load() != 1 {
			t.Fatalf("%d wins", wins.Load())
		}
	})

	t.Run("ParallelGuessesStayWithinTheBudget", func(t *testing.T) {
		e := boot(t, Config{})
		e.user("ada@example.com", true)
		ok(t, e.v.sendEmailCode(e.ctx, "ada@example.com", PurposeSignIn))
		parallel(20, func() { _, _ = e.v.signInWithEmailCode(e.ctx, "ada@example.com", "000000") })
		rows, _ := e.g.DB().FindMany(e.ctx, TableSecrets, store.Criteria{"kind": kindEmailSignIn}, store.Query{})
		if len(rows) != 1 || rows[0].Int("attempts") != 5 {
			t.Fatalf("rows %v", rows)
		}
	})

	t.Run("AHandOffCodeIsExchangedOnce", func(t *testing.T) {
		e := boot(t, Config{})
		code := must[string](t)(e.v.handOff(e.ctx, envelope{"access_token": "a"}))
		var wins atomic.Int32
		parallel(8, func() {
			if _, err := e.v.exchange(e.ctx, code); err == nil {
				wins.Add(1)
			}
		})
		if wins.Load() != 1 {
			t.Fatalf("%d wins", wins.Load())
		}
	})

	t.Run("ConcurrentSignUpsMakeOneAccount", func(t *testing.T) {
		e := boot(t, Config{})
		var ids sync.Map
		parallel(8, func() {
			if u, err := e.v.forEmail(e.ctx, "new@example.com"); err == nil {
				ids.Store(u.ID, true)
			}
		})
		n := 0
		ids.Range(func(any, any) bool { n++; return true })
		if n != 1 {
			t.Fatalf("%d accounts", n)
		}
	})
}

func parallel(n int, f func()) {
	var wg sync.WaitGroup
	for range n {
		wg.Go(f)
	}
	wg.Wait()
}

func TestPHPJSON(t *testing.T) {
	got, err := phpJSON(magicLinkData{Email: "zoë@example.com", RedirectURI: "https://app.example/x?a=1&b=<2>"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"email":"zo` + "\\u00eb" + `@example.com","redirect_uri":"https:\/\/app.example\/x?a=1&b=<2>"}`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
	if got, _ := phpJSON("\U0001F600"); got != "\"\\ud83d\\ude00\"" {
		t.Fatalf("surrogates %s", got)
	}
	if got, _ := phpJSON(nil); got != "[]" {
		t.Fatalf("nil %s", got)
	}
	if _, err := phpJSON(make(chan int)); err == nil {
		t.Fatal("unencodable accepted")
	}
}
