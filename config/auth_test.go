package config

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func validAuth() Auth {
	a := Defaults()
	a.Issuer = "x"
	return a
}

func mustFail(t *testing.T, a Auth, want string) {
	t.Helper()
	err := a.Validate()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not mention %q", err, want)
	}
}

func TestAuthAppliesDocumentedDefaults(t *testing.T) {
	c := Defaults()
	c.Issuer = "https://auth.example.com"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		name      string
		got, want any
	}{
		{"audience", c.Audience, ""},
		{"access ttl", c.AccessToken.TTL, 900 * time.Second},
		{"signer", c.AccessToken.Signer, SignerRS256},
		{"embed scope", c.AccessToken.EmbedScope, false},
		{"denylist", c.AccessToken.Denylist, false},
		{"refresh ttl", c.RefreshToken.TTL, 2592000 * time.Second},
		{"rotation", c.RefreshToken.Rotation, true},
		{"reuse detection", c.RefreshToken.ReuseDetection, true},
		{"sliding", c.RefreshToken.Sliding, false},
		{"max lifetime", c.RefreshToken.MaxLifetime, 7776000 * time.Second},
		{"otp length", c.OTP.Length, 6},
		{"otp ttl", c.OTP.TTL, 300 * time.Second},
		{"otp attempts", c.OTP.MaxAttempts, 5},
		{"otp cooldown", c.OTP.ResendCooldown, 30 * time.Second},
		{"otp send max", c.OTP.SendMax, 5},
		{"otp send window", c.OTP.SendWindow, 3600 * time.Second},
		{"totp digits", c.OTP.TOTP.Digits, 6},
		{"totp period", c.OTP.TOTP.Period, 30 * time.Second},
		{"totp algorithm", c.OTP.TOTP.Algorithm, SHA1},
		{"totp window", c.OTP.TOTP.Window, 1},
		{"totp issuer", c.OTP.TOTP.Issuer, "Univeros"},
		{"password min", c.Password.MinLength, 12},
		{"password algo", c.Password.Algo, Argon2id},
		{"breach check", c.Password.BreachCheck, false},
		{"lockout attempts", c.Lockout.MaxAttempts, 5},
		{"lockout window", c.Lockout.Window, 900 * time.Second},
		{"lockout duration", c.Lockout.Duration, 900 * time.Second},
		{"mfa enforce", c.MFA.Enforce, false},
		{"mfa grace", c.MFA.GraceEnroll, true},
		{"mfa login ttl", c.MFA.LoginTokenTTL, 300 * time.Second},
		{"step up", c.StepUpMaxAge, 300 * time.Second},
		{"verified email", c.Flows.RequireVerifiedEmail, true},
		{"delivery", c.Flows.TokenDelivery, DeliveryBody},
	}
	for _, ch := range checks {
		if ch.got != ch.want {
			t.Errorf("%s = %v, want %v", ch.name, ch.got, ch.want)
		}
	}
	if len(c.Flows.CookieTrustedOrigins) != 0 {
		t.Errorf("trusted origins = %v, want none", c.Flows.CookieTrustedOrigins)
	}
}

func TestAuthAcceptsOverrides(t *testing.T) {
	c := Defaults()
	c.Issuer = "acme"
	c.Audience = "https://api.acme.test"
	c.AccessToken.TTL = 600 * time.Second
	c.AccessToken.Signer = SignerEdDSA
	c.RefreshToken.TTL = 86400 * time.Second
	c.RefreshToken.Rotation = false
	c.OTP.Length = 8
	c.OTP.TOTP.Digits = 8
	c.OTP.TOTP.Algorithm = SHA256
	c.OTP.TOTP.Issuer = "Acme"
	c.Password.MinLength = 16
	c.Password.Algo = Bcrypt
	c.MFA.Enforce = true
	c.Flows.TokenDelivery = DeliveryCookie
	c.Flows.RequireVerifiedEmail = false
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthRejectsEmptyIssuer(t *testing.T) {
	mustFail(t, Defaults(), "AUTH_ISSUER")
}

func TestAuthRejectsUnknownSigner(t *testing.T) {
	a := validAuth()
	a.AccessToken.Signer = "HS256"
	mustFail(t, a, "auth.access_token.signer")
}

func TestAuthRejectsWeakPasswordPolicy(t *testing.T) {
	a := validAuth()
	a.Password.MinLength = 4
	mustFail(t, a, "auth.password.min_length")
}

func TestAuthRejectsUnknownTokenDelivery(t *testing.T) {
	a := validAuth()
	a.Flows.TokenDelivery = "header"
	mustFail(t, a, "auth.flows.token_delivery")
}

func TestAuthRejectsInvalidTotpDigits(t *testing.T) {
	a := validAuth()
	a.OTP.TOTP.Digits = 9
	mustFail(t, a, "auth.otp.totp.digits")
}

func TestAuthAcceptsHttpsTrustedOriginsForCookieMode(t *testing.T) {
	a := validAuth()
	a.Flows.TokenDelivery = DeliveryCookie
	a.Flows.CookieTrustedOrigins = []string{"https://app.example.com", "https://admin.example.com:8443"}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAuthRejectsATrustedOriginThatIsNotAnHttpsOrigin(t *testing.T) {
	for name, origin := range map[string]string{
		"plaintext":  "http://app.example.com",
		"a path":     "https://app.example.com/",
		"upper case": "https://App.example.com",
		"a wildcard": "https://*.example.com",
		"empty":      "",
	} {
		t.Run(name, func(t *testing.T) {
			a := validAuth()
			a.Flows.TokenDelivery = DeliveryCookie
			a.Flows.CookieTrustedOrigins = []string{origin}
			mustFail(t, a, "auth.flows.cookie.trusted_origins")
		})
	}
}

func TestAuthRejectsEveryInvariant(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Auth)
		want   string
	}{
		"access ttl":        {func(a *Auth) { a.AccessToken.TTL = 0 }, "auth.access_token.ttl"},
		"sub-second ttl":    {func(a *Auth) { a.AccessToken.TTL = 1500 * time.Millisecond }, "whole number of seconds"},
		"refresh ttl":       {func(a *Auth) { a.RefreshToken.TTL = -time.Second }, "auth.refresh_token.ttl"},
		"max lifetime":      {func(a *Auth) { a.RefreshToken.MaxLifetime = time.Hour }, "auth.refresh_token.max_lifetime"},
		"password algo":     {func(a *Auth) { a.Password.Algo = "md5" }, "auth.password.algo"},
		"lockout attempts":  {func(a *Auth) { a.Lockout.MaxAttempts = 0 }, "auth.lockout.max_attempts"},
		"lockout window":    {func(a *Auth) { a.Lockout.Window = 0 }, "auth.lockout.window"},
		"lockout duration":  {func(a *Auth) { a.Lockout.Duration = 0 }, "auth.lockout.lock_duration"},
		"mfa login ttl":     {func(a *Auth) { a.MFA.LoginTokenTTL = 0 }, "auth.mfa.login_token_ttl"},
		"step up":           {func(a *Auth) { a.StepUpMaxAge = 0 }, "auth.step_up.max_age"},
		"otp short":         {func(a *Auth) { a.OTP.Length = 3 }, "auth.otp.length"},
		"otp long":          {func(a *Auth) { a.OTP.Length = 11 }, "auth.otp.length"},
		"otp ttl":           {func(a *Auth) { a.OTP.TTL = 0 }, "auth.otp.ttl"},
		"otp attempts":      {func(a *Auth) { a.OTP.MaxAttempts = 0 }, "auth.otp.max_attempts"},
		"otp cooldown":      {func(a *Auth) { a.OTP.ResendCooldown = -time.Second }, "auth.otp.resend_cooldown"},
		"otp send max":      {func(a *Auth) { a.OTP.SendMax = 0 }, "auth.otp.send_max"},
		"otp send window":   {func(a *Auth) { a.OTP.SendWindow = 0 }, "auth.otp.send_window"},
		"totp digits low":   {func(a *Auth) { a.OTP.TOTP.Digits = 5 }, "auth.otp.totp.digits"},
		"totp period":       {func(a *Auth) { a.OTP.TOTP.Period = 0 }, "auth.otp.totp.period"},
		"totp algorithm":    {func(a *Auth) { a.OTP.TOTP.Algorithm = "MD5" }, "auth.otp.totp.algorithm"},
		"totp window low":   {func(a *Auth) { a.OTP.TOTP.Window = -1 }, "auth.otp.totp.window"},
		"totp window high":  {func(a *Auth) { a.OTP.TOTP.Window = 11 }, "auth.otp.totp.window"},
		"totp issuer":       {func(a *Auth) { a.OTP.TOTP.Issuer = "" }, "auth.otp.totp.issuer"},
		"rate limit budget": {func(a *Auth) { a.RateLimits.Login.Limit = 0 }, "auth.rate_limits.login.limit"},
		"rate limit window": {func(a *Auth) { a.RateLimits.MFASend.Window = 0 }, "auth.rate_limits.mfa_send.window"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			a := validAuth()
			c.mutate(&a)
			mustFail(t, a, c.want)
		})
	}
}

func TestAuthReportsEveryProblemAtOnce(t *testing.T) {
	a := Auth{}
	err := a.Validate()
	for _, want := range []string{"AUTH_ISSUER", "auth.access_token.ttl", "auth.otp.length", "auth.rate_limits.login.limit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
}

func TestZeroWindowAndCooldownAreValid(t *testing.T) {
	a := validAuth()
	a.OTP.TOTP.Window = 0
	a.OTP.ResendCooldown = 0
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestDefaultsDoNotShareState(t *testing.T) {
	a := Defaults()
	a.Flows.CookieTrustedOrigins = append(a.Flows.CookieTrustedOrigins, "https://a.example")
	if b := Defaults(); slices.Contains(b.Flows.CookieTrustedOrigins, "https://a.example") {
		t.Fatal("Defaults must return a fresh value")
	}
}
