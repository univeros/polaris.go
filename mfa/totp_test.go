package mfa

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
)

// 2026-06-08 12:00:00 UTC, as the upstream test.
var instant = time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

func newTOTP(t *testing.T, cfg config.TOTP, at time.Time) *TOTP {
	t.Helper()
	p, err := NewTOTP(cfg, clock.NewFrozen(at))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func defaults() config.TOTP { return config.Defaults().OTP.TOTP }

func TestGeneratesABase32SecretOf64Bytes(t *testing.T) {
	p := newTOTP(t, defaults(), instant)
	secret := p.GenerateSecret()
	// otphp's default: 64 random bytes, base32 upper case, padding trimmed.
	if !regexp.MustCompile(`^[A-Z2-7]{103}$`).MatchString(secret) {
		t.Fatalf("secret %q", secret)
	}
	if p.GenerateSecret() == secret {
		t.Fatal("secrets must be random")
	}
}

func TestProvisioningURIIsByteIdenticalToOtphp(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	custom := config.TOTP{Digits: 8, Period: 60 * time.Second, Algorithm: config.SHA256, Window: 1, Issuer: "Acme Corp & Co"}
	cases := []struct {
		cfg           config.TOTP
		secret, label string
		want          string
	}{
		// Captured from OtphpTotpProvider (polaris-core 0.12.0, spomky-labs/otphp).
		{defaults(), secret, "ada@example.com", "otpauth://totp/Univeros%3Aada%40example.com?issuer=Univeros&secret=JBSWY3DPEHPK3PXP"},
		{defaults(), secret, "Ada Lovelace+x~y/z@ex.com", "otpauth://totp/Univeros%3AAda%20Lovelace%2Bx~y%2Fz%40ex.com?issuer=Univeros&secret=JBSWY3DPEHPK3PXP"},
		{defaults(), "jbswy3dpehpk3pxp===", "ünïcode user", "otpauth://totp/Univeros%3A%C3%BCn%C3%AFcode%20user?issuer=Univeros&secret=JBSWY3DPEHPK3PXP"},
		{custom, secret, "ada@example.com", "otpauth://totp/Acme%20Corp%20%26%20Co%3Aada%40example.com?algorithm=sha256&digits=8&issuer=Acme%20Corp%20%26%20Co&period=60&secret=JBSWY3DPEHPK3PXP"},
	}
	for _, c := range cases {
		got, err := newTOTP(t, c.cfg, instant).ProvisioningURI(c.secret, c.label)
		if err != nil {
			t.Fatal(err)
		}
		if got != c.want {
			t.Errorf("got  %s\nwant %s", got, c.want)
		}
	}
}

func TestProvisioningURIRejectsWhatOtphpRejects(t *testing.T) {
	p := newTOTP(t, defaults(), instant)
	for _, label := range []string{"", "a:b", "a%3Ab", "a%3ab"} {
		if _, err := p.ProvisioningURI("JBSWY3DPEHPK3PXP", label); err == nil {
			t.Errorf("label %q accepted", label)
		}
	}
}

func TestRejectsAnIssuerWithAColonAtConstruction(t *testing.T) {
	cfg := defaults()
	cfg.Issuer = "Acme:Prod"
	_, err := NewTOTP(cfg, nil)
	if err == nil || !strings.Contains(err.Error(), "auth.otp.totp.issuer") {
		t.Fatalf("err = %v", err)
	}
	cfg.Digits = 0
	if _, err := NewTOTP(cfg, nil); !errors.Is(err, config.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
}

func TestMatchesTheRfc6238Sha1Vector(t *testing.T) {
	// RFC 6238 Appendix B: secret "12345678901234567890", SHA-1, 8 digits, T=59s → 94287082.
	cfg := config.TOTP{Digits: 8, Period: 30 * time.Second, Algorithm: config.SHA1, Window: 0, Issuer: "Univeros"}
	p := newTOTP(t, cfg, time.Unix(59, 0))
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

	step, ok, err := p.Match(secret, "94287082")
	if err != nil || !ok || step != 30 {
		t.Fatalf("Match = %d, %v, %v; want step 30", step, ok, err)
	}
	if _, ok, _ := p.Match(secret, "00000000"); ok {
		t.Fatal("wrong code matched")
	}
}

func TestCodesEqualOtphpForEveryAlgorithm(t *testing.T) {
	// Captured from OTPHP\TOTP::at() for secret JBSWY3DPEHPK3PXP.
	vectors := []struct {
		alg    config.TOTPAlgorithm
		digits int
		period time.Duration
		ts     int64
		code   string
	}{
		{config.SHA1, 6, 30 * time.Second, 59, "996554"},
		{config.SHA1, 6, 30 * time.Second, 1780000000, "895333"},
		{config.SHA256, 8, 30 * time.Second, 59, "36344551"},
		{config.SHA256, 8, 30 * time.Second, 2000000000, "25916370"},
		{config.SHA512, 7, 60 * time.Second, 59, "6582788"},
		{config.SHA512, 7, 60 * time.Second, 1780000000, "2027829"},
	}
	for _, v := range vectors {
		cfg := config.TOTP{Digits: v.digits, Period: v.period, Algorithm: v.alg, Window: 0, Issuer: "Univeros"}
		step, ok, err := newTOTP(t, cfg, time.Unix(v.ts, 0)).Match("JBSWY3DPEHPK3PXP", v.code)
		p := int64(v.period / time.Second)
		if err != nil || !ok || step != v.ts-v.ts%p {
			t.Errorf("%s/%d/%v at %d: Match = %d, %v, %v", v.alg, v.digits, v.period, v.ts, step, ok, err)
		}
	}
}

func TestVerifiesTheCurrentAndInWindowCodesButRejectsOthers(t *testing.T) {
	p := newTOTP(t, defaults(), instant)
	secret := p.GenerateSecret()
	code := func(at time.Time) string {
		c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	matches := func(c string) bool {
		_, ok, err := p.Match(secret, c)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// Window is ±1 step (period 30s): current and adjacent steps verify; two steps out doesn't.
	if !matches(code(instant)) || !matches(code(instant.Add(-30*time.Second))) || !matches(code(instant.Add(30*time.Second))) {
		t.Fatal("in-window codes must match")
	}
	if matches(code(instant.Add(-60 * time.Second))) {
		t.Fatal("two steps back is out of window")
	}
	for _, bad := range []string{"abc", ""} {
		if matches(bad) {
			t.Fatalf("%q matched", bad)
		}
	}
	step, _, _ := p.Match(secret, code(instant.Add(-30*time.Second)))
	if step != instant.Add(-30*time.Second).Unix() {
		t.Fatalf("step = %d", step)
	}
}

func TestSkipsStepsBeforeTheEpoch(t *testing.T) {
	cfg := defaults()
	p := newTOTP(t, cfg, time.Unix(10, 0))
	c, _ := totp.GenerateCodeCustom("JBSWY3DPEHPK3PXP", time.Unix(0, 0), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix})
	if step, ok, err := p.Match("JBSWY3DPEHPK3PXP", c); !ok || err != nil || step != 0 {
		t.Fatalf("Match = %d %v %v", step, ok, err)
	}
}

func TestAnUndecodableSecretIsAnError(t *testing.T) {
	p := newTOTP(t, defaults(), instant)
	if _, _, err := p.Match("not base32!", "123456"); err == nil {
		t.Fatal("want an error, as otphp throws")
	}
}
