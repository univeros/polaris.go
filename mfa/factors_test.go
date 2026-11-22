package mfa

// Factor confirmation and TOTP enrollment, plus the sms/email enrollment flow, run on memstore and
// SQLite.

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

func pendingSMS() model.MFAFactor {
	return model.MFAFactor{ID: "factor-1", UserID: "user-1", Type: model.FactorSMS, PhoneE164: ptr("+14155550101")}
}

func TestFirstConfirmationConfirmsIssuesCodesSetsDefaultAndEmits(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		f := h.insertFactor(t, pendingSMS())
		s := h.service(t)
		res, err := s.ConfirmFactor(ctx, f)
		must(t, err)
		if len(res.RecoveryCodes) != RecoveryCodeCount || remaining(t, s, "user-1") != RecoveryCodeCount {
			t.Fatalf("%d codes", len(res.RecoveryCodes))
		}
		got := h.factor(t, f.ID)
		if got.ConfirmedAt == nil || !got.ConfirmedAt.Equal(at(otpInstant)) || !got.IsDefault {
			t.Fatalf("%+v", got)
		}
		ev := ofType[event.MFAEnrolled](h.events)
		if len(ev) != 1 || ev[0].FactorID != f.ID || *ev[0].Type != "sms" {
			t.Fatalf("%+v", ev)
		}
	})
}

func TestSubsequentConfirmationConfirmsButIssuesNothing(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		h.insertFactor(t, model.MFAFactor{ID: "factor-0", Type: model.FactorTOTP, ConfirmedAt: ptr(at("2026-06-01 00:00:00"))})
		f := h.insertFactor(t, pendingSMS())
		s := h.service(t)
		res, err := s.ConfirmFactor(ctx, f)
		must(t, err)
		if res.RecoveryCodes == nil || len(res.RecoveryCodes) != 0 || remaining(t, s, "user-1") != 0 {
			t.Fatalf("%v", res.RecoveryCodes)
		}
		if got := h.factor(t, f.ID); got.ConfirmedAt == nil || got.IsDefault {
			t.Fatalf("only the first factor becomes default: %+v", got)
		}
		if len(ofType[event.MFAEnrolled](h.events)) != 0 {
			t.Fatal("no event")
		}
	})
}

func TestConfirmResultRedactsTheCodes(t *testing.T) {
	r := ConfirmResult{RecoveryCodes: []string{"aaaaa-bbbbb"}}
	for _, s := range []string{r.String(), r.GoString(), r.LogValue().String()} {
		if strings.Contains(s, "aaaaa") {
			t.Fatalf("leaked: %s", s)
		}
	}
}

// TOTP: confirm and verify.

func (h *harness) totpFactor(t *testing.T, userID string, typ string) model.MFAFactor {
	t.Helper()
	return h.insertFactor(t, model.MFAFactor{ID: "factor-1", UserID: userID, Type: typ, SecretEncrypted: ptr(h.encrypt(t, "JBSWY3DPEHPK3PXP"))})
}

func (h *harness) encrypt(t *testing.T, s string) string {
	t.Helper()
	out, err := h.cfg.Encrypter.Encrypt(s)
	must(t, err)
	return out
}

func withTOTP(step int64, ok bool) func(*Config) {
	return func(c *Config) { c.TOTP = stubTOTP{step: step, ok: ok} }
}

func TestTOTPConfirmAndVerifyRejectUnknownForeignAndNonTOTPFactors(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	h.insertFactor(t, model.MFAFactor{ID: "foreign", UserID: "someone-else", Type: model.FactorTOTP, SecretEncrypted: ptr("x")})
	h.insertFactor(t, model.MFAFactor{ID: "sms", Type: model.FactorSMS, PhoneE164: ptr("+14155550101")})
	s := h.service(t)
	for _, id := range []string{"missing", "foreign", "sms"} {
		if _, err := s.ConfirmTOTP(ctx, "user-1", id, "123456"); !errors.Is(err, ErrFactorNotFound) {
			t.Errorf("confirm %s: %v", id, err)
		}
		if err := s.verifyTOTP(ctx, "user-1", id, "123456"); !errors.Is(err, ErrFactorNotFound) {
			t.Errorf("verify %s: %v", id, err)
		}
	}
}

func TestTOTPConfirmRejectsAnInvalidCode(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	h.totpFactor(t, "user-1", model.FactorTOTP)
	if _, err := h.service(t, withTOTP(0, false)).ConfirmTOTP(ctx, "user-1", "factor-1", "000000"); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal(err)
	}
}

func TestTOTPRejectsAReplayedStep(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		f := h.totpFactor(t, "user-1", model.FactorTOTP)
		used := f
		used.LastUsedAt = ptr(time.Unix(1000, 0).UTC())
		must(t, h.repos.MFAFactors.Update(ctx, f, used))
		// The matched step equals the last-used step: a replay.
		s := h.service(t, withTOTP(1000, true))
		if _, err := s.ConfirmTOTP(ctx, "user-1", "factor-1", "123456"); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal(err)
		}
		if err := s.verifyTOTP(ctx, "user-1", "factor-1", "123456"); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal(err)
		}
		// An earlier step is a replay too.
		if err := h.service(t, withTOTP(970, true)).verifyTOTP(ctx, "user-1", "factor-1", "123456"); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal(err)
		}
	})
}

func TestADecryptFailureIsTreatedAsAnInvalidCode(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	h.totpFactor(t, "user-1", model.FactorTOTP)
	s := h.service(t, func(c *Config) { c.Encrypter = failingEncrypter{} })
	if _, err := s.ConfirmTOTP(ctx, "user-1", "factor-1", "123456"); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal(err)
	}
}

func TestFirstTOTPConfirmationConfirmsIssuesCodesAndEmitsTheEvent(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		h.totpFactor(t, "user-1", model.FactorTOTP)
		res, err := h.service(t).ConfirmTOTP(ctx, "user-1", "factor-1", "123456")
		must(t, err)
		got := h.factor(t, "factor-1")
		if len(res.RecoveryCodes) != RecoveryCodeCount || got.ConfirmedAt == nil || !got.IsDefault || got.LastUsedAt.Unix() != 5000 {
			t.Fatalf("%+v", got)
		}
		if len(ofType[event.MFAEnrolled](h.events)) != 1 {
			t.Fatal("event")
		}
	})
}

func TestSecondTOTPConfirmationIssuesNoCodesOrEvent(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	h.insertFactor(t, model.MFAFactor{ID: "factor-0", Type: model.FactorSMS, ConfirmedAt: ptr(at("2026-06-01 00:00:00"))})
	h.totpFactor(t, "user-1", model.FactorTOTP)
	res, err := h.service(t).ConfirmTOTP(ctx, "user-1", "factor-1", "123456")
	must(t, err)
	if len(res.RecoveryCodes) != 0 || h.factor(t, "factor-1").ConfirmedAt == nil || len(ofType[event.MFAEnrolled](h.events)) != 0 {
		t.Fatal("a second factor is confirmed without codes or event")
	}
}

func TestTOTPVerifyFencesTheStepWithoutReconfirmingOrIssuingCodes(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		f := h.insertFactor(t, model.MFAFactor{ID: "factor-1", Type: model.FactorTOTP, SecretEncrypted: ptr(h.encrypt(t, "JBSWY3DPEHPK3PXP")),
			ConfirmedAt: ptr(time.Unix(100, 0).UTC()), IsDefault: true})
		h.clock.Advance(time.Minute)
		s := h.service(t)
		must(t, s.verifyTOTP(ctx, "user-1", f.ID, "123456"))
		got := h.factor(t, f.ID)
		if got.LastUsedAt.Unix() != 5000 || got.ConfirmedAt.Unix() != 100 || !got.UpdatedAt.Equal(at(otpInstant).Add(time.Minute)) {
			t.Fatalf("%+v", got)
		}
		if remaining(t, s, "user-1") != 0 || len(ofType[event.MFAEnrolled](h.events)) != 0 {
			t.Fatal("login verify is not an enrollment")
		}
	})
}

func TestEnrollTOTPStoresAnEncryptedSecretAndReturnsTheProvisioning(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		provider, err := NewTOTP(h.cfg.Auth.OTP.TOTP, h.clock)
		must(t, err)
		s := h.service(t, func(c *Config) { c.TOTP = provider })
		res, err := s.EnrollTOTP(ctx, model.User{ID: "user-1", Email: "ada@example.com"})
		must(t, err)
		if !strings.HasPrefix(res.OTPAuthURI, "otpauth://totp/Univeros%3Aada%40example.com?issuer=Univeros&secret="+res.Secret) ||
			!strings.Contains(res.QRSVG, "<svg") || len(res.Secret) != 32 {
			t.Fatalf("%+v", res)
		}
		got := h.factor(t, res.FactorID)
		if got.Type != model.FactorTOTP || got.ConfirmedAt != nil || got.IsDefault || *got.SecretEncrypted == res.Secret {
			t.Fatalf("%+v", got)
		}
		if plain, err := h.cfg.Encrypter.Decrypt(*got.SecretEncrypted); err != nil || plain != res.Secret {
			t.Fatal("the secret is stored encrypted")
		}
		for _, out := range []string{res.String(), res.GoString(), res.LogValue().String()} {
			if strings.Contains(out, res.Secret) {
				t.Fatalf("leaked: %s", out)
			}
		}

		// The real provider end to end: the app's current code confirms the factor, once.
		code, err := totp.GenerateCode(res.Secret, h.clock.Now())
		must(t, err)
		confirmed, err := s.ConfirmTOTP(ctx, "user-1", res.FactorID, code)
		must(t, err)
		if len(confirmed.RecoveryCodes) != RecoveryCodeCount {
			t.Fatal("first factor")
		}
		if err := s.verifyTOTP(ctx, "user-1", res.FactorID, code); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal("the confirming code cannot be replayed:", err)
		}
	})
}

func TestEnrollTOTPRefusesAnAccountLabelWithAColonBeforeStoringAnything(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	provider, err := NewTOTP(h.cfg.Auth.OTP.TOTP, h.clock)
	must(t, err)
	if _, err := h.service(t, func(c *Config) { c.TOTP = provider }).EnrollTOTP(ctx, model.User{ID: "user-1", Email: "a:b@example.com"}); err == nil {
		t.Fatal("want an error")
	}
	if fs, _ := h.repos.MFAFactors.ListByUser(ctx, "user-1"); len(fs) != 0 {
		t.Fatal("no orphan factor")
	}
}

// SMS / email factors (OtpFactorService).

func TestEnrollOTPFactorCreatesAPendingFactorAndSendsTheEnrollCode(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		s := h.service(t)
		user := model.User{ID: "user-1", Email: "ada@example.com"}
		res, err := s.EnrollOTPFactor(ctx, user, model.FactorSMS, "+14155550101", token.ClientContext{})
		must(t, err)
		if res.Channel != "sms" || res.MaskedDestination != "+1 *** *** 0101" {
			t.Fatalf("%+v", res)
		}
		f := h.factor(t, res.FactorID)
		if f.ConfirmedAt != nil || *f.PhoneE164 != "+14155550101" || f.Email != nil {
			t.Fatalf("%+v", f)
		}
		code := sixDigits.FindStringSubmatch(h.sms.Sent()[0].Message)[1]

		// Re-enrolling replaces the still-pending factor of that channel.
		h.clock.Advance(time.Minute)
		again, err := s.EnrollOTPFactor(ctx, user, model.FactorSMS, "+14155550199", token.ClientContext{})
		must(t, err)
		if fs, _ := h.repos.MFAFactors.ListByUserAndType(ctx, "user-1", model.FactorSMS); len(fs) != 1 || fs[0].ID != again.FactorID {
			t.Fatalf("%+v", fs)
		}
		if _, err := s.ConfirmOTPFactor(ctx, "user-1", res.FactorID, code); !errors.Is(err, ErrFactorNotFound) {
			t.Fatal("the replaced factor is gone:", err)
		}

		newCode := sixDigits.FindStringSubmatch(h.sms.Sent()[1].Message)[1]
		if _, err := s.ConfirmOTPFactor(ctx, "user-1", again.FactorID, "x"+newCode); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal(err)
		}
		confirmed, err := s.ConfirmOTPFactor(ctx, "user-1", again.FactorID, newCode)
		must(t, err)
		got := h.factor(t, again.FactorID)
		if len(confirmed.RecoveryCodes) != RecoveryCodeCount || got.ConfirmedAt == nil || !got.IsDefault ||
			got.LastUsedAt == nil || !got.LastUsedAt.Equal(h.clock.Now()) {
			t.Fatalf("%+v", got)
		}
	})
}

func TestEnrollOTPFactorForEmail(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	res, err := h.service(t).EnrollOTPFactor(ctx, model.User{ID: "user-1"}, model.FactorEmail, "ada@example.com", token.ClientContext{})
	must(t, err)
	if f := h.factor(t, res.FactorID); *f.Email != "ada@example.com" || f.PhoneE164 != nil || res.MaskedDestination != "a***@example.com" {
		t.Fatalf("%+v", f)
	}
}

func TestEnrollOTPFactorRefusesOtherTypes(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	if _, err := h.service(t).EnrollOTPFactor(ctx, model.User{ID: "user-1"}, model.FactorTOTP, "x", token.ClientContext{}); err == nil {
		t.Fatal("want an error")
	}
}

func TestConfirmOTPFactorRejectsForeignAndTOTPFactors(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	h.insertFactor(t, model.MFAFactor{ID: "foreign", UserID: "someone-else", Type: model.FactorSMS})
	h.insertFactor(t, model.MFAFactor{ID: "totp", Type: model.FactorTOTP})
	s := h.service(t)
	for _, id := range []string{"missing", "foreign", "totp"} {
		if _, err := s.ConfirmOTPFactor(ctx, "user-1", id, "123456"); !errors.Is(err, ErrFactorNotFound) {
			t.Errorf("%s: %v", id, err)
		}
	}
}

func TestConcurrentUsesOfOneTOTPCodePassOnce(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		for _, last := range []*time.Time{nil, ptr(time.Unix(4970, 0).UTC())} {
			h := newHarness(t, db, otpInstant)
			id := repository.NewID()
			h.insertFactor(t, model.MFAFactor{ID: id, Type: model.FactorTOTP, SecretEncrypted: ptr(h.encrypt(t, "JBSWY3DPEHPK3PXP")),
				ConfirmedAt: ptr(at(otpInstant)), LastUsedAt: last})
			s := h.service(t) // every code matches step 5000
			var wins atomic.Int32
			var wg sync.WaitGroup
			for range 8 {
				wg.Go(func() {
					if s.verifyTOTP(ctx, "user-1", id, "123456") == nil {
						wins.Add(1)
					}
				})
			}
			wg.Wait()
			if wins.Load() != 1 || h.factor(t, id).LastUsedAt.Unix() != 5000 {
				t.Fatalf("last %v: %d uses passed", last, wins.Load())
			}
		}
	})
}
