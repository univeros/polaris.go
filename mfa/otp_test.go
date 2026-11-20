package mfa

// Ports of PHP tests/Mfa/OtpServiceTest and tests/Persistence/OtpServicePersistenceTest, run on
// memstore and SQLite, plus the concurrent-verify race.

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/notify"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
)

const otpInstant = "2026-06-08 12:00:00"

// seedChallenge stores a live login_mfa challenge for factor-1 and code, created at createdAt.
func (h *harness) seedChallenge(t *testing.T, code string, createdAt time.Time) model.OTPChallenge {
	t.Helper()
	now := h.clock.Now()
	c := model.OTPChallenge{
		ID: "challenge-" + code + createdAt.Format("150405"), UserID: "user-1", FactorID: ptr("factor-1"),
		Purpose: string(PurposeLoginMFA), Channel: model.ChannelSMS, CodeHash: ptr(h.pepper.Hash("otp", code)),
		Destination: ptr("+14155550101"), MaxAttempts: model.DefaultMaxAttempts, ExpiresAt: now.Add(5 * time.Minute),
		CreatedAt: createdAt,
	}
	must(t, h.repos.OTPChallenges.Insert(ctx, c))
	return c
}

func (h *harness) challenge(t *testing.T, id string) model.OTPChallenge {
	t.Helper()
	c, err := h.repos.OTPChallenges.Get(ctx, id)
	must(t, err)
	return c
}

var sixDigits = regexp.MustCompile(`\b(\d{6})\b`)

func TestChallengeStoresAHashedCodeSendsSmsAndMasksTheDestination(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		res, err := h.service(t).SendOTP(ctx, "user-1", smsFactor(), PurposeLoginMFA, token.ClientContext{IP: "203.0.113.7"})
		must(t, err)
		if res.Channel != model.ChannelSMS || res.MaskedDestination != "+1 *** *** 0101" || res.ChallengeID == "" {
			t.Fatalf("%+v", res)
		}
		sent := h.sms.Sent()
		if len(sent) != 1 || sent[0].To != "+14155550101" {
			t.Fatalf("%+v", sent)
		}
		m := sixDigits.FindStringSubmatch(sent[0].Message)
		if m == nil || sent[0].Message != "Your verification code is "+m[1]+"." {
			t.Fatalf("message %q", sent[0].Message)
		}
		c := h.challenge(t, res.ChallengeID)
		if *c.CodeHash == m[1] || *c.CodeHash != h.pepper.Hash("otp", m[1]) {
			t.Fatal("only the keyed hash of the code is stored")
		}
		if *c.IP != "203.0.113.7" || *c.FactorID != "factor-1" || c.Purpose != "login_mfa" || c.MaxAttempts != 5 ||
			!c.ExpiresAt.Equal(at(otpInstant).Add(300*time.Second)) || *c.Destination != "+14155550101" {
			t.Fatalf("%+v", c)
		}
		ev := ofType[event.OTPChallengeSent](h.events)
		if len(ev) != 1 || ev[0] != (event.OTPChallengeSent{UserID: "user-1", FactorID: "factor-1", Channel: "sms"}) {
			t.Fatalf("%+v", ev)
		}
	})
}

func TestChallengeRejectsATotpFactor(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	f := model.MFAFactor{ID: "factor-9", UserID: "user-1", Type: model.FactorTOTP}
	if _, err := h.service(t).SendOTP(ctx, "user-1", f, PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal(err)
	}
}

func TestChallengeRejectsAFactorWithoutADestination(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	f := model.MFAFactor{ID: "factor-9", UserID: "user-1", Type: model.FactorSMS}
	if _, err := h.service(t).SendOTP(ctx, "user-1", f, PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal(err)
	}
	if len(h.sms.Sent()) != 0 {
		t.Fatal("nothing is sent")
	}
}

func TestChallengeSendsEmailForAnEmailFactor(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	res, err := h.service(t).SendOTP(ctx, "user-1", emailFactor(), PurposeLoginMFA, token.ClientContext{})
	must(t, err)
	if res.Channel != model.ChannelEmail || res.MaskedDestination != "a***@example.com" {
		t.Fatalf("%+v", res)
	}
	sent := h.mail.Sent()
	if len(sent) != 1 || sent[0].To != "ada@example.com" || sent[0].Template != notify.TemplateOTPCode || sent[0].Data["ttl"] != 300 {
		t.Fatalf("%+v", sent)
	}
	if code, _ := sent[0].Data["code"].(string); len(code) != 6 {
		t.Fatalf("code %v", sent[0].Data["code"])
	}
	if c := h.challenge(t, res.ChallengeID); c.IP != nil {
		t.Fatal("no client IP is stored as NULL")
	}
}

func TestChallengeWithinTheCooldownIsRejected(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		h.seedChallenge(t, "123456", at(otpInstant)) // 0 s ago < 30 s cooldown
		if _, err := h.service(t).SendOTP(ctx, "user-1", smsFactor(), PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, ErrOTPCooldown) {
			t.Fatal(err)
		}
		if len(h.sms.Sent()) != 0 {
			t.Fatal("nothing is sent")
		}
	})
}

func TestChallengeSupersedesAnOlderPendingChallenge(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		old := h.seedChallenge(t, "123456", at("2026-06-08 11:00:00")) // 1 h ago > cooldown
		res, err := h.service(t).SendOTP(ctx, "user-1", smsFactor(), PurposeLoginMFA, token.ClientContext{})
		must(t, err)
		if h.challenge(t, old.ID).ConsumedAt == nil {
			t.Fatal("the older pending challenge is superseded")
		}
		if h.challenge(t, res.ChallengeID).ConsumedAt != nil {
			t.Fatal("the new challenge is live")
		}
	})
}

func TestTheCooldownIgnoresAnExpiredChallenge(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	c := h.seedChallenge(t, "123456", at(otpInstant))
	expired := c
	expired.ExpiresAt = at("2026-06-08 11:59:59")
	must(t, h.repos.OTPChallenges.Update(ctx, c, expired))
	if _, err := h.service(t).SendOTP(ctx, "user-1", smsFactor(), PurposeLoginMFA, token.ClientContext{}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySucceedsAndConsumesTheChallenge(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		c := h.seedChallenge(t, "123456", at("2026-06-08 11:58:00"))
		must(t, h.service(t).VerifyOTP(ctx, "user-1", "factor-1", "123456", PurposeLoginMFA))
		if h.challenge(t, c.ID).ConsumedAt == nil {
			t.Fatal("the challenge is consumed in the database")
		}
	})
}

func TestVerifyOfAConsumedChallengeIsRejected(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		h.seedChallenge(t, "123456", at(otpInstant))
		s := h.service(t)
		must(t, s.VerifyOTP(ctx, "user-1", "factor-1", "123456", PurposeLoginMFA))
		if err := s.VerifyOTP(ctx, "user-1", "factor-1", "123456", PurposeLoginMFA); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal("a verified code cannot be replayed:", err)
		}
	})
}

func TestVerifyWithAWrongCodeIncrementsAttempts(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		c := h.seedChallenge(t, "123456", at(otpInstant))
		if err := h.service(t).VerifyOTP(ctx, "user-1", "factor-1", "000000", PurposeLoginMFA); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal(err)
		}
		got := h.challenge(t, c.ID)
		if got.Attempts != 1 || got.ConsumedAt != nil {
			t.Fatalf("%+v", got)
		}
		failures := ofType[event.OTPVerifyFailed](h.events)
		if len(failures) != 1 || *failures[0].AttemptsLeft != 4 || failures[0].FactorID != "factor-1" {
			t.Fatalf("one of five attempts spent: %+v", failures)
		}
	})
}

func TestVerifyIsRejectedOnceAttemptsAreExhausted(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		c := h.seedChallenge(t, "123456", at(otpInstant))
		s := h.service(t)
		for range 5 {
			if err := s.VerifyOTP(ctx, "user-1", "factor-1", "000000", PurposeLoginMFA); !errors.Is(err, ErrInvalidOTP) {
				t.Fatal(err)
			}
		}
		// Even the correct code is rejected once the attempt budget is spent.
		if err := s.VerifyOTP(ctx, "user-1", "factor-1", "123456", PurposeLoginMFA); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal(err)
		}
		if got := h.challenge(t, c.ID); got.Attempts != 5 || got.ConsumedAt != nil {
			t.Fatalf("%+v", got)
		}
		if n := len(ofType[event.OTPVerifyFailed](h.events)); n != 5 {
			t.Fatalf("%d failure events: the exhausted check emits none", n)
		}
	})
}

func TestVerifyOfAnExpiredChallengeIsRejected(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	h.seedChallenge(t, "123456", at(otpInstant))
	h.clock.Advance(5*time.Minute + time.Second)
	if err := h.service(t).VerifyOTP(ctx, "user-1", "factor-1", "123456", PurposeLoginMFA); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal(err)
	}
}

func TestVerifyIsScopedToThePurpose(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	h.seedChallenge(t, "123456", at(otpInstant))
	if err := h.service(t).VerifyOTP(ctx, "user-1", "factor-1", "123456", PurposeStepUp); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal("a login_mfa code cannot satisfy step_up:", err)
	}
}

func TestVerifyChecksTheNewestChallenge(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	h.seedChallenge(t, "111111", at("2026-06-08 11:58:00"))
	h.seedChallenge(t, "222222", at("2026-06-08 11:59:00"))
	s := h.service(t)
	if err := s.VerifyOTP(ctx, "user-1", "factor-1", "111111", PurposeLoginMFA); !errors.Is(err, ErrInvalidOTP) {
		t.Fatal("only the newest pending challenge is live:", err)
	}
	must(t, s.VerifyOTP(ctx, "user-1", "factor-1", "222222", PurposeLoginMFA))
}

func TestSendQuotaThrottlesRepeatedSendsToADestination(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	s := h.service(t)
	// Distinct factors keep the resend cooldown out of it, isolating the quota (SendMax 5).
	for i := range 5 {
		f := smsFactor()
		f.ID = string(rune('a' + i))
		if _, err := s.SendOTP(ctx, "user-1", f, PurposeLoginMFA, token.ClientContext{}); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := s.SendOTP(ctx, "user-1", smsFactor(), PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, ErrOTPCooldown) {
		t.Fatal(err)
	}
	// Another account sending to the same phone is throttled by the per-destination budget.
	if _, err := s.SendOTP(ctx, "user-2", smsFactor(), PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, ErrOTPCooldown) {
		t.Fatal(err)
	}
	// The same account sending elsewhere is throttled by the per-account budget.
	if _, err := s.SendOTP(ctx, "user-1", emailFactor(), PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, ErrOTPCooldown) {
		t.Fatal(err)
	}
}

func TestSendQuotaWindowResetsAfterItElapses(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	s := h.service(t)
	for i := range 5 {
		f := smsFactor()
		f.ID = string(rune('a' + i))
		_, err := s.SendOTP(ctx, "user-1", f, PurposeLoginMFA, token.ClientContext{})
		must(t, err)
	}
	// The window is anchored on the first send, not the cache TTL: a send past SendWindow (3600 s)
	// opens a fresh window rather than staying blocked.
	h.clock.Set(at("2026-06-08 13:00:01"))
	if _, err := s.SendOTP(ctx, "user-1", smsFactor(), PurposeLoginMFA, token.ClientContext{}); err != nil {
		t.Fatal("a send in a fresh window is allowed:", err)
	}
}

func TestACorruptQuotaEntryOpensAFreshWindow(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	must(t, h.cache.Set(ctx, "otp.send.acct.user-1", []byte("not json"), time.Hour))
	if _, err := h.service(t).SendOTP(ctx, "user-1", smsFactor(), PurposeLoginMFA, token.ClientContext{}); err != nil {
		t.Fatal(err)
	}
}

func TestADeliveryFailureIsReturnedAndNoEventIsSent(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	boom := errors.New("provider down")
	s := h.service(t, func(c *Config) { c.SMS = failingSMS{boom} })
	if _, err := s.SendOTP(ctx, "user-1", smsFactor(), PurposeLoginMFA, token.ClientContext{}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if len(ofType[event.OTPChallengeSent](h.events)) != 0 {
		t.Fatal("no event for an unsent code")
	}
}

type failingSMS struct{ err error }

func (f failingSMS) Send(context.Context, string, string) error { return f.err }

// Persistence ports: the conditional UPDATEs hold when the caller's view of the row is stale.

func TestAWrongCodeCannotPushAttemptsPastTheBudgetWhenTheRowIsStale(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, "2026-06-10 12:00:00")
		c := h.seedChallenge(t, "123456", at("2026-06-10 11:58:00"))
		// Another worker exhausted the budget after this request listed the challenge.
		s := h.service(t, staleAfterRead(db, func() {
			exhausted := c
			exhausted.Attempts = c.MaxAttempts
			must(t, h.repos.OTPChallenges.Update(ctx, c, exhausted))
		}))
		if err := s.VerifyOTP(ctx, "user-1", "factor-1", "000000", PurposeLoginMFA); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal(err)
		}
		if got := h.challenge(t, c.ID); got.Attempts != c.MaxAttempts {
			t.Fatalf("attempts %d: the budget is neither reset nor exceeded", got.Attempts)
		}
	})
}

func TestACorrectCodeCannotConsumeAChallengeAlreadyConsumedConcurrently(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, "2026-06-10 12:00:00")
		c := h.seedChallenge(t, "123456", at("2026-06-10 11:58:00"))
		s := h.service(t, staleAfterRead(db, func() {
			consumed := c
			consumed.ConsumedAt = ptr(at("2026-06-10 12:00:00"))
			must(t, h.repos.OTPChallenges.Update(ctx, c, consumed))
		}))
		if err := s.VerifyOTP(ctx, "user-1", "factor-1", "123456", PurposeLoginMFA); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal(err)
		}
	})
}

func TestConcurrentPresentationsOfOneCodeConsumeItOnce(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		h.seedChallenge(t, "123456", at(otpInstant))
		s := h.service(t)
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 8 {
			wg.Go(func() {
				if s.VerifyOTP(ctx, "user-1", "factor-1", "123456", PurposeLoginMFA) == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d presentations succeeded", wins)
		}
	})
}
