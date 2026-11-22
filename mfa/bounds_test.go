package mfa

import (
	"errors"
	"testing"
	"time"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// The attempt is reserved before the code is compared (decision 69): a request that read the
// challenge before other requests spent its budget does not get a compare beyond the budget.
func TestACorrectCodeIsRefusedWhenTheBudgetWasSpentAfterTheRead(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, "2026-06-10 12:00:00")
		c := h.seedChallenge(t, "123456", at("2026-06-10 11:58:00"))
		s := h.service(t, staleAfterRead(db, func() {
			exhausted := c
			exhausted.Attempts = c.MaxAttempts
			must(t, h.repos.OTPChallenges.Update(ctx, c, exhausted))
		}))
		if err := s.VerifyOTP(ctx, "user-1", "factor-1", "123456", PurposeLoginMFA); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal("a compare beyond the attempt budget:", err)
		}
		if got := h.challenge(t, c.ID); got.ConsumedAt != nil {
			t.Fatal("the challenge was consumed")
		}
	})
}

// Wrong second-factor codes are counted per user (decision 69): after auth.lockout.max_attempts of
// them the gate and step-up refuse every code, a right one and a recovery code included, with the
// answer of a wrong code, until auth.lockout.lock_duration has passed. A code that clears resets
// the count.
func TestRepeatedWrongSecondFactorCodesCloseTheGateForAWhile(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, gateAt)
		h.insertFactor(t, model.MFAFactor{ID: "f-1", Type: model.FactorTOTP, SecretEncrypted: ptr(h.encrypt(t, "JBSWY3DPEHPK3PXP")), ConfirmedAt: ptr(at(gateAt))})
		wrong := h.service(t, withTOTP(0, false))
		recovery := issue(t, wrong, "user-1")
		limit := h.cfg.Auth.Lockout.MaxAttempts
		fail := func(n int) {
			t.Helper()
			for range n {
				if _, err := wrong.VerifyLogin(ctx, "user-1", "f-1", "000000", token.ClientContext{}); !errors.Is(err, ErrInvalidOTP) {
					t.Fatal(err)
				}
			}
		}
		fail(limit - 1)
		if _, err := wrong.VerifyLogin(ctx, "user-1", "", recovery[0], token.ClientContext{}); err != nil {
			t.Fatal("below the limit a right code clears:", err)
		}
		fail(limit - 1) // the success reset the count
		if _, err := wrong.VerifyStepUp(ctx, "user-1", "", "session-1", "f-1", "000000"); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal(err) // step-up failures count with the gate's
		}
		if _, err := wrong.VerifyLogin(ctx, "user-1", "", recovery[1], token.ClientContext{}); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal("a right code after the limit is answered as a wrong one:", err)
		}
		if _, err := wrong.VerifyStepUp(ctx, "user-1", "", "session-1", "", recovery[1]); !errors.Is(err, ErrInvalidOTP) {
			t.Fatal("step-up after the limit:", err)
		}
		if n, _ := wrong.RemainingRecoveryCodes(ctx, "user-1"); n != len(recovery)-1 {
			t.Fatal("a refused attempt spends no recovery code")
		}
		other := issue(t, wrong, "user-2")
		if _, err := wrong.VerifyLogin(ctx, "user-2", "", other[0], token.ClientContext{}); err != nil {
			t.Fatal("another user is counted on its own:", err)
		}
		h.clock.Advance(h.cfg.Auth.Lockout.Duration + time.Second)
		if _, err := wrong.VerifyLogin(ctx, "user-1", "", recovery[1], token.ClientContext{}); err != nil {
			t.Fatal("after the lock a right code clears again:", err)
		}
	})
}
