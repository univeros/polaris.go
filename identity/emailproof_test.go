package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
)

// factor gives address a confirmed MFA factor, as someone holding its session could.
func (h *harness) factor(t *testing.T, address string) {
	t.Helper()
	now := h.clock.Now()
	must(t, h.repos.MFAFactors.Insert(ctx, model.MFAFactor{ID: repository.NewID(), UserID: h.user(t, address).ID, Type: model.FactorTOTP, ConfirmedAt: &now, CreatedAt: now}))
}

func (h *harness) factors(t *testing.T, address string) int {
	t.Helper()
	list, err := h.repos.MFAFactors.ListByUser(ctx, h.user(t, address).ID)
	must(t, err)
	return len(list)
}

// Whoever registered an address without proving it does not keep the account when the mailbox's
// owner resets the password: the reset is the first proof, and what could sign in before goes.
func TestAResetIsTheFirstProofOfAnUnprovenMailbox(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		lax := h.auth
		lax.Flows.RequireVerifiedEmail = false
		h.svc = h.service(t, lax)
		var erased []string
		h.svc.onEmailProven = func(_ context.Context, userID string) error { erased = append(erased, userID); return nil }

		h.register(t, email)
		attacker := h.login(t, email)
		h.factor(t, email)
		must(t, h.svc.ResetPassword(ctx, h.requestReset(t, email), newPassword, client))

		u := h.user(t, email)
		if u.EmailVerifiedAt == nil || h.factors(t, email) != 0 || h.refreshes(t, attacker.RefreshToken) || len(erased) != 1 || erased[0] != u.ID {
			t.Fatalf("verified %v, factors %d, plugins asked %v", u.EmailVerifiedAt != nil, h.factors(t, email), erased)
		}
		if _, err := h.svc.Login(ctx, email, password, client); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("the password set before the proof: %v", err)
		}
		if r, err := h.svc.Login(ctx, email, newPassword, client); err != nil || r.MFA != nil {
			t.Fatalf("the owner signs in with the new password, without the old factor: %+v %v", r, err)
		}
		if n := len(ofType[event.UserEmailVerified](h.events)); n != 1 {
			t.Fatalf("%d verified events", n)
		}

		// A reset of a proven account is a reset: what its owner added stays.
		h.factor(t, email)
		must(t, h.svc.ResetPassword(ctx, h.requestReset(t, email), password, client))
		if h.factors(t, email) != 1 || len(erased) != 1 {
			t.Fatalf("a later reset removed the owner's factor: %d, plugins asked %v", h.factors(t, email), erased)
		}
	})
}

// The verification link confirms the registration that set the password, and keeps what its
// holder has; an account without a password has no registration to confirm.
func TestTheVerificationLinkConfirmsARegistration(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		lax := h.auth
		lax.Flows.RequireVerifiedEmail = false
		h.svc = h.service(t, lax)
		verification := h.register(t, email)
		session := h.login(t, email)
		h.factor(t, email)
		must(t, h.svc.VerifyEmail(ctx, verification))
		if u := h.user(t, email); u.EmailVerifiedAt == nil || u.PasswordHash == nil || h.factors(t, email) != 1 || !h.refreshes(t, session.RefreshToken) {
			t.Fatalf("a confirmed registration lost something: %+v", u)
		}
		must(t, h.svc.VerifyEmail(ctx, verification)) // idempotent

		const other = "grace@example.com"
		h.register(t, other)
		h.set(t, other, func(u *model.User) { u.PasswordHash = nil }) // as an account a provider created
		h.factor(t, other)
		must(t, h.svc.ResendVerification(ctx, other, client))
		regs := ofType[event.UserRegistered](h.events)
		must(t, h.svc.VerifyEmail(ctx, regs[len(regs)-1].VerificationToken))
		if u := h.user(t, other); u.EmailVerifiedAt == nil || h.factors(t, other) != 0 {
			t.Fatalf("no password, nothing to confirm: the factor stayed (%d)", h.factors(t, other))
		}
	})
}

// A failure of what the plugins remove leaves the account unproven and untouched.
func TestAFailedFirstProofChangesNothing(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.register(t, email)
		h.factor(t, email)
		down := errors.New("plugin store down")
		h.svc.onEmailProven = func(context.Context, string) error { return down }
		_, first, err := h.svc.ProveEmail(ctx, h.user(t, email).ID, false)
		if !errors.Is(err, down) || first {
			t.Fatalf("%v %v", first, err)
		}
		if u := h.user(t, email); u.EmailVerifiedAt != nil || u.PasswordHash == nil || h.factors(t, email) != 1 {
			t.Fatalf("half a proof: %+v, factors %d", u, h.factors(t, email))
		}
	})
}
