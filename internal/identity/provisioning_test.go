package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
)

// Decision 74. An address registered and never verified is registered again by its owner: the
// account is theirs to confirm, with their password, and what the first registrant held is gone.
func TestASecondRegistrationOfAnUnverifiedAddressTakesItsPlace(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		lax := h.auth
		lax.Flows.RequireVerifiedEmail = false
		h.svc = h.service(t, lax)
		var erased []string
		h.svc.onEmailProven = func(_ context.Context, userID string) error { erased = append(erased, userID); return nil }

		must(t, h.svc.Register(ctx, email, password, "First", client))
		first := ofType[event.UserRegistered](h.events)[0]
		session := h.login(t, email)
		h.factor(t, email)

		must(t, h.svc.Register(ctx, email, newPassword, "", client))
		regs := ofType[event.UserRegistered](h.events)
		if len(regs) != 2 || regs[1].UserID != first.UserID || regs[1].VerificationToken == first.VerificationToken {
			t.Fatalf("the second registration sends its own verification message: %+v", regs)
		}
		if u := h.user(t, email); u.EmailVerifiedAt != nil || u.DisplayName != nil || h.factors(t, email) != 0 ||
			h.refreshes(t, session.RefreshToken) || len(erased) != 1 {
			t.Fatalf("what the first registrant held stayed: %+v, factors %d, plugins asked %v", u, h.factors(t, email), erased)
		}
		isErr(t, h.svc.VerifyEmail(ctx, first.VerificationToken), ErrInvalidVerificationToken)
		if u := h.user(t, email); u.EmailVerifiedAt != nil {
			t.Fatal("the first registrant's link verified the account")
		}
		must(t, h.svc.VerifyEmail(ctx, regs[1].VerificationToken))
		if _, err := h.svc.Login(ctx, email, password, client); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("the first registrant's password was confirmed: %v", err)
		}
		if _, err := h.svc.Login(ctx, email, newPassword, client); err != nil {
			t.Fatalf("the owner's password: %v", err)
		}

		// A verified address answers as before: nothing changes, no message.
		must(t, h.svc.Register(ctx, email, password, "", client))
		if _, err := h.svc.Login(ctx, email, newPassword, client); err != nil || len(ofType[event.UserRegistered](h.events)) != 2 {
			t.Fatalf("a registration changed a verified account: %v", err)
		}
	})
}

// An account a directory or a provider created has no registration to replace: registering its
// address changes nothing (its owner proves the mailbox by reset).
func TestRegisteringAnAddressWithoutAPasswordChangesNothing(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.register(t, email)
		h.set(t, email, func(u *model.User) { u.PasswordHash = nil })
		must(t, h.svc.Register(ctx, email, newPassword, "", client))
		if u := h.user(t, email); u.PasswordHash != nil || len(ofType[event.UserRegistered](h.events)) != 1 {
			t.Fatalf("the account changed: %+v", u)
		}
	})
}

// A verification token confirms the password it was issued with, and no other.
func TestAVerificationTokenConfirmsOnlyThePasswordItWasIssuedWith(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		verification := h.register(t, email)
		other, err := h.hasher.Hash(newPassword)
		must(t, err)
		h.set(t, email, func(u *model.User) { u.PasswordHash = &other })
		isErr(t, h.svc.VerifyEmail(ctx, verification), ErrInvalidVerificationToken)
		if u := h.user(t, email); u.EmailVerifiedAt != nil {
			t.Fatal("verified")
		}
		// A new message is for the password the account has now.
		must(t, h.svc.ResendVerification(ctx, email, client))
		regs := ofType[event.UserRegistered](h.events)
		must(t, h.svc.VerifyEmail(ctx, regs[len(regs)-1].VerificationToken))
	})
}

// A token issued by an earlier release (no binding) keeps verifying.
func TestAVerificationTokenOfAnEarlierReleaseStillVerifies(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.register(t, email)
		u := h.user(t, email)
		rows, err := h.repos.EmailVerifications.ListByUser(ctx, u.ID)
		must(t, err)
		old := rows[0]
		old.TokenHash = h.pepper.Hash(verifyPepperContext, "an-unbound-token-of-an-earlier-release")
		must(t, h.repos.EmailVerifications.Update(ctx, rows[0], old))
		must(t, h.svc.VerifyEmail(ctx, "an-unbound-token-of-an-earlier-release"))
		if u := h.user(t, email); u.EmailVerifiedAt == nil {
			t.Fatal("not verified")
		}
	})
}

// A token sent to an address is for that address: after the account moved to another one, the
// old mailbox's reset and verification tokens are dead.
func TestTokensSentToAnAddressDieWhenTheAccountLeavesIt(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		const moved = "grace@example.com"
		id := h.registerAndVerify(t, email)
		reset := h.requestReset(t, email)

		row, err := h.repos.PasswordResets.ListByUser(ctx, id)
		must(t, err)
		u, err := h.svc.ChangeEmail(ctx, id, moved, false)
		must(t, err)
		if u.Email != moved || u.EmailVerifiedAt != nil {
			t.Fatalf("moved unverified: %+v", u)
		}
		if left, _ := h.repos.PasswordResets.ListByUser(ctx, id); len(left) != 0 {
			t.Fatalf("pending resets survived the move: %d", len(left))
		}
		// A token whose row survived the move (written by an earlier release, or racing it).
		must(t, h.repos.PasswordResets.Insert(ctx, row[0]))
		isErr(t, h.svc.ResetPassword(ctx, reset, newPassword, client), ErrInvalidResetToken)
		if _, err := h.svc.Login(ctx, moved, newPassword, client); err == nil {
			t.Fatal("the old mailbox reset the moved account's password")
		}

		// Back on a vouched address the account is verified again; a taken address is refused.
		if u, err = h.svc.ChangeEmail(ctx, id, email, true); err != nil || u.EmailVerifiedAt == nil {
			t.Fatalf("moved verified: %+v %v", u, err)
		}
		h.register(t, moved)
		if _, err := h.svc.ChangeEmail(ctx, id, moved, true); !errors.Is(err, ErrEmailTaken) {
			t.Fatalf("a taken address: %v", err)
		}
	})
}
