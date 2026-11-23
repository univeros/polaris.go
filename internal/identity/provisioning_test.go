package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
)

// Decision 74. Two parties registered an address nobody verified: only the mailbox tells which is
// its owner, so neither password is confirmed by the verification link, in either order, and what
// the earlier registrant held is gone. The owner verifies and sets a password by reset.
func TestTwoRegistrationsOfAnUnverifiedAddressConfirmNeitherPassword(t *testing.T) {
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

		must(t, h.svc.Register(ctx, email, newPassword, "Second", client))
		regs := ofType[event.UserRegistered](h.events)
		if len(regs) != 2 || regs[1].UserID != first.UserID || regs[1].VerificationToken == first.VerificationToken {
			t.Fatalf("the second registration sends its own verification message: %+v", regs)
		}
		if u := h.user(t, email); u.EmailVerifiedAt != nil || u.PasswordHash != nil || u.DisplayName != nil || h.factors(t, email) != 0 ||
			h.refreshes(t, session.RefreshToken) || len(erased) != 1 {
			t.Fatalf("what the first registrant held stayed: %+v, factors %d, plugins asked %v", u, h.factors(t, email), erased)
		}
		isErr(t, h.svc.VerifyEmail(ctx, first.VerificationToken), ErrInvalidVerificationToken)
		if u := h.user(t, email); u.EmailVerifiedAt != nil {
			t.Fatal("the first registrant's link verified the account")
		}
		// Whichever of the two the mailbox's owner is, the link they press confirms no password.
		must(t, h.svc.VerifyEmail(ctx, regs[1].VerificationToken))
		if u := h.user(t, email); u.EmailVerifiedAt == nil || u.PasswordHash != nil {
			t.Fatalf("the link proves the mailbox and nothing else: %+v", u)
		}
		for _, pw := range []string{password, newPassword} {
			if _, err := h.svc.Login(ctx, email, pw, client); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("a registrant's password was confirmed: %v", err)
			}
		}
		const owners = "the owner's own passphrase, set by reset"
		must(t, h.svc.ResetPassword(ctx, h.requestReset(t, email), owners, client))
		if _, err := h.svc.Login(ctx, email, owners, client); err != nil {
			t.Fatalf("the owner's password: %v", err)
		}

		// A verified address answers as before: nothing changes, no message.
		must(t, h.svc.Register(ctx, email, password, "", client))
		if _, err := h.svc.Login(ctx, email, owners, client); err != nil || len(ofType[event.UserRegistered](h.events)) != 2 {
			t.Fatalf("a registration changed a verified account: %v", err)
		}
	})
}

// The same person registering twice (the same password) loses nothing: a new message, and the
// link confirms the registration as before.
func TestRegisteringAgainWithTheSamePasswordKeepsTheRegistration(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		lax := h.auth
		lax.Flows.RequireVerifiedEmail = false
		h.svc = h.service(t, lax)
		first := h.register(t, email)
		session := h.login(t, email)
		h.factor(t, email)
		hashes := h.hasher.hashes.Load() + h.hasher.verifies.Load()

		second := h.register(t, email)
		if h.hasher.hashes.Load()+h.hasher.verifies.Load() != hashes+1 {
			t.Fatal("one Argon2id computation, as on every path (timing parity)")
		}
		isErr(t, h.svc.VerifyEmail(ctx, first), ErrInvalidVerificationToken)
		must(t, h.svc.VerifyEmail(ctx, second))
		if u := h.user(t, email); u.EmailVerifiedAt == nil || u.PasswordHash == nil || h.factors(t, email) != 1 || !h.refreshes(t, session.RefreshToken) {
			t.Fatalf("a confirmed registration lost something: %+v", u)
		}
	})
}

// An account a directory or a provider created has no password: a registration of its address
// changes nothing and stores no password; the message it sends is the mailbox's first proof.
func TestRegisteringAnAddressWithoutAPasswordStoresNone(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.register(t, email)
		h.set(t, email, func(u *model.User) { u.PasswordHash = nil })
		h.factor(t, email)
		verification := h.register(t, email)
		if u := h.user(t, email); u.PasswordHash != nil || u.EmailVerifiedAt != nil || h.factors(t, email) != 1 {
			t.Fatalf("the account changed before anyone proved the mailbox: %+v", u)
		}
		must(t, h.svc.VerifyEmail(ctx, verification))
		if u := h.user(t, email); u.PasswordHash != nil || u.EmailVerifiedAt == nil || h.factors(t, email) != 0 {
			t.Fatalf("the first proof: %+v, factors %d", u, h.factors(t, email))
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
