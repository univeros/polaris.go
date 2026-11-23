package identity

// The password reset service (the password endpoints, service side).

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
)

func TestForgotIsGenericAndNotifiesAKnownUser(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		id := h.registerAndVerify(t, email)
		secret := h.requestReset(t, " ADA@example.com")

		resets := ofType[event.PasswordResetRequested](h.events)
		if len(resets) != 1 || resets[0].UserID != id || resets[0].Email != email || len(secret) != 43 {
			t.Fatalf("reset requested %+v", resets)
		}
		rows, err := h.repos.PasswordResets.ListByUser(ctx, id)
		must(t, err)
		if len(rows) != 1 || rows[0].TokenHash != h.pepper.Hash("password_reset", secret) ||
			!rows[0].ExpiresAt.Equal(start.Add(time.Hour)) || *rows[0].IP != client.IP || rows[0].ConsumedAt != nil {
			t.Fatalf("challenge %+v", rows)
		}
	})
}

// A lock stops password sign-ins, never the mailbox's way back in.
func TestALockedAccountIsSentAReset(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		for range 5 {
			_, _ = h.svc.Login(ctx, email, "wrong", client)
		}
		if u := h.user(t, email); u.Status != model.UserStatusLocked {
			t.Fatalf("user %+v", u)
		}
		h.resetTo(t, newPassword)
		if _, err := h.svc.Login(ctx, email, newPassword, client); err != nil {
			t.Fatalf("login after the reset: %v", err)
		}
	})
}

func TestForgotIsGenericForAnUnknownOrDisabledAccount(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		must(t, h.svc.ForgotPassword(ctx, "nobody@example.com", client))
		h.registerAndVerify(t, email)
		h.set(t, email, func(u *model.User) { u.Status = model.UserStatusDisabled })
		must(t, h.svc.ForgotPassword(ctx, email, client))
		if n := len(ofType[event.PasswordResetRequested](h.events)); n != 0 {
			t.Fatalf("reset requested events %d", n)
		}
	})
}

func TestResetChangesThePasswordAndRevokesEverySession(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		session := h.login(t, email)
		secret := h.requestReset(t, email)

		must(t, h.svc.ResetPassword(ctx, secret, newPassword, client))
		changed := ofType[event.PasswordChanged](h.events)
		if len(changed) != 1 || changed[0].Method != event.PasswordMethodReset {
			t.Fatalf("password changed %+v", changed)
		}
		if h.refreshes(t, session.RefreshToken) {
			t.Fatal("a session survived the reset")
		}
		rows, _ := h.repos.RefreshTokens.ListByFamily(ctx, session.SessionID)
		if *rows[0].RevokedReason != model.RevokedPasswordChange {
			t.Fatalf("revoked reason %v", *rows[0].RevokedReason)
		}
		_, err := h.svc.Login(ctx, email, password, client)
		isErr(t, err, ErrInvalidCredentials)
		_, err = h.svc.Login(ctx, email, newPassword, client)
		must(t, err)
	})
}

func TestResetRejectsAShortPasswordAndABadToken(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		secret := h.requestReset(t, email)

		isErr(t, h.svc.ResetPassword(ctx, secret, "short", client), ErrInvalidPassword)
		err := h.svc.ResetPassword(ctx, "not-a-token", newPassword, client)
		isErr(t, err, ErrInvalidResetToken)
		if err.Error() != "The reset token is invalid or expired." {
			t.Fatal(err)
		}
		// The policy failure did not spend the token.
		must(t, h.svc.ResetPassword(ctx, secret, newPassword, client))
	})
}

func TestAResetTokenCannotBeReplayed(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		secret := h.requestReset(t, email)
		must(t, h.svc.ResetPassword(ctx, secret, newPassword, client))
		isErr(t, h.svc.ResetPassword(ctx, secret, "yet another passphrase", client), ErrInvalidResetToken)
	})
}

func TestAResetTokenIsSingleUseUnderConcurrency(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		secret := h.requestReset(t, email)

		var wg sync.WaitGroup
		errs := make([]error, 4)
		for i := range errs {
			wg.Go(func() { errs[i] = h.svc.ResetPassword(ctx, secret, newPassword, client) })
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, ErrInvalidResetToken) {
				t.Fatal(err)
			}
		}
		if ok != 1 {
			t.Fatalf("%d resets succeeded", ok)
		}
	})
}

func TestResetTokenExpiryAndSupersession(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		first := h.requestReset(t, email)
		second := h.requestReset(t, email)
		isErr(t, h.svc.ResetPassword(ctx, first, newPassword, client), ErrInvalidResetToken)

		h.clock.Advance(time.Hour)
		isErr(t, h.svc.ResetPassword(ctx, second, newPassword, client), ErrInvalidResetToken)
	})
}

func TestResetRecoversALockedAccountButNotADisabledOne(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		h.registerAndVerify(t, email)
		secret := h.requestReset(t, email)
		for range 5 {
			_, _ = h.svc.Login(ctx, email, "wrong", client)
		}
		must(t, h.svc.ResetPassword(ctx, secret, newPassword, client))
		if u := h.user(t, email); u.Status != model.UserStatusActive || u.LockedUntil != nil || u.FailedLoginCount != 0 {
			t.Fatalf("user %+v", u)
		}

		secret = h.requestReset(t, email)
		h.set(t, email, func(u *model.User) { u.Status = model.UserStatusDisabled })
		isErr(t, h.svc.ResetPassword(ctx, secret, "yet another passphrase", client), ErrInvalidResetToken)
		if u := h.user(t, email); u.Status != model.UserStatusDisabled {
			t.Fatalf("user %+v", u)
		}
	})
}

func TestChangeKeepsTheCurrentSessionAndRevokesTheRest(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		id := h.registerAndVerify(t, email)
		current := h.login(t, email)
		other := h.login(t, email)
		for range 2 {
			_, _ = h.svc.Login(ctx, email, "wrong", client)
		}

		must(t, h.svc.ChangePassword(ctx, id, password, newPassword, current.SessionID))
		if !h.refreshes(t, current.RefreshToken) || h.refreshes(t, other.RefreshToken) {
			t.Fatal("only the current session survives")
		}
		changed := ofType[event.PasswordChanged](h.events)
		if len(changed) != 1 || changed[0].Method != event.PasswordMethodChange {
			t.Fatalf("password changed %+v", changed)
		}
		if u := h.user(t, email); u.FailedLoginCount != 0 || u.FailedLoginAt != nil {
			t.Fatalf("user %+v", u)
		}
		_, err := h.svc.Login(ctx, email, newPassword, client)
		must(t, err)
	})
}

func TestChangeRefusals(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		id := h.registerAndVerify(t, email)

		err := h.svc.ChangePassword(ctx, id, "wrong-password", newPassword, "")
		isErr(t, err, ErrInvalidCredentials)
		if err.Error() != "The current password is incorrect." {
			t.Fatal(err)
		}
		isErr(t, h.svc.ChangePassword(ctx, id, password, "short", ""), ErrInvalidPassword)
		isErr(t, h.svc.ChangePassword(ctx, "unknown", password, newPassword, ""), ErrInvalidCredentials)

		h.set(t, email, func(u *model.User) { u.Status = model.UserStatusDisabled })
		isErr(t, h.svc.ChangePassword(ctx, id, password, newPassword, ""), ErrAccountDisabled)

		h.set(t, email, func(u *model.User) { u.PasswordHash = nil })
		isErr(t, h.svc.ChangePassword(ctx, id, password, newPassword, ""), ErrInvalidCredentials)
		if n := len(ofType[event.PasswordChanged](h.events)); n != 0 {
			t.Fatalf("password changed events %d", n)
		}
	})
}
