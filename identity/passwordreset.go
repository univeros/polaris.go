package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

const (
	resetPepperContext = "password_reset"
	resetTTL           = time.Hour // shorter than email verification by design
)

// ForgotPassword opens a reset challenge for a known, active account, superseding the outstanding
// ones, and dispatches event.PasswordResetRequested carrying the plaintext token for the mailer
// For anyone else it does nothing: the caller answers the same generic
// 202 either way. (The known path does a little more work; the forgot rate limit covers that
// residual delta.)
func (s *Service) ForgotPassword(ctx context.Context, email string, client token.ClientContext) error {
	user, err := s.repos.Users.ByEmail(ctx, NormalizeEmail(email))
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("identity: forgot password: %w", err)
	}
	if user.Status != model.UserStatusActive {
		return nil
	}
	now := s.now()
	secret := newSecret()
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		pending, err := s.repos.PasswordResets.ListByUser(ctx, user.ID)
		if err != nil {
			return err
		}
		for _, c := range pending {
			if c.ConsumedAt == nil {
				consumed := c
				consumed.ConsumedAt = &now
				if err := s.repos.PasswordResets.Update(ctx, c, consumed); err != nil {
					return err
				}
			}
		}
		return s.repos.PasswordResets.Insert(ctx, model.PasswordReset{
			ID: repository.NewID(), UserID: user.ID, Email: user.Email,
			TokenHash: s.pepper.Hash(resetPepperContext, secret), ExpiresAt: now.Add(resetTTL),
			IP: optional(client.IP), CreatedAt: now,
		})
	})
	if err != nil {
		return fmt.Errorf("identity: forgot password: %w", err)
	}
	s.events.Dispatch(ctx, event.PasswordResetRequested{UserID: user.ID, Email: user.Email, ResetToken: secret})
	return nil
}

// ResetPassword sets a new password from a reset token, clears any lockout (proving control of
// the email is a legitimate recovery), consumes the token, revokes every session (reason
// password_change) and dispatches event.PasswordChanged. The token proves the mailbox: an
// unverified account becomes verified, as a first proof (ProveEmail).
//
// A new password failing the policy returns a *PasswordError (checked first). An unknown,
// consumed or expired token, or a disabled account, returns ErrInvalidResetToken: a disabled
// account cannot re-enable itself through a reset.
func (s *Service) ResetPassword(ctx context.Context, secret, newPassword string, client token.ClientContext) error {
	if err := s.policy.enforce(ctx, newPassword); err != nil {
		return err
	}
	now := s.now()
	challenge, err := s.repos.PasswordResets.ByTokenHash(ctx, s.pepper.Hash(resetPepperContext, secret))
	if errors.Is(err, repository.ErrNotFound) {
		return refuse(ErrInvalidResetToken, msgBadReset)
	}
	if err != nil {
		return fmt.Errorf("identity: reset password: %w", err)
	}
	if challenge.ConsumedAt != nil || !challenge.ExpiresAt.After(now) {
		return refuse(ErrInvalidResetToken, msgBadReset)
	}
	user, err := s.repos.Users.Get(ctx, challenge.UserID)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && user.Status == model.UserStatusDisabled) {
		return refuse(ErrInvalidResetToken, msgBadReset)
	}
	if err != nil {
		return fmt.Errorf("identity: reset password: %w", err)
	}

	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("identity: reset password: %w", err)
	}
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		// Single use under concurrency too: only the request that flips consumed_at goes on.
		claimed, err := s.db.Update(ctx, "auth_password_resets",
			store.Criteria{"id": challenge.ID, "consumed_at": nil},
			store.Data{"consumed_at": now.Truncate(time.Second)})
		if err != nil {
			return err
		}
		if claimed != 1 {
			return refuse(ErrInvalidResetToken, msgBadReset)
		}
		// The token came through the mailbox: for an account nobody had proven it is the first
		// proof, and what could sign in before goes with the old password.
		proven, _, err := s.ProveEmail(ctx, user.ID, false)
		if err != nil {
			return err
		}
		next := clearLockout(proven)
		next.PasswordHash, next.UpdatedAt = &hash, now
		return s.repos.Users.Update(ctx, proven, next)
	})
	if errors.Is(err, ErrInvalidResetToken) {
		return err
	}
	if err != nil {
		return fmt.Errorf("identity: reset password: %w", err)
	}
	if _, err := s.sessions.RevokeAll(ctx, user.ID, model.RevokedPasswordChange); err != nil {
		return fmt.Errorf("identity: reset password: %w", err)
	}
	s.events.Dispatch(ctx, event.PasswordChanged{UserID: user.ID, Method: event.PasswordMethodReset})
	return nil
}

// ChangePassword replaces the password of an authenticated user who proved the current one,
// clears any lockout, revokes every other session (currentSessionID is kept; "" keeps none) with
// reason password_change and dispatches event.PasswordChanged.
//
// A wrong current password (or an unknown or passwordless user) returns ErrInvalidCredentials,
// a disabled account ErrAccountDisabled, a new password failing the policy a *PasswordError.
func (s *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword, currentSessionID string) error {
	user, err := s.repos.Users.Get(ctx, userID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("identity: change password: %w", err)
	}
	if err != nil || user.PasswordHash == nil || !s.hasher.Verify(currentPassword, *user.PasswordHash) {
		return refuse(ErrInvalidCredentials, msgWrongPassword)
	}
	if user.Status == model.UserStatusDisabled {
		return refuse(ErrAccountDisabled, msgDisabled)
	}
	if err := s.policy.enforce(ctx, newPassword); err != nil {
		return err
	}

	hash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("identity: change password: %w", err)
	}
	next := clearLockout(user)
	next.PasswordHash, next.UpdatedAt = &hash, s.now()
	if err := s.repos.Users.Update(ctx, user, next); err != nil {
		return fmt.Errorf("identity: change password: %w", err)
	}
	if _, err := s.sessions.RevokeAllExcept(ctx, user.ID, currentSessionID, model.RevokedPasswordChange); err != nil {
		return fmt.Errorf("identity: change password: %w", err)
	}
	s.events.Dispatch(ctx, event.PasswordChanged{UserID: user.ID, Method: event.PasswordMethodChange})
	return nil
}
