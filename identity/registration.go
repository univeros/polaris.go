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

// errTaken aborts a registration whose insert hit the unique email index.
var errTaken = errors.New("identity: email taken")

const (
	verifyPepperContext = "email_verify"
	verifyTTL           = 24 * time.Hour
)

// Register creates an unverified account with an Argon2id hash, opens an email-verification
// challenge and dispatches event.UserRegistered carrying the plaintext token for the mailer
// displayName "" stores none.
//
// A password failing the policy returns a *PasswordError. A taken email returns nil without
// creating anything or dispatching an event, after hashing the password anyway, so the response
// and its timing match the account-created path. That includes losing a race with a concurrent
// registration of the same address (the unique index refuses the second insert).
func (s *Service) Register(ctx context.Context, email, password, displayName string, client token.ClientContext) error {
	if err := s.policy.enforce(ctx, password); err != nil {
		return err
	}
	email = NormalizeEmail(email)
	_, err := s.repos.Users.ByEmail(ctx, email)
	if err == nil {
		_, _ = s.hasher.Hash(password) // timing parity with the create path; the result is unused
		return nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("identity: register: %w", err)
	}

	hash, err := s.hasher.Hash(password)
	if err != nil {
		return fmt.Errorf("identity: register: %w", err)
	}
	now := s.now()
	user := model.User{
		ID: repository.NewID(), Email: email, PasswordHash: &hash, DisplayName: optional(displayName),
		Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now,
	}
	var secret string
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.InsertUser(ctx, user); errors.Is(err, store.ErrDuplicate) {
			return errTaken
		} else if err != nil {
			return err
		}
		secret, err = s.insertVerification(ctx, user, client, now)
		return err
	})
	if errors.Is(err, errTaken) {
		return nil // lost a race with a registration of the same address: the taken path, hash spent
	}
	if err != nil {
		return fmt.Errorf("identity: register: %w", err)
	}
	s.events.Dispatch(ctx, event.UserRegistered{UserID: user.ID, Email: user.Email, VerificationToken: secret})
	return nil
}

// VerifyEmail confirms an email address from its token (ProveEmail, confirming the registration)
// and dispatches event.UserEmailVerified.
// It is idempotent: a token that matched a real challenge succeeds again
// once the user is verified, even consumed or expired. Otherwise an unknown, consumed or expired
// token returns ErrInvalidVerificationToken.
func (s *Service) VerifyEmail(ctx context.Context, secret string) error {
	challenge, err := s.repos.EmailVerifications.ByTokenHash(ctx, s.pepper.Hash(verifyPepperContext, secret))
	if errors.Is(err, repository.ErrNotFound) {
		return refuse(ErrInvalidVerificationToken, msgBadVerification)
	}
	if err != nil {
		return fmt.Errorf("identity: verify email: %w", err)
	}
	user, err := s.repos.Users.Get(ctx, challenge.UserID)
	if errors.Is(err, repository.ErrNotFound) {
		return refuse(ErrInvalidVerificationToken, msgBadVerification)
	}
	if err != nil {
		return fmt.Errorf("identity: verify email: %w", err)
	}
	// Idempotency precedes the validity check on purpose: a second click presents a consumed
	// token and must still succeed. The token still had to match a real challenge.
	if user.EmailVerifiedAt != nil {
		return nil
	}
	now := s.now()
	if challenge.ConsumedAt != nil || !challenge.ExpiresAt.After(now) {
		return refuse(ErrInvalidVerificationToken, msgExpiredVerify)
	}

	consumed := challenge
	consumed.ConsumedAt = &now
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.repos.EmailVerifications.Update(ctx, challenge, consumed); err != nil {
			return err
		}
		// The link confirms the registration that set the password; an account without one (it
		// was not created by registering) is the mailbox owner's from here.
		_, _, err := s.ProveEmail(ctx, user.ID, true)
		return err
	})
	if err != nil {
		return fmt.Errorf("identity: verify email: %w", err)
	}
	return nil
}

// ResendVerification reissues a verification challenge for a known, unverified user, superseding
// the outstanding ones, and dispatches event.UserRegistered with the new token. For anyone else it
// does nothing: the caller answers the same generic 202 either way.
func (s *Service) ResendVerification(ctx context.Context, email string, client token.ClientContext) error {
	user, err := s.repos.Users.ByEmail(ctx, NormalizeEmail(email))
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("identity: resend verification: %w", err)
	}
	if user.EmailVerifiedAt != nil {
		return nil
	}
	now := s.now()
	var secret string
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		pending, err := s.repos.EmailVerifications.ListByUser(ctx, user.ID)
		if err != nil {
			return err
		}
		for _, c := range pending {
			if c.ConsumedAt == nil {
				consumed := c
				consumed.ConsumedAt = &now
				if err := s.repos.EmailVerifications.Update(ctx, c, consumed); err != nil {
					return err
				}
			}
		}
		secret, err = s.insertVerification(ctx, user, client, now)
		return err
	})
	if err != nil {
		return fmt.Errorf("identity: resend verification: %w", err)
	}
	s.events.Dispatch(ctx, event.UserRegistered{UserID: user.ID, Email: user.Email, VerificationToken: secret})
	return nil
}

// insertVerification stores a new challenge for user and returns its plaintext token.
func (s *Service) insertVerification(ctx context.Context, user model.User, client token.ClientContext, now time.Time) (string, error) {
	secret := newSecret()
	err := s.repos.EmailVerifications.Insert(ctx, model.EmailVerification{
		ID: repository.NewID(), UserID: user.ID, Email: user.Email,
		TokenHash: s.pepper.Hash(verifyPepperContext, secret), ExpiresAt: now.Add(verifyTTL),
		IP: optional(client.IP), CreatedAt: now,
	})
	return secret, err
}
