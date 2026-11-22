package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
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
	verifyBindContext   = "email_verify_bind" // never stored: the binding inside a verification token
	verifyTTL           = 24 * time.Hour
)

// Register creates an unverified account with an Argon2id hash, opens an email-verification
// challenge and dispatches event.UserRegistered carrying the plaintext token for the mailer
// displayName "" stores none.
//
// An address registered before and never verified is registered again (registerAgain): nobody
// proved that mailbox, so the earlier registration does not hold it.
//
// A password failing the policy returns a *PasswordError. Any other taken email returns nil
// without creating anything or dispatching an event, after hashing the password anyway, so the
// response and its timing match the account-created path. That includes losing a race with a
// concurrent registration of the same address (the unique index refuses the second insert).
func (s *Service) Register(ctx context.Context, email, password, displayName string, client token.ClientContext) error {
	if err := enforce(ctx, s.policy, password); err != nil {
		return err
	}
	email = NormalizeEmail(email)
	existing, err := s.repos.Users.ByEmail(ctx, email)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return fmt.Errorf("identity: register: %w", err)
	}
	taken := err == nil

	hash, err := s.hasher.Hash(password) // on every path: the answer's timing does not say which
	if err != nil {
		return fmt.Errorf("identity: register: %w", err)
	}
	now := s.now()
	if taken {
		// A verified account is its owner's; one without a password was not made by registering
		// (a directory, a provider) and its owner proves the mailbox by reset; a disabled one
		// stays disabled.
		if existing.EmailVerifiedAt != nil || existing.PasswordHash == nil || existing.Status == model.UserStatusDisabled {
			return nil
		}
		return s.registerAgain(ctx, existing, hash, displayName, client, now)
	}
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

// registerAgain is a registration of an address whose account nobody verified. The new
// registration takes the account: its password and display name replace the stored ones, what the
// earlier registrant could act with goes (factors, the plugins' access rows, sessions: dropAccess),
// the outstanding verification tokens die and a new one, for the new password, is sent. Otherwise
// the password of whoever registered an address first would be the one its owner's click confirms.
// The update is conditional, so a verification that won the race keeps its account.
func (s *Service) registerAgain(ctx context.Context, user model.User, hash, displayName string, client token.ClientContext, now time.Time) error {
	var secret string
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		data := store.Data{"password_hash": hash, "display_name": store.Nullable(optional(displayName)),
			"failed_login_count": 0, "failed_login_at": nil, "locked_until": nil, "updated_at": now}
		if user.Status == model.UserStatusLocked {
			data["status"] = model.UserStatusActive
		}
		claimed, err := s.db.Update(ctx, "auth_users", store.Criteria{"id": user.ID, "email_verified_at": nil}, data)
		if err != nil || claimed != 1 {
			return err
		}
		if _, err := s.repos.EmailVerifications.DeleteByUser(ctx, user.ID); err != nil {
			return err
		}
		next := user
		next.PasswordHash = &hash
		if secret, err = s.insertVerification(ctx, next, client, now); err != nil {
			return err
		}
		return s.dropAccess(ctx, user.ID) // last: it revokes sessions, which a rollback cannot undo
	})
	if err != nil {
		return fmt.Errorf("identity: register: %w", err)
	}
	if secret != "" {
		s.events.Dispatch(ctx, event.UserRegistered{UserID: user.ID, Email: user.Email, VerificationToken: secret})
	}
	return nil
}

// VerifyEmail confirms an email address from its token (ProveEmail, confirming the registration)
// and dispatches event.UserEmailVerified.
// It is idempotent: a token that matched a real challenge succeeds again
// once the user is verified, even consumed or expired. Otherwise an unknown, consumed or expired
// token, one sent to an address the account has left since, or one issued for another password
// than the account has now, returns ErrInvalidVerificationToken.
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
	// The token is for the address it was sent to and the password it was issued with.
	if challenge.Email != user.Email || !s.confirms(secret, user) {
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

// insertVerification stores a new challenge for user and returns its plaintext token: a random
// nonce, a dot and the binding of the nonce to the password hash the account has now.
func (s *Service) insertVerification(ctx context.Context, user model.User, client token.ClientContext, now time.Time) (string, error) {
	nonce := newSecret()
	secret := nonce + "." + s.binding(nonce, user)
	err := s.repos.EmailVerifications.Insert(ctx, model.EmailVerification{
		ID: repository.NewID(), UserID: user.ID, Email: user.Email,
		TokenHash: s.pepper.Hash(verifyPepperContext, secret), ExpiresAt: now.Add(verifyTTL),
		IP: optional(client.IP), CreatedAt: now,
	})
	return secret, err
}

// binding ties a verification token to the password hash its account had when it was issued (""
// for none): 128 bits of a keyed hash of both. The token then confirms that password and no other.
// It is not stored: the token carries it and VerifyEmail recomputes it.
func (s *Service) binding(nonce string, user model.User) string {
	hash := ""
	if user.PasswordHash != nil {
		hash = *user.PasswordHash
	}
	return s.pepper.Hash(verifyBindContext, nonce+"\x00"+hash)[:32]
}

// confirms reports whether the token was issued for the password the account has now. A token
// without a binding was issued before v1.0.0 and confirms as it did then; no new one can be made,
// since the stored hash covers the whole token.
func (s *Service) confirms(secret string, user model.User) bool {
	nonce, bound, ok := strings.Cut(secret, ".")
	return !ok || subtle.ConstantTimeCompare([]byte(bound), []byte(s.binding(nonce, user))) == 1
}
