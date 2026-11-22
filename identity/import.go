package identity

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
)

const msgCreatedInFuture = "The creation time cannot be in the future."

// ImportedUser is an account a trusted caller brings from another system, with its password
// hash as that system stored it.
type ImportedUser struct {
	Email string
	// PasswordHash is the stored hash, in a format the configured hasher verifies
	// (security.SupportedHashFormats for the default); "" imports an account without a password.
	PasswordHash string
	DisplayName  string
	// EmailVerified imports the address as verified (now). Otherwise it stays unverified and no
	// verification email goes out; the user asks for one when sign-in requires it.
	EmailVerified bool
	// Disabled imports the account disabled: sign-in refuses it until it is enabled.
	Disabled bool
	// CreatedAt keeps the account's original creation time; zero is now. It cannot be in the
	// future.
	CreatedAt time.Time
}

// ImportUser creates an account from another system, keeping its password hash: the user signs
// in with the password they already have, and that first sign-in rehashes it to the configured
// hasher (NeedsRehash). The email and display name are checked as CreateUser checks them; the
// hash must pass the hasher's security.HashChecker (an error matching
// security.ErrUnsupportedHash says why not). The account goes through InsertUser (the host's
// OnUserCreated, inside the caller's transaction) and event.UserRegistered is dispatched without
// a verification token. A taken email is ErrEmailTaken.
func (s *Service) ImportUser(ctx context.Context, in ImportedUser) (model.User, error) {
	now := s.now()
	user, err := newAccount(in.Email, in.DisplayName, now)
	if err != nil {
		return model.User{}, err
	}
	if in.PasswordHash != "" {
		checker, ok := s.hasher.(security.HashChecker)
		if !ok {
			return model.User{}, fmt.Errorf("identity: import user: the configured Hasher (%T) does not implement "+
				"security.HashChecker; add CheckHash(hash string) error, delegating to security.Argon2id", s.hasher)
		}
		if err := checker.CheckHash(in.PasswordHash); err != nil {
			return model.User{}, fmt.Errorf("identity: import user: %w", err)
		}
		hash := in.PasswordHash
		user.PasswordHash = &hash
	}
	if !in.CreatedAt.IsZero() {
		if in.CreatedAt.After(now) {
			return model.User{}, refuse(ErrInvalidProfile, msgCreatedInFuture)
		}
		user.CreatedAt = in.CreatedAt.UTC()
	}
	if in.EmailVerified {
		user.EmailVerifiedAt = &now
	}
	if in.Disabled {
		user.Status = model.UserStatusDisabled
	}
	if err := s.InsertUser(ctx, user); errors.Is(err, store.ErrDuplicate) {
		return model.User{}, refuse(ErrEmailTaken, msgEmailTaken)
	} else if err != nil {
		return model.User{}, fmt.Errorf("identity: import user: %w", err)
	}
	s.events.Dispatch(ctx, event.UserRegistered{UserID: user.ID, Email: user.Email})
	return user, nil
}
