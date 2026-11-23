package identity

import (
	"context"
	"errors"
	"fmt"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

// ProveEmail records that whoever is acting now controls the account's mailbox: they followed a
// link or typed a code sent there, or a party trusted for the address (a trusted social provider,
// the identity provider of the organization that verified the domain) vouched for them. Every such
// path calls it; it is the only place an existing account becomes verified.
//
// For an account whose mailbox had never been proven it is the first proof, and first reports
// true: the account is marked verified and everything that could act as it before goes, since
// whoever created the account may not be the mailbox's owner (account pre-hijacking). That is the
// password and lockout state, the MFA factors and recovery codes, what the plugins hold (provider
// links, passkeys, API keys, OAuth grants, agents, phone numbers: Config.OnEmailProven) and every
// session. For an already verified account nothing changes and first is false.
//
// confirmsRegistration is for the verification message a registration sends (core's link, the
// passwordless verification code): when the account has a password, the proof confirms the
// registration that set it, so the account is only marked verified and nothing is removed. An
// account without a password has no registration to confirm and is treated as above.
//
// It runs in one transaction (inside the caller's, when ctx carries one) and dispatches
// event.UserEmailVerified on a first proof. The returned user is the row after the proof.
func (s *Service) ProveEmail(ctx context.Context, userID string, confirmsRegistration bool) (user model.User, first bool, err error) {
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		var err error
		if user, err = s.repos.Users.Get(ctx, userID); err != nil || user.EmailVerifiedAt != nil {
			return err
		}
		now := s.now()
		keeps := confirmsRegistration && user.PasswordHash != nil
		data := store.Data{"email_verified_at": now, "updated_at": now}
		if !keeps {
			data["password_hash"], data["failed_login_count"], data["failed_login_at"], data["locked_until"] = nil, 0, nil, nil
		}
		// Conditional, so of concurrent proofs one is the first.
		claimed, err := s.db.Update(ctx, "auth_users", store.Criteria{"id": userID, "email_verified_at": nil}, data)
		if err != nil {
			return err
		}
		if user, err = s.repos.Users.Get(ctx, userID); err != nil || claimed != 1 {
			return err
		}
		first = true
		if keeps {
			return nil
		}
		return s.dropAccess(ctx, userID)
	})
	if err != nil {
		return model.User{}, false, fmt.Errorf("identity: prove email: %w", err)
	}
	if first {
		s.events.Dispatch(ctx, event.UserEmailVerified{UserID: user.ID, Email: user.Email})
	}
	return user, first, nil
}

// dropAccess removes what could act as the account apart from its password: the MFA factors,
// recovery codes and pending challenges, what the plugins hold (Config.OnEmailProven) and every
// session. It runs inside the caller's transaction.
func (s *Service) dropAccess(ctx context.Context, userID string) error {
	for _, table := range []string{"auth_otp_challenges", "auth_mfa_factors", "auth_recovery_codes"} { // challenges before the factors they reference
		if _, err := s.db.Delete(ctx, table, store.Criteria{"user_id": userID}); err != nil {
			return err
		}
	}
	if s.onEmailProven != nil {
		if err := s.onEmailProven(ctx, userID); err != nil {
			return err
		}
	}
	// Last: the denylist watermark is in the cache, which a rollback cannot undo.
	_, err := s.sessions.RevokeAll(ctx, userID, model.RevokedAdmin)
	return err
}

// ChangeEmail moves the account to another address for a trusted caller (a directory renaming an
// account it owns), which decides whether the move is allowed at all. verified says whether the
// caller vouches for the new mailbox: the account is verified when it does (for an unverified one
// that is its first proof, ProveEmail) and unverified when it does not, whatever it was before. The reset and verification tokens sent to the old address are
// removed: a token is for the mailbox it was sent to. A taken address is ErrEmailTaken.
func (s *Service) ChangeEmail(ctx context.Context, userID, email string, verified bool) (model.User, error) {
	email = NormalizeEmail(email)
	var next model.User
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		user, err := s.repos.Users.Get(ctx, userID)
		if err != nil {
			return err
		}
		next = user
		next.Email, next.UpdatedAt = email, s.now()
		if !verified {
			next.EmailVerifiedAt = nil
		}
		if err := s.repos.Users.Update(ctx, user, next); err != nil {
			return err
		}
		if _, err := s.repos.PasswordResets.DeleteByUser(ctx, userID); err != nil {
			return err
		}
		if _, err := s.repos.EmailVerifications.DeleteByUser(ctx, userID); err != nil {
			return err
		}
		if verified && next.EmailVerifiedAt == nil {
			// The caller's word is the mailbox's first proof, with what a first proof removes.
			next, _, err = s.ProveEmail(ctx, userID, false)
		}
		return err
	})
	if errors.Is(err, store.ErrDuplicate) {
		return model.User{}, refuse(ErrEmailTaken, msgEmailTaken)
	}
	if err != nil {
		return model.User{}, fmt.Errorf("identity: change email: %w", err)
	}
	return next, nil
}
