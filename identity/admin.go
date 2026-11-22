package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
)

const (
	erasurePepperContext = "user_erasure"
	tombstoneEmailSuffix = "@deleted.invalid"
	displayNameMax       = 120
	// atom is RFC 3339 to the second with a numeric offset: UTC is written "+00:00", never "Z".
	atom = "2006-01-02T15:04:05-07:00"
)

// UserView is a user as the users endpoints answer it: profile
// and account state, never credentials.
type UserView struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	DisplayName   *string `json:"display_name"`
	Status        string  `json:"status"`
	EmailVerified bool    `json:"email_verified"`
	MFAEnforced   bool    `json:"mfa_enforced"`
	CreatedAt     string  `json:"created_at"`    // DATE_ATOM
	LastLoginAt   *string `json:"last_login_at"` // DATE_ATOM
}

func viewOf(u model.User) UserView {
	v := UserView{
		ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Status: u.Status,
		EmailVerified: u.EmailVerifiedAt != nil, MFAEnforced: u.MFAEnforced,
		CreatedAt: u.CreatedAt.UTC().Format(atom),
	}
	if u.LastLoginAt != nil {
		last := u.LastLoginAt.UTC().Format(atom)
		v.LastLoginAt = &last
	}
	return v
}

// ReadUser returns userID's profile to the user themselves or to an actor holding users.read in
// actorOrganizationID ("" for none). Authority is checked before existence, so a caller without
// it learns nothing about which ids exist: *authz.ForbiddenError first, then ErrUserNotFound.
func (s *Service) ReadUser(ctx context.Context, actorUserID, actorOrganizationID, userID string) (UserView, error) {
	if err := s.selfOrPermission(ctx, actorUserID, actorOrganizationID, userID, authz.UsersRead); err != nil {
		return UserView{}, err
	}
	user, err := s.user(ctx, userID)
	if err != nil {
		return UserView{}, err
	}
	return viewOf(user), nil
}

// UpdateProfile sets userID's display name, for the user themselves or an actor holding
// users.manage. A nil displayName leaves it unchanged; one that trims to "" clears it; one longer
// than 120 characters returns ErrInvalidProfile.
func (s *Service) UpdateProfile(ctx context.Context, actorUserID, actorOrganizationID, userID string, displayName *string) (UserView, error) {
	if err := s.selfOrPermission(ctx, actorUserID, actorOrganizationID, userID, authz.UsersManage); err != nil {
		return UserView{}, err
	}
	user, err := s.user(ctx, userID)
	if err != nil {
		return UserView{}, err
	}
	next := user
	if displayName != nil {
		name := strings.Trim(*displayName, trimSet)
		if utf8.RuneCountInString(name) > displayNameMax {
			return UserView{}, refuse(ErrInvalidProfile, msgDisplayNameTooLong)
		}
		next.DisplayName = optional(name)
	}
	next.UpdatedAt = s.now()
	if err := s.repos.Users.Update(ctx, user, next); err != nil {
		return UserView{}, fmt.Errorf("identity: update profile: %w", err)
	}
	return viewOf(next), nil
}

// DisableUser disables an account and revokes every session (reason admin); the login flow then
// refuses it. The caller's users.manage is enforced by the route's authorization. Disabling
// yourself returns ErrConflict. Disabling an already disabled account revokes again (a retry
// completes a revocation that failed midway) but dispatches event.UserDisabled only once.
func (s *Service) DisableUser(ctx context.Context, actorUserID, userID string) error {
	if actorUserID == userID {
		return refuse(ErrConflict, msgSelfDisable)
	}
	user, err := s.user(ctx, userID)
	if err != nil {
		return err
	}
	becameDisabled := user.Status != model.UserStatusDisabled
	if becameDisabled {
		next := user
		next.Status, next.UpdatedAt = model.UserStatusDisabled, s.now()
		if err := s.repos.Users.Update(ctx, user, next); err != nil {
			return fmt.Errorf("identity: disable user: %w", err)
		}
	}
	if _, err := s.sessions.RevokeAll(ctx, userID, model.RevokedAdmin); err != nil {
		return fmt.Errorf("identity: disable user: %w", err)
	}
	if becameDisabled {
		s.events.Dispatch(ctx, event.UserDisabled{UserID: userID, ActorUserID: actorUserID})
	}
	return nil
}

// EnableUser re-enables a disabled or locked account and clears its lockout state. An erased
// account (a tombstone) returns ErrConflict: it must never read as a live account again.
func (s *Service) EnableUser(ctx context.Context, actorUserID, userID string) error {
	user, err := s.user(ctx, userID)
	if err != nil {
		return err
	}
	if user.PasswordHash == nil && strings.HasSuffix(user.Email, tombstoneEmailSuffix) {
		return refuse(ErrConflict, msgTombstone)
	}
	next := clearLockout(user)
	next.Status, next.UpdatedAt = model.UserStatusActive, s.now()
	if err := s.repos.Users.Update(ctx, user, next); err != nil {
		return fmt.Errorf("identity: enable user: %w", err)
	}
	s.events.Dispatch(ctx, event.UserEnabled{UserID: userID, ActorUserID: actorUserID})
	return nil
}

// EraseUser deletes (anonymizes) userID for the user themselves or an actor holding users.manage;
// see AnonymizeUser.
func (s *Service) EraseUser(ctx context.Context, actorUserID, actorOrganizationID, userID string) error {
	if err := s.selfOrPermission(ctx, actorUserID, actorOrganizationID, userID, authz.UsersManage); err != nil {
		return err
	}
	return s.AnonymizeUser(ctx, actorUserID, userID)
}

// AnonymizeUser erases an account for a caller that already established its authority (an
// operator tool): the row stays as a tombstone so audit and foreign references hold, with the
// email replaced by its keyed hash at @deleted.invalid, profile and credentials nulled and status
// disabled. The rows carrying plaintext personal data (MFA factors, OTP challenges, email
// verifications, password resets) are deleted, every session is revoked (reason admin) and
// event.UserDeleted is dispatched (the right to erasure).
func (s *Service) AnonymizeUser(ctx context.Context, actorUserID, userID string) error {
	user, err := s.user(ctx, userID)
	if err != nil {
		return err
	}
	next := user
	next.Email = s.pepper.Hash(erasurePepperContext, user.Email) + tombstoneEmailSuffix
	next.DisplayName, next.PasswordHash, next.EmailVerifiedAt = nil, nil, nil
	next.Status, next.MFAEnforced, next.UpdatedAt = model.UserStatusDisabled, false, s.now()
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.repos.Users.Update(ctx, user, next); err != nil {
			return err
		}
		// Refresh-token rows keep their ip/user agent: revoked sessions are retained for
		// theft-detection audit. Challenges go before the factors they may reference.
		for _, deleteByUser := range []func(context.Context, string) (int64, error){
			s.repos.OTPChallenges.DeleteByUser, s.repos.MFAFactors.DeleteByUser,
			s.repos.EmailVerifications.DeleteByUser, s.repos.PasswordResets.DeleteByUser,
		} {
			if _, err := deleteByUser(ctx, userID); err != nil {
				return err
			}
		}
		return s.OnUserDeleted(ctx, userID)
	})
	if err != nil {
		return fmt.Errorf("identity: anonymize user: %w", err)
	}
	if _, err := s.sessions.RevokeAll(ctx, userID, model.RevokedAdmin); err != nil {
		return fmt.Errorf("identity: anonymize user: %w", err)
	}
	s.events.Dispatch(ctx, event.UserDeleted{UserID: userID, ActorUserID: actorUserID})
	return nil
}

// selfOrPermission lets the user act on themselves; anyone else needs permission, resolved from
// the database.
func (s *Service) selfOrPermission(ctx context.Context, actorUserID, actorOrganizationID, userID, permission string) error {
	if actorUserID == userID {
		return nil
	}
	authority, err := s.authority.Resolve(ctx, actorUserID, actorOrganizationID)
	if err != nil {
		return fmt.Errorf("identity: resolve authority: %w", err)
	}
	if !authority.Allows(permission) {
		return authz.Forbidden(msgOwnAccountOnly)
	}
	return nil
}

func (s *Service) user(ctx context.Context, userID string) (model.User, error) {
	user, err := s.repos.Users.Get(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return user, refuse(ErrUserNotFound, msgUserNotFound)
	}
	if err != nil {
		return user, fmt.Errorf("identity: %w", err)
	}
	return user, nil
}
