package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// InsertUser writes a new account row and runs the host's OnUserCreated hook in one transaction
// (a savepoint inside the caller's): a hook error leaves no account. Every path that creates an
// account (registration, passwordless and social sign-up, SSO and SCIM provisioning, guests,
// CreateUser) goes through it. A taken email matches store.ErrDuplicate.
func (s *Service) InsertUser(ctx context.Context, u model.User) error {
	return s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.repos.Users.Insert(ctx, u); err != nil {
			return err
		}
		if s.onCreated == nil {
			return nil
		}
		if err := s.onCreated(ctx, u); err != nil {
			return fmt.Errorf("identity: OnUserCreated: %w", err)
		}
		return nil
	})
}

// OnUserDeleted runs the host's OnUserDeleted hook for userID. Call it inside the transaction
// that erases or removes the account, so a hook error rolls the removal back.
func (s *Service) OnUserDeleted(ctx context.Context, userID string) error {
	if s.onDeleted == nil {
		return nil
	}
	if err := s.onDeleted(ctx, userID); err != nil {
		return fmt.Errorf("identity: OnUserDeleted: %w", err)
	}
	return nil
}

// NewUser is an account a trusted caller (the host, in process) creates.
type NewUser struct {
	Email       string
	Password    string // "" creates an account without a password (it signs in another way)
	DisplayName string
	// EmailVerified creates the account verified. Otherwise a verification challenge is opened
	// and event.UserRegistered carries its token, as registration does.
	EmailVerified bool
}

// CreateUser creates an account for a trusted caller: registration's checks (email format,
// password policy) without its anti-enumeration, so a taken email is ErrEmailTaken. It
// dispatches event.UserRegistered (without a token when the account is created verified).
func (s *Service) CreateUser(ctx context.Context, in NewUser, client token.ClientContext) (model.User, error) {
	email := NormalizeEmail(in.Email)
	if !manifest.IsEmail(email) {
		return model.User{}, refuse(ErrInvalidProfile, msgInvalidEmail)
	}
	name := strings.Trim(in.DisplayName, trimSet)
	if utf8.RuneCountInString(name) > displayNameMax {
		return model.User{}, refuse(ErrInvalidProfile, msgDisplayNameTooLong)
	}
	now := s.now()
	user := model.User{
		ID: repository.NewID(), Email: email, DisplayName: optional(name),
		Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now,
	}
	if in.Password != "" {
		if err := s.policy.enforce(ctx, in.Password); err != nil {
			return model.User{}, err
		}
		hash, err := s.hasher.Hash(in.Password)
		if err != nil {
			return model.User{}, fmt.Errorf("identity: create user: %w", err)
		}
		user.PasswordHash = &hash
	}
	if in.EmailVerified {
		user.EmailVerifiedAt = &now
	}
	var secret string
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.InsertUser(ctx, user); errors.Is(err, store.ErrDuplicate) {
			return refuse(ErrEmailTaken, msgEmailTaken)
		} else if err != nil {
			return err
		}
		if in.EmailVerified {
			return nil
		}
		var err error
		secret, err = s.insertVerification(ctx, user, client, now)
		return err
	})
	if err != nil {
		return model.User{}, wrapUnlessRefusal("create user", err)
	}
	s.events.Dispatch(ctx, event.UserRegistered{UserID: user.ID, Email: user.Email, VerificationToken: secret})
	return user, nil
}

// SetPassword sets userID's password for a trusted caller (an operator, the host), as a reset
// does: the policy applies (*PasswordError), every session ends and event.PasswordChanged (method
// reset) is dispatched.
func (s *Service) SetPassword(ctx context.Context, userID, password string) error {
	user, err := s.user(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.policy.enforce(ctx, password); err != nil {
		return err
	}
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return fmt.Errorf("identity: set password: %w", err)
	}
	next := user
	next.PasswordHash, next.UpdatedAt = &hash, s.now()
	if err := s.repos.Users.Update(ctx, user, next); err != nil {
		return fmt.Errorf("identity: set password: %w", err)
	}
	if _, err := s.sessions.RevokeAll(ctx, userID, model.RevokedPasswordChange); err != nil {
		return fmt.Errorf("identity: set password: %w", err)
	}
	s.events.Dispatch(ctx, event.PasswordChanged{UserID: userID, Method: event.PasswordMethodReset})
	return nil
}

// SignIn opens a session for userID after the host authenticated them its own way, with login's
// account checks (disabled: ErrAccountDisabled; unverified when verification is required:
// ErrEmailNotVerified) but no password and no MFA gate. amr says how the user authenticated
// (RFC 8176 values; empty is ["custom"]). It records the login and dispatches
// event.UserLoggedIn.
func (s *Service) SignIn(ctx context.Context, userID string, amr []string, client token.ClientContext) (token.IssuedTokens, error) {
	user, err := s.user(ctx, userID)
	if err != nil {
		return token.IssuedTokens{}, err
	}
	if user.Status == model.UserStatusDisabled {
		return token.IssuedTokens{}, refuse(ErrAccountDisabled, msgDisabled)
	}
	if s.auth.Flows.RequireVerifiedEmail && user.EmailVerifiedAt == nil {
		return token.IssuedTokens{}, refuse(ErrEmailNotVerified, msgUnverified)
	}
	if len(amr) == 0 {
		amr = []string{"custom"}
	}
	now := s.now()
	authTime := now.Unix()
	next := user
	next.LastLoginAt, next.UpdatedAt = &now, now
	principal := token.SessionPrincipal{
		UserID: user.ID, EmailVerified: user.EmailVerifiedAt != nil, AMR: amr, AuthTime: &authTime,
	}
	var tokens token.IssuedTokens
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.repos.Users.Update(ctx, user, next); err != nil {
			return err
		}
		tokens, err = s.sessions.Issue(ctx, principal, client)
		return err
	})
	if err != nil {
		return token.IssuedTokens{}, fmt.Errorf("identity: sign in: %w", err)
	}
	s.events.Dispatch(ctx, event.UserLoggedIn{
		UserID: user.ID, SessionID: tokens.SessionID, IP: optional(client.IP),
		UserAgent: optional(client.UserAgent), AMR: amr,
	})
	return tokens, nil
}

// wrapUnlessRefusal wraps a failure of op, leaving a refusal (*Error, *PasswordError) as it is.
func wrapUnlessRefusal(op string, err error) error {
	var refusal *Error
	if errors.As(err, &refusal) {
		return err
	}
	return fmt.Errorf("identity: %s: %w", op, err)
}
