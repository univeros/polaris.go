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

// LoginResult is the outcome of a correct password. Either Tokens holds the new session, or MFA
// is set: the user has a confirmed second factor, no session was opened, and the client completes
// the login through the MFA challenge/verify step.
type LoginResult struct {
	UserID        string
	Email         string
	EmailVerified bool
	Tokens        token.IssuedTokens // zero when MFA is set
	MFA           *MFAChallenge
}

// MFAChallenge is the mfa_required outcome of a login (upstream MfaChallengeResult).
type MFAChallenge struct {
	// Ticket is the login_mfa JWT (mfa_token on the wire).
	Ticket string
	// Factors are the user's confirmed factors. They are rows: render them with the mfa package's
	// masked factor view, never as they are (they carry destinations and encrypted secrets).
	Factors []model.MFAFactor
}

// Login checks a password and opens a session (docs/auth/flows.md §3, §10), or returns an MFA
// challenge when the user has a confirmed factor.
//
// An unknown email, a wrong password and a locked account all return ErrInvalidCredentials after
// exactly one password verify (against a dummy hash when there is no account or no password), so
// neither the answer nor its timing tells whether the account exists. Only with the right
// password does the account state show: ErrAccountDisabled, then ErrEmailNotVerified when
// auth.flows.require_verified_email is on.
//
// Lockout is windowed (auth.lockout): MaxAttempts failures, each within Window of the previous
// one, lock the account for Duration (status locked, event.UserLocked), after which it unlocks on
// its own. A failure against a live lock or a disabled account is not counted, so attempts can
// neither extend a lock nor move a disabled account through the lock lifecycle. A success clears
// the streak and rehashes a password hashed with outdated parameters.
func (s *Service) Login(ctx context.Context, email, password string, client token.ClientContext) (LoginResult, error) {
	now := s.now()
	user, err := s.repos.Users.ByEmail(ctx, NormalizeEmail(email))
	found := err == nil
	if !found && !errors.Is(err, repository.ErrNotFound) {
		return LoginResult{}, fmt.Errorf("identity: login: %w", err)
	}
	hash := ""
	if found && user.PasswordHash != nil {
		hash = *user.PasswordHash
	}
	locked := found && user.LockedUntil != nil && user.LockedUntil.After(now)

	// Always run one verify, real or dummy, so timing does not leak account existence.
	against := hash
	if against == "" {
		if against, err = s.dummyHash(); err != nil {
			return LoginResult{}, fmt.Errorf("identity: login: %w", err)
		}
	}
	verified := s.hasher.Verify(password, against)

	if !found || hash == "" || !verified {
		if found && !locked && user.Status != model.UserStatusDisabled {
			if err := s.recordFailure(ctx, user, now, client); err != nil {
				return LoginResult{}, err
			}
		}
		return LoginResult{}, refuse(ErrInvalidCredentials, msgInvalidCredentials)
	}
	if locked { // a live lock reads as a credential failure: no lock disclosure
		return LoginResult{}, refuse(ErrInvalidCredentials, msgInvalidCredentials)
	}
	if user.Status == model.UserStatusDisabled {
		return LoginResult{}, refuse(ErrAccountDisabled, msgDisabled)
	}
	if s.auth.Flows.RequireVerifiedEmail && user.EmailVerifiedAt == nil {
		return LoginResult{}, refuse(ErrEmailNotVerified, msgUnverified)
	}

	next := clearLockout(user)
	if s.hasher.NeedsRehash(hash) {
		rehashed, err := s.hasher.Hash(password)
		if err != nil {
			return LoginResult{}, fmt.Errorf("identity: login: %w", err)
		}
		next.PasswordHash = &rehashed
	}
	next.UpdatedAt = now
	result := LoginResult{UserID: user.ID, Email: user.Email, EmailVerified: user.EmailVerifiedAt != nil}

	// A confirmed second factor: no session yet, the MFA step mints it. last_login_at and
	// user.logged_in mark a completed login, so they wait for that step too.
	factors, err := s.mfa.ConfirmedFactors(ctx, user.ID)
	if err != nil {
		return LoginResult{}, fmt.Errorf("identity: login: %w", err)
	}
	if len(factors) > 0 {
		if err := s.repos.Users.Update(ctx, user, next); err != nil {
			return LoginResult{}, fmt.Errorf("identity: login: %w", err)
		}
		ticket, err := s.tickets.Issue(user.ID)
		if err != nil {
			return LoginResult{}, fmt.Errorf("identity: login: %w", err)
		}
		result.MFA = &MFAChallenge{Ticket: ticket, Factors: factors}
		return result, nil
	}

	next.LastLoginAt = &now
	authTime := now.Unix()
	principal := token.SessionPrincipal{
		UserID: user.ID, EmailVerified: user.EmailVerifiedAt != nil, AMR: []string{"pwd"}, AuthTime: &authTime,
	}
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.repos.Users.Update(ctx, user, next); err != nil {
			return err
		}
		result.Tokens, err = s.sessions.Issue(ctx, principal, client)
		return err
	})
	if err != nil {
		return LoginResult{}, fmt.Errorf("identity: login: %w", err)
	}
	s.events.Dispatch(ctx, event.UserLoggedIn{
		UserID: user.ID, SessionID: result.Tokens.SessionID, IP: optional(client.IP),
		UserAgent: optional(client.UserAgent), AMR: []string{"pwd"},
	})
	return result, nil
}

// recordFailure counts a failed password against an active (or lapsed-lock) account and locks it
// at the threshold. The transition is a compare-and-swap on the lockout columns, retried on the
// re-read row when a concurrent failure, login or admin action got there first: N concurrent
// failures count N and lock exactly where the sequential rule would, and a failure that finds
// a live lock or a disabled account on re-read is not counted.
func (s *Service) recordFailure(ctx context.Context, user model.User, now time.Time, client token.ClientContext) error {
	for {
		next, lockedNow := s.failed(user, now)
		claimed, err := s.db.Update(ctx, "auth_users", lockoutState(user), store.Data{
			"failed_login_count": next.FailedLoginCount, "failed_login_at": nullTime(next.FailedLoginAt),
			"locked_until": nullTime(next.LockedUntil), "status": next.Status, "updated_at": now.Truncate(time.Second),
		})
		if err != nil {
			return fmt.Errorf("identity: login: %w", err)
		}
		if claimed == 1 {
			s.events.Dispatch(ctx, event.UserLoginFailed{
				UserID: user.ID, IP: optional(client.IP), UserAgent: optional(client.UserAgent),
				Reason: event.LoginFailedInvalidCredentials,
			})
			if lockedNow {
				s.events.Dispatch(ctx, event.UserLocked{UserID: user.ID, IP: optional(client.IP), Until: next.LockedUntil})
			}
			return nil
		}
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("identity: login: %w", err)
		}
		user, err = s.repos.Users.Get(ctx, user.ID)
		if errors.Is(err, repository.ErrNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("identity: login: %w", err)
		}
		if (user.LockedUntil != nil && user.LockedUntil.After(now)) || user.Status == model.UserStatusDisabled {
			return nil // as upstream: a live lock is not extended, a disabled account is left alone
		}
	}
}

// failed returns user after one more failure (upstream's sequential rule) and whether that
// failure locks the account.
func (s *Service) failed(user model.User, now time.Time) (model.User, bool) {
	next := user
	// A stale streak (an expired lock, or a last failure older than the window) starts over, so
	// only failures clustered within the window count toward a lock.
	if s.failureWindowExpired(user, now) {
		next.FailedLoginCount, next.LockedUntil = 0, nil
		if next.Status == model.UserStatusLocked {
			next.Status = model.UserStatusActive
		}
	}
	next.FailedLoginCount++
	next.FailedLoginAt = &now
	if next.LockedUntil == nil && next.FailedLoginCount >= s.auth.Lockout.MaxAttempts {
		until := now.Add(s.auth.Lockout.Duration)
		next.LockedUntil, next.Status = &until, model.UserStatusLocked
		return next, true
	}
	return next, false
}

// lockoutState matches the row only while its lockout columns are still as read.
func lockoutState(u model.User) store.Criteria {
	return store.Criteria{
		"id": u.ID, "failed_login_count": u.FailedLoginCount, "failed_login_at": nullTime(u.FailedLoginAt),
		"locked_until": nullTime(u.LockedUntil), "status": u.Status,
	}
}

// nullTime is a nullable datetime as stored: UTC, to the second.
func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Truncate(time.Second)
}

// failureWindowExpired reports whether the next failure opens a fresh window: after an expired
// lock, or when the last failure is older than auth.lockout.window. A first failure continues the
// (empty) window.
func (s *Service) failureWindowExpired(user model.User, now time.Time) bool {
	if user.LockedUntil != nil && !user.LockedUntil.After(now) {
		return true
	}
	if user.FailedLoginAt == nil {
		return false
	}
	return now.Unix()-user.FailedLoginAt.Unix() > int64(s.auth.Lockout.Window/time.Second)
}

// clearLockout returns user with the failure streak and any lock cleared (locked → active; a
// disabled status is kept).
func clearLockout(user model.User) model.User {
	user.FailedLoginCount, user.FailedLoginAt, user.LockedUntil = 0, nil, nil
	if user.Status == model.UserStatusLocked {
		user.Status = model.UserStatusActive
	}
	return user
}
