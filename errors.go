package polaris

import (
	"errors"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/identity"
	"github.com/univeros/polaris-go/orgs"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/session"
	"github.com/univeros/polaris-go/store"
)

// Errors of the programmatic API (Users, Orgs, Sessions), matched with errors.Is. The error
// itself carries the reason; its message is safe to show a user.
var (
	// ErrNotFound: no such user, organization or membership.
	ErrNotFound = errors.New("polaris: not found")
	// ErrConflict: the email is taken, the slug is taken, the user is already a member, the last
	// owner would go, an erased account cannot be re-enabled.
	ErrConflict = errors.New("polaris: conflict")
	// ErrForbidden: the account is disabled, its email is unverified while verification is
	// required, or an authorization rule refuses.
	ErrForbidden = errors.New("polaris: forbidden")
	// ErrInvalidInput: a malformed email or name, an unknown role, a password failing the policy
	// (errors.As a *PasswordError for the rules it broke).
	ErrInvalidInput = errors.New("polaris: invalid input")
	// ErrInvalidCredentials: an unknown, expired or revoked refresh token.
	ErrInvalidCredentials = errors.New("polaris: invalid credentials")
)

// PasswordError lists the password-policy rules a password broke (Violations); it matches
// ErrInvalidInput.
type PasswordError = identity.PasswordError

// kinds maps the domain packages' sentinels to the API's.
var kinds = []struct{ from, to error }{
	{identity.ErrUserNotFound, ErrNotFound}, {orgs.ErrNotFound, ErrNotFound}, {repository.ErrNotFound, ErrNotFound},
	{identity.ErrConflict, ErrConflict}, {identity.ErrEmailTaken, ErrConflict}, {orgs.ErrConflict, ErrConflict},
	{store.ErrDuplicate, ErrConflict},
	{authz.ErrForbidden, ErrForbidden}, {identity.ErrAccountDisabled, ErrForbidden},
	{identity.ErrEmailNotVerified, ErrForbidden},
	{identity.ErrInvalidPassword, ErrInvalidInput}, {identity.ErrInvalidProfile, ErrInvalidInput},
	{orgs.ErrInvalid, ErrInvalidInput},
	{session.ErrInvalidGrant, ErrInvalidCredentials}, {identity.ErrInvalidCredentials, ErrInvalidCredentials},
}

// apiError is a domain error that also matches its API sentinel.
type apiError struct{ kind, err error }

func (e *apiError) Error() string   { return e.err.Error() }
func (e *apiError) Unwrap() []error { return []error{e.kind, e.err} }

// classify makes err match the API sentinel of its domain sentinel; other errors (the database
// failing) pass through.
func classify(err error) error {
	if err == nil {
		return nil
	}
	for _, k := range kinds {
		if errors.Is(err, k.from) {
			return &apiError{kind: k.to, err: err}
		}
	}
	return err
}
