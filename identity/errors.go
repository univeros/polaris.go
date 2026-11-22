package identity

import "errors"

// Sentinels matched (errors.Is) by the refusals of this package. Endpoints map each to a fixed status
// and error code; the message to send is the error's Error().
var (
	// ErrInvalidCredentials: unknown email, wrong password or locked account at login (401, never
	// distinguished), or a wrong current password on change (403).
	ErrInvalidCredentials = errors.New("identity: invalid credentials")
	// ErrAccountDisabled: the password is right but an administrator disabled the account (403).
	ErrAccountDisabled = errors.New("identity: account disabled")
	// ErrEmailNotVerified: the password is right but the email is unverified and
	// auth.flows.require_verified_email is on (403 email_unverified).
	ErrEmailNotVerified = errors.New("identity: email not verified")
	// ErrInvalidVerificationToken: an unknown, consumed or expired email-verification token (400).
	ErrInvalidVerificationToken = errors.New("identity: invalid verification token")
	// ErrInvalidResetToken: an unknown, consumed or expired reset token, or a disabled account (401).
	ErrInvalidResetToken = errors.New("identity: invalid reset token")
	// ErrInvalidPassword: a new password fails the policy; the error is a *PasswordError (422).
	ErrInvalidPassword = errors.New("identity: password fails the policy")
	// ErrUserNotFound: user administration on an unknown id (404).
	ErrUserNotFound = errors.New("identity: user not found")
	// ErrConflict: disabling yourself, or re-enabling an erased account (409 conflict).
	ErrConflict = errors.New("identity: conflict")
	// ErrInvalidProfile: a profile update with an invalid value (422).
	ErrInvalidProfile = errors.New("identity: invalid profile")
	// ErrEmailTaken: CreateUser for an email another account holds.
	ErrEmailTaken = errors.New("identity: email taken")
	// ErrInvalidConfig: New was given an incomplete Config.
	ErrInvalidConfig = errors.New("identity: invalid configuration")
)

// Error is a refusal carrying the client-facing message. It
// matches its Kind, one of the sentinels above.
type Error struct {
	Kind    error
	Message string
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns Kind, so errors.Is matches the sentinel.
func (e *Error) Unwrap() error { return e.Kind }

func refuse(kind error, message string) error { return &Error{Kind: kind, Message: message} }

// PasswordError reports a password that fails the policy; Violations lists each failed rule as
// the 422 body shows it. It matches ErrInvalidPassword.
type PasswordError struct{ Violations []string }

func (e *PasswordError) Error() string { return "The password does not meet the policy requirements." }

// Is reports whether target is ErrInvalidPassword.
func (e *PasswordError) Is(target error) bool { return target == ErrInvalidPassword }

// Client-facing messages: clients may match on them, so they do not change.
const (
	msgInvalidCredentials = "Invalid email or password."
	msgWrongPassword      = "The current password is incorrect."
	msgDisabled           = "This account is disabled."
	msgUnverified         = "Email address is not verified."
	msgBadVerification    = "The verification token is invalid."
	msgExpiredVerify      = "The verification token has expired."
	msgBadReset           = "The reset token is invalid or expired."
	msgUserNotFound       = "The user does not exist."
	msgSelfDisable        = "You cannot disable your own account."
	msgTombstone          = "The account has been anonymized and cannot be re-enabled."
	msgDisplayNameTooLong = "The display name must be 120 characters or fewer."
	msgOwnAccountOnly     = "You may only manage your own account."
	msgInvalidEmail       = "A valid email address is required."
	msgEmailTaken         = "The email address is already registered."
)
