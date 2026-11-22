package identity

import pub "github.com/univeros/polaris.go/identity"

// The names of the public package identity (the v1 API), repeated here so this package's
// code and its callers inside the module read as one package.
type (
	Error          = pub.Error
	LoginResult    = pub.LoginResult
	MFAChallenge   = pub.MFAChallenge
	PasswordError  = pub.PasswordError
	PasswordPolicy = pub.PasswordPolicy
)

// The public errors.
var (
	ErrAccountDisabled          = pub.ErrAccountDisabled
	ErrConflict                 = pub.ErrConflict
	ErrEmailNotVerified         = pub.ErrEmailNotVerified
	ErrEmailTaken               = pub.ErrEmailTaken
	ErrInvalidCredentials       = pub.ErrInvalidCredentials
	ErrInvalidPassword          = pub.ErrInvalidPassword
	ErrInvalidProfile           = pub.ErrInvalidProfile
	ErrInvalidResetToken        = pub.ErrInvalidResetToken
	ErrInvalidVerificationToken = pub.ErrInvalidVerificationToken
	ErrUserNotFound             = pub.ErrUserNotFound
)

// The public functions.
var (
	NormalizeEmail = pub.NormalizeEmail
)
