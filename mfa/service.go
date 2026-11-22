package mfa

import (
	"context"
	"errors"

	"github.com/univeros/polaris.go/model"
)

var (
	// ErrInvalidOTP reports a code that does not verify: wrong, expired, attempt-exhausted,
	// already used, a replayed TOTP step, or a factor that takes no sent challenge. The endpoints
	// answer a generic 422 that never says which.
	ErrInvalidOTP = errors.New("mfa: the verification code is invalid")
	// ErrOTPCooldown reports a code requested before the resend cooldown elapsed, or past the
	// per-account / per-destination send budget. The endpoints answer 429.
	ErrOTPCooldown = errors.New("mfa: please wait before requesting another code")
	// ErrFactorNotFound reports a factor that does not exist, is another user's, has the wrong
	// type for the operation, is unconfirmed where a confirmed one is needed, or has a type no
	// one verifies. The endpoints answer 404: another user's factor looks like no factor.
	ErrFactorNotFound = errors.New("mfa: factor not found")
	// ErrInvalidFactorState reports a management change the factor's state forbids (422); the
	// error is a *PolicyError carrying the client-facing message.
	ErrInvalidFactorState = errors.New("mfa: invalid factor state")
	// ErrLastFactorProtected reports removing the last confirmed factor of a user for whom MFA
	// is enforced (409); the error is a *PolicyError carrying the client-facing message.
	ErrLastFactorProtected = errors.New("mfa: last factor protected")
)

// PolicyError is a refused factor-management change. Message is the explanation sent to the
// client verbatim; Err is ErrInvalidFactorState or ErrLastFactorProtected.
type PolicyError struct {
	Err     error
	Message string
}

func (e *PolicyError) Error() string { return e.Err.Error() + ": " + e.Message }

func (e *PolicyError) Unwrap() error { return e.Err }

// FactorType is an MFA factor type a plugin adds to core's gate (passkey adds "passkey"). Core
// owns the auth_mfa_factors row (listed, relabelled, defaulted and removed by core, confirmed
// through Service.ConfirmFactor), the login_mfa ticket and the verify routes; the type owns the
// verification of what the client sends as the code. Core's own types (totp, sms, email) cannot
// be replaced.
type FactorType interface {
	// Type is the auth_mfa_factors.type value of the rows this verifies.
	Type() string
	// Verify checks code for a confirmed factor of this type under purpose and returns nil when
	// it clears. A code that does not verify returns an error wrapping ErrInvalidOTP (answered
	// as a wrong code, never more); any other error is an infrastructure failure.
	Verify(ctx context.Context, factor model.MFAFactor, code string, purpose ChallengePurpose) error
}
