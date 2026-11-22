package mfa

import pub "github.com/univeros/polaris.go/mfa"

// The names of the public package mfa (the v1 API), repeated here so this package's
// code and its callers inside the module read as one package.
type (
	ChallengePurpose = pub.ChallengePurpose
	ConfirmResult    = pub.ConfirmResult
	FactorType       = pub.FactorType
	FactorView       = pub.FactorView
	LoginChallenge   = pub.LoginChallenge
	PolicyError      = pub.PolicyError
)

// The public constants.
const (
	PurposeEmailVerify   = pub.PurposeEmailVerify
	PurposeEnroll        = pub.PurposeEnroll
	PurposeLoginMFA      = pub.PurposeLoginMFA
	PurposePasswordReset = pub.PurposePasswordReset
	PurposeStepUp        = pub.PurposeStepUp
)

// The public errors.
var (
	ErrFactorNotFound      = pub.ErrFactorNotFound
	ErrInvalidFactorState  = pub.ErrInvalidFactorState
	ErrInvalidOTP          = pub.ErrInvalidOTP
	ErrLastFactorProtected = pub.ErrLastFactorProtected
	ErrOTPCooldown         = pub.ErrOTPCooldown
)

// The public functions.
var (
	MaskDestination = pub.MaskDestination
	ValidE164       = pub.ValidE164
	ViewOf          = pub.ViewOf
)
