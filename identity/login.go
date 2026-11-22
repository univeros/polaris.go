package identity

import (
	"github.com/univeros/polaris.go/model"
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

// MFAChallenge is the mfa_required outcome of a login.
type MFAChallenge struct {
	// Ticket is the login_mfa JWT (mfa_token on the wire).
	Ticket string
	// Factors are the user's confirmed factors. They are rows: render them with the mfa package's
	// masked factor view, never as they are (they carry destinations and encrypted secrets).
	Factors []model.MFAFactor
}
