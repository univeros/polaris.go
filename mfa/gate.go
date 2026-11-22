package mfa

// LoginChallenge is the MFA-required outcome of a password login: no session yet, a short-lived
// login_mfa ticket and the factors the client may complete the second step with.
type LoginChallenge struct {
	UserID   string
	MFAToken string
	Factors  []FactorView
}
