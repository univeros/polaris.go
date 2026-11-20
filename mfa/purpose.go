package mfa

// ChallengePurpose scopes an OTP challenge to one flow, so a code issued for one cannot satisfy
// another (an enroll code cannot clear the login gate). The value is what
// auth_otp_challenges.purpose stores.
type ChallengePurpose string

// The challenge purposes.
const (
	PurposeLoginMFA      ChallengePurpose = "login_mfa"      // the 2FA step of login
	PurposeEnroll        ChallengePurpose = "enroll"         // confirming a new sms/email factor
	PurposePasswordReset ChallengePurpose = "password_reset" // OTP-style password reset
	PurposeEmailVerify   ChallengePurpose = "email_verify"   // OTP-style email verification
	PurposeStepUp        ChallengePurpose = "step_up"        // re-authentication in a session
)
