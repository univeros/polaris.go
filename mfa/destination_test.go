package mfa

import "testing"

func TestMaskDestination(t *testing.T) {
	for _, c := range []struct{ channel, in, want string }{
		{"sms", "+14155550101", "+1 *** *** 0101"},
		{"sms", "4155550101", "*** *** 0101"},
		{"sms", "+12", "+1 *** *** +12"},
		{"email", "ada@example.com", "a***@example.com"},
		{"email", "a@b@example.com", "a***@example.com"},
		{"email", "élodie@example.com", "é***@example.com"},
		{"email", "not-an-email", "***"},
		{"email", "@example.com", "***"},
		{"sms", "", ""},
		{"email", "", ""},
	} {
		if got := MaskDestination(c.channel, c.in); got != c.want {
			t.Errorf("MaskDestination(%q, %q) = %q, want %q", c.channel, c.in, got, c.want)
		}
	}
}

func TestValidE164(t *testing.T) {
	for _, ok := range []string{"+14155550101", "+442071234567", "+8613800138000"} {
		if !ValidE164(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "4155550101", "+0155550101", "+1 415 555 0101", "+1-415-555-0101", "+1234567890123456", "+12", "+", "+14155550101\n", "+1415555０101"} {
		if ValidE164(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestChallengePurposeValuesAreTheStoredColumnValues(t *testing.T) {
	for p, want := range map[ChallengePurpose]string{
		PurposeLoginMFA: "login_mfa", PurposeEnroll: "enroll", PurposePasswordReset: "password_reset",
		PurposeEmailVerify: "email_verify", PurposeStepUp: "step_up",
	} {
		if string(p) != want {
			t.Errorf("%q, want %q", p, want)
		}
	}
}
