package passwordless

import "testing"

// Stored digests are found again only under the pepper context they were written with
// (testdata/vectors/pepper.json, docs/stored-formats.md); a secret's context is
// "passwordless:" + its kind, and the kind is also the stored kind column.
func TestPepperContextsAreTheStoredOnes(t *testing.T) {
	for _, c := range [][2]string{
		{identifierContext, "passwordless:identifier"}, {kindMagicLink, "magic_link"},
		{kindEmailSignIn, "email_otp:sign-in"}, {kindEmailVerify, "email_otp:verify-email"},
		{kindEmailReset, "email_otp:reset-password"}, {kindPhoneSignIn, "phone:sign-in"},
		{kindPhoneAdd, "phone:add"}, {kindOneTimeToken, "one_time_token"},
	} {
		if c[0] != c[1] {
			t.Errorf("stored format changed: %q, recorded %q", c[0], c[1])
		}
	}
}
