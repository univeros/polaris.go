package mfa

import "testing"

// Stored digests are found again only under the pepper context they were written with
// (testdata/vectors/pepper.json, docs/stored-formats.md): renaming one strands every stored row.
func TestPepperContextsAreTheStoredOnes(t *testing.T) {
	for _, c := range [][2]string{{recoveryPepperContext, "recovery"}, {otpPepperContext, "otp"}} {
		if c[0] != c[1] {
			t.Errorf("stored format changed: %q, recorded %q", c[0], c[1])
		}
	}
}
