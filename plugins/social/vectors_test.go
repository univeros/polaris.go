package social

import "testing"

// The redirect proxy's state signature is verified by another deployment, which may run an
// earlier release during a rollout (testdata/vectors/pepper.json, docs/stored-formats.md).
func TestPepperContextsAreTheStoredOnes(t *testing.T) {
	if proxyContext != "social:proxy" {
		t.Errorf("stored format changed: %q, recorded %q", proxyContext, "social:proxy")
	}
}
