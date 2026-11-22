package scim

import "testing"

// Stored digests are found again only under the pepper context they were written with
// (testdata/vectors/pepper.json, docs/stored-formats.md): renaming one strands every stored row.
func TestPepperContextsAreTheStoredOnes(t *testing.T) {
	if pepperContext != "scim_token" {
		t.Errorf("stored format changed: %q, recorded %q", pepperContext, "scim_token")
	}
}
