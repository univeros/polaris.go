package admin

import "testing"

// Stored digests are found again only under the pepper context they were written with
// (testdata/vectors/pepper.json, docs/stored-formats.md): renaming one strands every stored row.
func TestPepperContextsAreTheStoredOnes(t *testing.T) {
	if keyPepperContext != "admin_key" {
		t.Errorf("stored format changed: %q, recorded %q", keyPepperContext, "admin_key")
	}
}
