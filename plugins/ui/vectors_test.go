package ui

import "testing"

// Stored digests are found again only under the pepper context they were written with
// (testdata/vectors/pepper.json, docs/stored-formats.md): renaming this one invalidates every
// open sign-in form.
func TestPepperContextsAreTheStoredOnes(t *testing.T) {
	if csrfContext != "ui.csrf" {
		t.Errorf("stored format changed: %q, recorded %q", csrfContext, "ui.csrf")
	}
}
