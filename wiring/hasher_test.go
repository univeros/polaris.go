package wiring

import (
	"strings"
	"testing"

	"github.com/univeros/polaris.go/security"
)

type hostHasher struct{ security.PasswordHasher }

// New warns (outside tests) about an Argon2id hasher cheaper than the default, the test hasher
// included; the default, a stronger one and a host's own hasher are not named.
func TestAHasherBelowTheDefaultCostIsNamed(t *testing.T) {
	for name, tc := range map[string]struct {
		hasher security.PasswordHasher
		weak   bool
	}{
		"the default":         {security.Argon2id{}, false},
		"the test hasher":     {security.Argon2id{Memory: 1024, Time: 1, Threads: 1}, true},
		"less memory":         {security.Argon2id{Memory: 19456}, true},
		"fewer passes":        {&security.Argon2id{Time: 1}, true},
		"stronger":            {security.Argon2id{Memory: 131072, Time: 5}, false},
		"a nil pointer":       {(*security.Argon2id)(nil), false},
		"the host's own type": {hostHasher{}, false},
	} {
		detail, weak := weakHasher(tc.hasher)
		if weak != tc.weak || (weak && !strings.Contains(detail, "KiB")) {
			t.Errorf("%s: weak %v (%q), want %v", name, weak, detail, tc.weak)
		}
	}
}
