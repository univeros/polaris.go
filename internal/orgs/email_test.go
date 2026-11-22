package orgs

import (
	"testing"

	"github.com/univeros/polaris.go/identity"
)

// An invitation's address is matched against the account's stored one, so both are normalized by
// the same rule, byte for byte.
func TestNormalizeEmailIsIdentitysRule(t *testing.T) {
	for _, in := range []string{
		"  ADA@Example.com ", "\t\n\r\x00\x0Ba@B.c\n", "ÉLODIE@Example.COM", " a@b.c ",
		"A\xffB@x", "\fA@B.c\f", "İ@X.io", "",
	} {
		if got, want := normalizeEmail(in), identity.NormalizeEmail(in); got != want {
			t.Errorf("normalizeEmail(%q) = %q, identity.NormalizeEmail = %q", in, got, want)
		}
	}
}
