package identity

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/univeros/polaris.go/security"
)

// PasswordPolicy is the rule set a new password must pass before it is hashed: a minimum length
// in characters (auth.password.min_length) and, when Breaches is set, the breached-password
// screen (auth.password.breach_check).
type PasswordPolicy struct {
	MinLength int
	Breaches  security.BreachedPasswordCheck // nil: no breach check
}

// Validate returns the violated rules, as the 422 body lists them; none means valid.
func (p PasswordPolicy) Validate(ctx context.Context, password string) []string {
	var violations []string
	if utf8.RuneCountInString(password) < p.MinLength {
		violations = append(violations, fmt.Sprintf("Password must be at least %d characters long.", p.MinLength))
	}
	if p.Breaches != nil && p.Breaches.IsBreached(ctx, password) {
		violations = append(violations, "This password has appeared in a known data breach; choose a different one.")
	}
	return violations
}

func (p PasswordPolicy) enforce(ctx context.Context, password string) error {
	if v := p.Validate(ctx, password); len(v) > 0 {
		return &PasswordError{Violations: v}
	}
	return nil
}

// NormalizeEmail canonicalizes an email so one address always maps to one stored value and one
// lookup key: surrounding whitespace trimmed, ASCII letters lowercased, every other byte (non-ASCII letters included) kept as it
// is. The result is stored, so it must stay byte for byte what earlier releases stored for the
// same input.
func NormalizeEmail(email string) string {
	b := []byte(strings.Trim(email, trimSet)) // bytes, not runes: invalid UTF-8 survives
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// trimSet is the edge characters stripped from emails and names: space, tab, LF, CR, NUL and
// vertical tab. Not strings.TrimSpace: it would also strip form feed and Unicode spaces, changing
// stored values.
const trimSet = " \t\n\r\x00\x0B"
