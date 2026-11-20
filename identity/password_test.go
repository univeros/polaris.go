package identity

// Port of tests/Identity/PasswordPolicyTest plus the EmailNormalizer contract.

import (
	"context"
	"strings"
	"testing"
)

type breached bool

func (b breached) IsBreached(context.Context, string) bool { return bool(b) }

func TestPasswordPolicy(t *testing.T) {
	t.Run("testAcceptsAPasswordMeetingTheMinimumLength", func(t *testing.T) {
		if v := (PasswordPolicy{MinLength: 12}).Validate(ctx, password); len(v) != 0 {
			t.Fatal(v)
		}
	})
	t.Run("testRejectsAShortPassword", func(t *testing.T) {
		v := (PasswordPolicy{MinLength: 12}).Validate(ctx, "short")
		if len(v) != 1 || v[0] != "Password must be at least 12 characters long." {
			t.Fatal(v)
		}
	})
	t.Run("testRejectsABreachedPasswordWhenTheCheckIsWired", func(t *testing.T) {
		v := (PasswordPolicy{MinLength: 12, Breaches: breached(true)}).Validate(ctx, password)
		if len(v) != 1 || !strings.Contains(v[0], "data breach") {
			t.Fatal(v)
		}
	})
	t.Run("testSkipsTheBreachCheckWhenNotWired", func(t *testing.T) {
		if v := (PasswordPolicy{MinLength: 12, Breaches: breached(false)}).Validate(ctx, password); len(v) != 0 {
			t.Fatal(v)
		}
	})
	t.Run("testCountsCharactersNotBytes", func(t *testing.T) {
		if v := (PasswordPolicy{MinLength: 12}).Validate(ctx, strings.Repeat("é", 12)); len(v) != 0 {
			t.Fatal(v)
		}
	})
	t.Run("both rules fail together", func(t *testing.T) {
		if v := (PasswordPolicy{MinLength: 12, Breaches: breached(true)}).Validate(ctx, "short"); len(v) != 2 {
			t.Fatal(v)
		}
	})
}

func TestNormalizeEmailMatchesPHPStrtolowerTrim(t *testing.T) {
	for in, want := range map[string]string{
		"  ADA@Example.com ":    "ada@example.com",
		"\t\n\r\x00\x0Ba@B.c\n": "a@b.c",
		"ÉLODIE@Example.COM":    "Élodie@example.com", // strtolower is ASCII only
		" a@b.c ":               " a@b.c ",            // trim does not strip Unicode spaces
		"A\xffB@x":              "a\xffb@x",           // invalid UTF-8 kept byte for byte
		"already@normalized.io": "already@normalized.io",
	} {
		if got := NormalizeEmail(in); got != want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPasswordErrorMatchesItsSentinel(t *testing.T) {
	var err error = &PasswordError{Violations: []string{"x"}}
	isErr(t, err, ErrInvalidPassword)
	if err.Error() != "The password does not meet the policy requirements." {
		t.Fatal(err)
	}
}
