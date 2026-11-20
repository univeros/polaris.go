package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRateLimitDefaultsMatchTheSecuritySpec(t *testing.T) {
	r := DefaultRateLimits()
	want := map[string][2]int{
		"login":           {10, 300},
		"register":        {5, 3600},
		"password_forgot": {5, 3600},
		"token_refresh":   {60, 60},
		"mfa_enroll":      {5, 3600},
		"mfa_confirm":     {10, 300},
		"mfa_send":        {5, 600},
		"token_consume":   {10, 300},
		"authenticated":   {600, 60}, // the global per-user budget (docs/auth/security.md §5)
	}
	got := r.groups()
	if len(got) != len(want) {
		t.Fatalf("%d groups, want %d", len(got), len(want))
	}
	for _, g := range got {
		w, ok := want[g.key]
		if !ok {
			t.Fatalf("unexpected group %q", g.key)
		}
		if g.limit.Limit != w[0] || g.limit.Window != time.Duration(w[1])*time.Second {
			t.Errorf("%s = %d/%v, want %d/%ds", g.key, g.limit.Limit, g.limit.Window, w[0], w[1])
		}
		if g.limit.KeyPrefix != "auth."+g.key {
			t.Errorf("%s prefix = %q", g.key, g.limit.KeyPrefix)
		}
	}
}

func TestRateLimitEachGroupHasADistinctCacheKeyPrefix(t *testing.T) {
	seen := map[string]bool{}
	for _, g := range DefaultRateLimits().groups() {
		if seen[g.limit.KeyPrefix] {
			t.Fatalf("prefix %q collides in a shared cache", g.limit.KeyPrefix)
		}
		seen[g.limit.KeyPrefix] = true
	}
}

func TestRateLimitOverridingOneGroupKeepsTheOthers(t *testing.T) {
	r := DefaultRateLimits()
	r.Login.Limit, r.Login.Window = 3, time.Minute
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.Register.Limit != 5 || r.Login.KeyPrefix != "auth.login" {
		t.Fatalf("untouched values changed: %+v", r)
	}
}

func TestRateLimitRejectsANonPositiveBudget(t *testing.T) {
	err := RateLimit{Limit: 0, Window: time.Minute, KeyPrefix: "p"}.Validate()
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "Limit") {
		t.Fatalf("err = %v", err)
	}
	err = RateLimit{Limit: 1, Window: 0, KeyPrefix: "p"}.Validate()
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "Window") {
		t.Fatalf("err = %v", err)
	}
	if err := (RateLimit{Limit: 1, Window: time.Second}).Validate(); err != nil {
		t.Fatal(err)
	}
}
