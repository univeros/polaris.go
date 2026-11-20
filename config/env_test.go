package config

import (
	"errors"
	"strings"
	"testing"
)

func TestFromLookupReadsSecretsAndAuth(t *testing.T) {
	s, a, err := FromLookup(lookupMap(with(validEnv(),
		"AUTH_ISSUER", "https://auth.example.com",
		"AUTH_AUDIENCE", "https://api.example.com",
		"AUTH_ACCESS_TOKEN_DENYLIST", "1",
		"AUTH_PASSWORD_BREACH_CHECK", "true",
	)))
	if err != nil {
		t.Fatal(err)
	}
	if s.AppKey != testAppKey {
		t.Fatalf("secrets not read: %v", s)
	}
	if a.Issuer != "https://auth.example.com" || a.Audience != "https://api.example.com" {
		t.Fatalf("issuer/audience = %q/%q", a.Issuer, a.Audience)
	}
	if !a.AccessToken.Denylist || !a.Password.BreachCheck {
		t.Fatal("flags not read")
	}
	if a.AccessToken.TTL != Defaults().AccessToken.TTL {
		t.Fatal("everything else keeps its default")
	}
}

func TestFromLookupDefaultsTheIssuerToPolaris(t *testing.T) {
	_, a, err := FromLookup(lookupMap(with(validEnv(), "AUTH_ISSUER", "")))
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer != "polaris" || a.Audience != "" {
		t.Fatalf("issuer/audience = %q/%q", a.Issuer, a.Audience)
	}
}

func TestFromLookupFlagsAcceptOnly1TrueOn(t *testing.T) {
	for value, want := range map[string]bool{"1": true, "true": true, "on": true, "yes": false, "TRUE": false, "0": false, "": false} {
		_, a, err := FromLookup(lookupMap(with(validEnv(), "AUTH_ACCESS_TOKEN_DENYLIST", value)))
		if err != nil {
			t.Fatal(err)
		}
		if a.AccessToken.Denylist != want {
			t.Errorf("AUTH_ACCESS_TOKEN_DENYLIST=%q gave %v, want %v", value, a.AccessToken.Denylist, want)
		}
	}
}

func TestFromLookupFailsWithEveryFix(t *testing.T) {
	s, a, err := FromLookup(lookupMap(map[string]string{}))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	if s.AppKey != "" || a.Issuer != "" {
		t.Fatal("values must be zero on error")
	}
	for _, want := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %s: %v", want, err)
		}
	}
}

func TestFromEnvReadsTheProcessEnvironment(t *testing.T) {
	for k, v := range validEnv() {
		t.Setenv(k, v)
	}
	t.Setenv("AUTH_ISSUER", "from-env")
	_, a, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if a.Issuer != "from-env" {
		t.Fatalf("issuer = %q", a.Issuer)
	}
}
