package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const testAppKey = "app-key-value-0123456789abcdef01"

func validEnv() map[string]string {
	return map[string]string{
		"APP_KEY":              testAppKey,
		"AUTH_JWT_PRIVATE_KEY": "private-key-pem",
		"AUTH_JWT_PUBLIC_KEY":  "public-key-pem",
	}
}

func lookupMap(env map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func with(env map[string]string, kv ...string) map[string]string {
	out := make(map[string]string, len(env)+len(kv)/2)
	for k, v := range env {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i]] = kv[i+1]
	}
	return out
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestSecretsBuildsFromCompleteEnvironment(t *testing.T) {
	s, err := SecretsFromLookup(lookupMap(validEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if s.AppKey != testAppKey || s.JWTPrivateKey != "private-key-pem" || s.JWTPublicKey != "public-key-pem" {
		t.Fatalf("unexpected secrets: %#v", []string{s.AppKey, s.JWTPrivateKey, s.JWTPublicKey})
	}
	if s.KeyID() == "" {
		t.Fatal("a kid is derived from the public key when not supplied")
	}
}

func TestSecretsUsesExplicitKidWhenProvided(t *testing.T) {
	s, err := SecretsFromLookup(lookupMap(with(validEnv(), "AUTH_JWT_KID", "key-2026")))
	if err != nil {
		t.Fatal(err)
	}
	if s.KeyID() != "key-2026" {
		t.Fatalf("kid = %q", s.KeyID())
	}
}

func TestSecretsDerivedKidIsTheFullSha256Fingerprint(t *testing.T) {
	a, _ := SecretsFromLookup(lookupMap(validEnv()))
	b, _ := SecretsFromLookup(lookupMap(validEnv()))
	if a.KeyID() != b.KeyID() || a.KeyID() != sha("public-key-pem") {
		t.Fatalf("kid = %q, want %q", a.KeyID(), sha("public-key-pem"))
	}
}

func TestSecretsPreviousKey(t *testing.T) {
	s, err := SecretsFromLookup(lookupMap(with(validEnv(), "AUTH_JWT_PREVIOUS_PUBLIC_KEY", "previous-key-pem")))
	if err != nil {
		t.Fatal(err)
	}
	if s.PreviousKeyID() != sha("previous-key-pem") {
		t.Fatalf("previous kid = %q", s.PreviousKeyID())
	}

	s, _ = SecretsFromLookup(lookupMap(with(validEnv(), "AUTH_JWT_PREVIOUS_PUBLIC_KEY", "previous-key-pem", "AUTH_JWT_PREVIOUS_KID", "old")))
	if s.PreviousKeyID() != "old" {
		t.Fatalf("previous kid = %q", s.PreviousKeyID())
	}

	// A previous kid without a previous key is ignored, as upstream.
	s, _ = SecretsFromLookup(lookupMap(with(validEnv(), "AUTH_JWT_PREVIOUS_KID", "old")))
	if s.PreviousKeyID() != "" {
		t.Fatalf("previous kid = %q, want empty", s.PreviousKeyID())
	}
}

func TestSecretsRejectsMissingSecretsAndNamesThem(t *testing.T) {
	_, err := SecretsFromLookup(lookupMap(map[string]string{"APP_KEY": testAppKey}))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("err = %v, want ErrInvalid", err)
	}
	for _, want := range []string{"AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "openssl"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "APP_KEY,") {
		t.Errorf("APP_KEY is present, must not be reported missing: %v", err)
	}
}

func TestSecretsRejectsAnAppKeyShorterThan32Bytes(t *testing.T) {
	_, err := SecretsFromLookup(lookupMap(with(validEnv(), "APP_KEY", "only-31-bytes-0123456789abcdef0")))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "APP_KEY is 31 bytes") {
		t.Fatalf("err = %v", err)
	}
}

func TestSecretsTreatsBlankValuesAsMissing(t *testing.T) {
	_, err := SecretsFromLookup(lookupMap(with(validEnv(), "APP_KEY", "   ")))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "APP_KEY") {
		t.Fatalf("err = %v", err)
	}
}

func TestSecretsAreTrimmed(t *testing.T) {
	s, err := SecretsFromLookup(lookupMap(with(validEnv(), "AUTH_JWT_PUBLIC_KEY", "\n public-key-pem\t\n")))
	if err != nil {
		t.Fatal(err)
	}
	if s.JWTPublicKey != "public-key-pem" || s.KeyID() != sha("public-key-pem") {
		t.Fatalf("public key not trimmed: %q", s.JWTPublicKey)
	}
}

func TestSecretsNeverPrintOrLogTheirValues(t *testing.T) {
	s, _ := SecretsFromLookup(lookupMap(validEnv()))
	var buf strings.Builder
	slog.New(slog.NewTextHandler(&buf, nil)).Info("boot", "secrets", s)
	for _, out := range []string{fmt.Sprint(s), fmt.Sprintf("%+v", s), fmt.Sprintf("%#v", s), buf.String()} {
		for _, secret := range []string{testAppKey, "private-key-pem"} {
			if strings.Contains(out, secret) {
				t.Errorf("secret %q leaked in %q", secret, out)
			}
		}
	}
	if !strings.Contains(buf.String(), s.KeyID()) {
		t.Errorf("the kid is public and helps debugging; want it logged: %s", buf.String())
	}
}
