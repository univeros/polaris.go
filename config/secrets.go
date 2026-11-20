package config

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"
)

// MinAppKeyBytes is the shortest accepted APP_KEY: every key derived from it (peppers, the MFA
// encrypter) is only as strong as the key itself.
const MinAppKeyBytes = 32

const (
	fixAppKey  = `generate one with "openssl rand -base64 32"`
	fixJWTKeys = `generate a pair with "polaris keys:generate" (RS256 PEMs; --alg=EdDSA for base64 Ed25519 keys)`
)

// Secrets are the cryptographic secrets Polaris needs at boot. They are never defaulted.
//
// The values never reach a log or a formatted string: String, GoString and LogValue redact them.
type Secrets struct {
	AppKey string // APP_KEY, at least MinAppKeyBytes bytes
	// JWTPrivateKey is AUTH_JWT_PRIVATE_KEY: a PEM for RS256; for EdDSA the 64-byte libsodium
	// secret key, raw (as upstream reads it) or base64 (as "polaris keys:generate --alg=EdDSA"
	// prints it; SecretsFromLookup decodes it).
	JWTPrivateKey string
	// JWTPublicKey is AUTH_JWT_PUBLIC_KEY: a PEM for RS256; for EdDSA the 32-byte public key, raw
	// or base64 as JWTPrivateKey.
	JWTPublicKey string
	// JWTKeyID is AUTH_JWT_KID; empty means the SHA-256 hex of the public key (see KeyID).
	JWTKeyID string
	// JWTPreviousPublicKey is AUTH_JWT_PREVIOUS_PUBLIC_KEY: the retiring key, kept in the JWKS for
	// one access-token TTL during a rotation. Optional.
	JWTPreviousPublicKey string
	// JWTPreviousKeyID is AUTH_JWT_PREVIOUS_KID; empty means the SHA-256 hex of the previous key.
	JWTPreviousKeyID string
}

var secretEnv = []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_JWT_KID", "AUTH_JWT_PREVIOUS_PUBLIC_KEY", "AUTH_JWT_PREVIOUS_KID"}

// SecretsFromLookup reads the secrets from the environment, trimming surrounding whitespace, and
// validates them. An EdDSA key given in base64 (88 characters for the private key, 44 for a public
// key) is decoded to the raw libsodium bytes; raw keys and PEMs are kept as they are.
func SecretsFromLookup(lookup LookupFunc) (Secrets, error) {
	v := make(map[string]string, len(secretEnv))
	for _, key := range secretEnv {
		raw, _ := lookup(key)
		v[key] = strings.Trim(raw, " \t\n\r\x00\x0B") // PHP trim()'s set
	}
	s := Secrets{
		AppKey:               v["APP_KEY"],
		JWTPrivateKey:        rawEd25519(v["AUTH_JWT_PRIVATE_KEY"], ed25519.PrivateKeySize),
		JWTPublicKey:         rawEd25519(v["AUTH_JWT_PUBLIC_KEY"], ed25519.PublicKeySize),
		JWTKeyID:             v["AUTH_JWT_KID"],
		JWTPreviousPublicKey: rawEd25519(v["AUTH_JWT_PREVIOUS_PUBLIC_KEY"], ed25519.PublicKeySize),
		JWTPreviousKeyID:     v["AUTH_JWT_PREVIOUS_KID"],
	}
	if err := s.Validate(); err != nil {
		return Secrets{}, err
	}
	return s, nil
}

// rawEd25519 decodes v when it is the standard base64 of exactly size bytes. Upstream reads EdDSA
// keys as raw bytes, which an environment variable often cannot hold (a NUL byte, edge whitespace
// lost to trimming). No PEM is 44 or 88 characters long and no raw key is the length of its base64
// form, so nothing else changes.
func rawEd25519(v string, size int) string {
	if len(v) != base64.StdEncoding.EncodedLen(size) {
		return v
	}
	if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b) == size {
		return string(b)
	}
	return v
}

// Validate reports missing secrets and a short APP_KEY.
func (s Secrets) Validate() error {
	var missing, fixes []string
	if strings.TrimSpace(s.AppKey) == "" {
		missing, fixes = append(missing, "APP_KEY"), append(fixes, "APP_KEY: "+fixAppKey)
	}
	if strings.TrimSpace(s.JWTPrivateKey) == "" {
		missing = append(missing, "AUTH_JWT_PRIVATE_KEY")
	}
	if strings.TrimSpace(s.JWTPublicKey) == "" {
		missing = append(missing, "AUTH_JWT_PUBLIC_KEY")
	}
	if len(missing) > len(fixes) {
		fixes = append(fixes, "AUTH_JWT_PRIVATE_KEY and AUTH_JWT_PUBLIC_KEY: "+fixJWTKeys)
	}

	var p problems
	if len(missing) > 0 {
		p.add("missing required Polaris secrets: %s. Set them in the environment; %s", strings.Join(missing, ", "), strings.Join(fixes, "; "))
	}
	if n := len(s.AppKey); strings.TrimSpace(s.AppKey) != "" && n < MinAppKeyBytes {
		p.add("APP_KEY is %d bytes, need at least %d: %s", n, MinAppKeyBytes, fixAppKey)
	}
	return p.err()
}

// KeyID is the kid of the signing key: JWTKeyID, or the SHA-256 hex of the public key.
func (s Secrets) KeyID() string {
	if s.JWTKeyID != "" {
		return s.JWTKeyID
	}
	return fingerprint(s.JWTPublicKey)
}

// PreviousKeyID is the kid of the retiring key, or "" when there is no previous key.
func (s Secrets) PreviousKeyID() string {
	switch {
	case s.JWTPreviousPublicKey == "":
		return ""
	case s.JWTPreviousKeyID != "":
		return s.JWTPreviousKeyID
	}
	return fingerprint(s.JWTPreviousPublicKey)
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// String redacts every secret value.
func (s Secrets) String() string {
	return fmt.Sprintf("config.Secrets{AppKey:[redacted] JWTPrivateKey:[redacted] KeyID:%s PreviousKeyID:%s}", s.KeyID(), s.PreviousKeyID())
}

// GoString redacts every secret value for %#v.
func (s Secrets) GoString() string { return s.String() }

// LogValue redacts every secret value for log/slog; the key ids are public and are kept.
func (s Secrets) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("app_key", "[redacted]"),
		slog.String("jwt_private_key", "[redacted]"),
		slog.String("kid", s.KeyID()),
		slog.String("previous_kid", s.PreviousKeyID()),
	)
}
