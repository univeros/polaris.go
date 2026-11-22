package config

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strings"

	"github.com/univeros/polaris.go/internal/strutil"
	"github.com/univeros/polaris.go/token"
)

// MinAppKeyBytes is the shortest accepted APP_KEY: every key derived from it (peppers, the MFA
// encrypter) is only as strong as the key itself.
const MinAppKeyBytes = 32

const (
	fixAppKey  = `generate one with "openssl rand -base64 32"`
	fixJWTKeys = `generate a pair with "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private.pem && openssl pkey -in private.pem -pubout -out public.pem" and export the PEM contents (EdDSA: "polaris keys:generate --alg=EdDSA")`
)

// Secrets are the cryptographic secrets Polaris needs at boot. They are never defaulted.
//
// The values never reach a log or a formatted string: String, GoString and LogValue redact them.
//
// APP_KEY is fixed for the life of a deployment in 1.x: keep it, back it up with the database,
// and never change it. Every peppered digest Polaris stores (refresh tokens, API keys, operator
// and SCIM tokens, OAuth client secrets, codes and refresh tokens, recovery codes, verification,
// reset, invitation and passwordless tokens) is an HMAC under a key derived from it, and every
// encrypted secret (TOTP secrets, SSO client secrets, social provider tokens, audit drain secrets)
// is encrypted under another. A new APP_KEY makes all of them unmatchable or unreadable: sessions,
// API keys and second factors stop working. There is no key ring in 1.x; one (APP_KEY_PREVIOUS)
// can be added later without a format change, since encrypted values carry a version byte and a
// peppered lookup can try both keys (decision 73, docs/stored-formats.md).
//
// The JWT signing key, unlike APP_KEY, rotates: AUTH_JWT_PREVIOUS_PUBLIC_KEY keeps the retiring
// key verifying while the new one signs.
type Secrets struct {
	AppKey string // APP_KEY, at least MinAppKeyBytes bytes; fixed for the life of a deployment
	// JWTPrivateKey is AUTH_JWT_PRIVATE_KEY: a PEM for RS256; for EdDSA the 64-byte libsodium
	// secret key, raw or base64 (as "polaris keys:generate --alg=EdDSA"
	// prints it; SecretsFromLookup decodes it).
	JWTPrivateKey string
	// JWTPublicKey is AUTH_JWT_PUBLIC_KEY: a PEM for RS256; for EdDSA the 32-byte public key, raw
	// or base64 as JWTPrivateKey.
	JWTPublicKey string
	// JWTKeyID is AUTH_JWT_KID; empty means the RFC 7638 thumbprint of the public key (see KeyID).
	JWTKeyID string
	// JWTPreviousPublicKey is AUTH_JWT_PREVIOUS_PUBLIC_KEY: the retiring key, kept in the JWKS for
	// one access-token TTL during a rotation. Optional.
	JWTPreviousPublicKey string
	// JWTPreviousKeyID is AUTH_JWT_PREVIOUS_KID; empty means the RFC 7638 thumbprint of the
	// previous key.
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
		v[key] = strutil.Trim(raw)
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

// rawEd25519 decodes v when it is the standard base64 of exactly size bytes. A raw EdDSA key is
// accepted too, but an environment variable often cannot hold (a NUL byte, edge whitespace
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

// KeyID is the kid of the signing key: JWTKeyID, or the RFC 7638 thumbprint of the public key
// (token.Thumbprint; decision 73), which depends on the key and not on how its PEM is encoded.
// It is "" when the key does not parse; building the token codec reports why.
func (s Secrets) KeyID() string { return keyID(s.JWTKeyID, s.JWTPublicKey) }

// PreviousKeyID is the kid of the retiring key, as KeyID, or "" when there is no previous key.
func (s Secrets) PreviousKeyID() string {
	if s.JWTPreviousPublicKey == "" {
		return ""
	}
	return keyID(s.JWTPreviousKeyID, s.JWTPreviousPublicKey)
}

// LegacyKeyID is the kid releases before decision 73 derived by default for the signing key: the
// SHA-256 hex of the public key as configured. Polaris accepts tokens naming it and publishes the
// key under it too, so tokens and cached key sets from those releases keep working. It is "" when
// AUTH_JWT_KID is set: an explicit kid never changed, so it has no alias.
func (s Secrets) LegacyKeyID() string { return legacyKeyID(s.JWTKeyID, s.JWTPublicKey) }

// PreviousLegacyKeyID is LegacyKeyID for the retiring key, or "" when there is no previous key or
// AUTH_JWT_PREVIOUS_KID is set.
func (s Secrets) PreviousLegacyKeyID() string {
	return legacyKeyID(s.JWTPreviousKeyID, s.JWTPreviousPublicKey)
}

func keyID(explicit, publicKey string) string {
	if explicit != "" {
		return explicit
	}
	// The form tells the algorithm apart: an EdDSA public key is 32 raw bytes, never a PEM.
	alg := token.RS256
	if len(publicKey) == ed25519.PublicKeySize {
		alg = token.EdDSA
	}
	kid, _ := token.Thumbprint(alg, publicKey) // "" for an unparseable key; token.New reports it
	return kid
}

func legacyKeyID(explicit, publicKey string) string {
	if explicit != "" || publicKey == "" {
		return ""
	}
	return fingerprint(publicKey)
}

// fingerprint is the legacy default kid: the SHA-256 hex of the key text (decision 73).
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
