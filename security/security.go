// Package security holds Polaris's secret-handling primitives: password hashing (Argon2id, PHC
// strings), keyed hashing of verifiable secrets (Pepper), authenticated encryption of secrets at
// rest (XChaCha20-Poly1305) and breached-password screening (HIBP k-anonymity).
//
// Every format here is frozen: a hash, digest or payload made by an earlier release keeps
// verifying, given the same APP_KEY (testdata/vectors holds the known-answer vectors).
// Comparisons are constant-time and secret-bearing types redact themselves in slog output.
package security

import (
	"context"
	"errors"
	"log/slog"
)

// PasswordHasher hashes and verifies user passwords as self-describing hash strings.
type PasswordHasher interface {
	// Hash returns a self-describing hash of plain.
	Hash(plain string) (string, error)
	// Verify reports, in constant time, whether plain matches hash.
	Verify(plain, hash string) bool
	// NeedsRehash reports whether hash was made with other parameters and should be
	// replaced on the next successful sign-in.
	NeedsRehash(hash string) bool
}

// Encrypter is authenticated encryption of secrets at rest (TOTP seeds).
type Encrypter interface {
	// Encrypt seals plaintext into an opaque, printable payload.
	Encrypt(plaintext string) (string, error)
	// Decrypt opens a payload made by Encrypt; it fails with ErrDecrypt when the payload is
	// malformed, tampered with, or sealed under another key.
	Decrypt(payload string) (string, error)
}

// BreachedPasswordCheck tells whether a candidate password is known from public credential
// dumps. Implementations are fail-open: when the source is unreachable they return false
// rather than blocking sign-ups on a third-party outage.
type BreachedPasswordCheck interface {
	IsBreached(ctx context.Context, password string) bool
}

var (
	// ErrDecrypt reports a payload that is malformed, tampered with, or sealed under another key.
	ErrDecrypt = errors.New("security: cannot decrypt payload")
	// ErrInvalidAppKey reports an application key unfit for key derivation. Fix: set APP_KEY to
	// a random value of at least 32 bytes.
	ErrInvalidAppKey = errors.New("security: invalid application key")
	// ErrInvalidParams reports Argon2id cost parameters outside the allowed range.
	ErrInvalidParams = errors.New("security: invalid argon2id parameters")
)

// redacted is what secret-bearing types log instead of their key material.
var redacted = slog.StringValue("[REDACTED]")
