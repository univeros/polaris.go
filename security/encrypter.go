package security

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	encrypterVersion    byte = 0x01
	encrypterKeyContext      = "polaris:encrypter:mfa"
)

// XChaCha20Poly1305 is the at-rest Encrypter, byte-compatible with upstream's SodiumEncrypter
// (libsodium's crypto_aead_xchacha20poly1305_ietf).
//
// The key is HKDF-SHA256(appKey, 32 bytes, info "polaris:encrypter:mfa", empty salt); the
// additional data is the version byte 0x01; a payload is
// base64(0x01 ‖ nonce(24) ‖ ciphertext ‖ tag(16)). It is safe for concurrent use and never
// logs its key.
type XChaCha20Poly1305 struct {
	aead cipher.AEAD
}

var _ Encrypter = (*XChaCha20Poly1305)(nil)

// NewXChaCha20Poly1305 derives the encryption key from appKey. It fails with
// ErrInvalidAppKey when appKey is empty.
func NewXChaCha20Poly1305(appKey string) (*XChaCha20Poly1305, error) {
	if appKey == "" {
		return nil, fmt.Errorf("%w: the encrypter requires a non-empty application key (set APP_KEY)", ErrInvalidAppKey)
	}
	key, err := hkdf.Key(sha256.New, []byte(appKey), nil, encrypterKeyContext, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("security: deriving encrypter key: %w", err)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("security: encrypter cipher: %w", err)
	}
	return &XChaCha20Poly1305{aead: aead}, nil
}

// Encrypt seals plaintext under a fresh random nonce; the same plaintext never yields the
// same payload twice.
func (e *XChaCha20Poly1305) Encrypt(plaintext string) (string, error) {
	out := make([]byte, 1+chacha20poly1305.NonceSizeX, 1+chacha20poly1305.NonceSizeX+len(plaintext)+chacha20poly1305.Overhead)
	out[0] = encrypterVersion
	if _, err := rand.Read(out[1:]); err != nil {
		return "", fmt.Errorf("security: reading nonce: %w", err)
	}
	out = e.aead.Seal(out, out[1:], []byte(plaintext), []byte{encrypterVersion})
	return base64.StdEncoding.EncodeToString(out), nil
}

// Decrypt opens a payload made by Encrypt (here or upstream). It fails with ErrDecrypt when
// the payload is malformed, tampered with, or sealed under another key.
func (e *XChaCha20Poly1305) Decrypt(payload string) (string, error) {
	raw, ok := phpBase64DecodeStrict(payload)
	minimum := 1 + chacha20poly1305.NonceSizeX + chacha20poly1305.Overhead
	if !ok || len(raw) < minimum || raw[0] != encrypterVersion {
		return "", fmt.Errorf("%w: the encrypted payload is malformed", ErrDecrypt)
	}
	nonce := raw[1 : 1+chacha20poly1305.NonceSizeX]
	plain, err := e.aead.Open(nil, nonce, raw[1+chacha20poly1305.NonceSizeX:], []byte{encrypterVersion})
	if err != nil {
		return "", fmt.Errorf("%w: the encrypted payload could not be authenticated", ErrDecrypt)
	}
	return string(plain), nil
}

// LogValue keeps the key out of logs.
func (*XChaCha20Poly1305) LogValue() slog.Value { return redacted }

// String keeps the key out of fmt output.
func (*XChaCha20Poly1305) String() string { return redacted.String() }

// GoString keeps the key out of %#v output.
func (*XChaCha20Poly1305) GoString() string { return redacted.String() }

// phpBase64DecodeStrict is PHP's base64_decode($s, true): standard alphabet, spaces, tabs,
// CR and LF skipped, padding optional but, when present, exactly right and final; non-zero
// trailing bits accepted.
func phpBase64DecodeStrict(s string) ([]byte, bool) {
	clean := make([]byte, 0, len(s))
	padding := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '=':
			padding++
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
		case isBase64Std(c) && padding == 0:
			clean = append(clean, c)
		default:
			return nil, false
		}
	}
	n := len(clean)
	if n%4 == 1 || (padding > 0 && (padding > 2 || (n+padding)%4 != 0)) {
		return nil, false
	}
	out, err := base64.RawStdEncoding.DecodeString(string(clean))
	return out, err == nil
}
