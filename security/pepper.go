package security

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
)

// MinAppKeyBytes is the shortest application key Pepper accepts: HKDF input keying material
// must carry the full 256 bits of the derived keys' strength.
const MinAppKeyBytes = 32

const pepperInfoPrefix = "polaris:pepper:"

// Pepper is keyed hashing for secrets that must be verifiable but never recoverable: refresh
// tokens, OTP codes, recovery codes, reset and verification tokens.
//
// A per-context key is derived from the application key with HKDF-SHA256 (32 bytes, empty
// salt, info "polaris:pepper:<context>"), then values are HMAC-SHA256ed under it and rendered
// as lowercase hex. It is safe for concurrent use and never logs its key.
type Pepper struct {
	appKey []byte
}

// NewPepper returns a Pepper over appKey. It fails with ErrInvalidAppKey when appKey is
// shorter than MinAppKeyBytes.
func NewPepper(appKey string) (*Pepper, error) {
	if len(appKey) < MinAppKeyBytes {
		return nil, fmt.Errorf("%w: Pepper requires an application key of at least %d bytes (set APP_KEY)",
			ErrInvalidAppKey, MinAppKeyBytes)
	}
	return &Pepper{appKey: []byte(appKey)}, nil
}

// Hash returns the keyed HMAC of value for context, as 64 lowercase hex characters.
func (p *Pepper) Hash(context, value string) string {
	key, err := hkdf.Key(sha256.New, p.appKey, nil, pepperInfoPrefix+context, sha256.Size)
	if err != nil {
		// Unreachable: 32 bytes is far below HKDF-SHA256's 255*32-byte limit.
		panic("security: hkdf: " + err.Error())
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// Matches reports, in constant time, whether value re-hashed for context equals hash. An
// empty or non-hexadecimal hash never matches.
func (p *Pepper) Matches(context, value, hash string) bool {
	if hash == "" || !isHex(hash) {
		return false
	}
	return hmac.Equal([]byte(p.Hash(context, value)), []byte(hash))
}

// LogValue keeps the application key out of logs.
func (*Pepper) LogValue() slog.Value { return redacted }

// String keeps the application key out of fmt output.
func (*Pepper) String() string { return redacted.String() }

// GoString keeps the application key out of %#v output.
func (*Pepper) GoString() string { return redacted.String() }

// isHex is PHP's ctype_xdigit: every byte is 0-9, a-f or A-F.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
