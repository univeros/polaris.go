package security

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id cost defaults (OWASP): 64 MiB, 4 passes, 1 lane.
const (
	DefaultArgon2Memory  uint32 = 65536
	DefaultArgon2Time    uint32 = 4
	DefaultArgon2Threads uint8  = 1
)

const (
	argon2Version  = argon2.Version // 0x13 = 19, the only version libargon2 emits
	argon2SaltLen  = 16
	argon2HashLen  = 32
	argon2MinSalt  = 8 // libargon2 ARGON2_MIN_SALT_LENGTH
	argon2MinHash  = 4 // libargon2 ARGON2_MIN_OUTLEN
	argon2MinBlock = 8 // libargon2 ARGON2_MIN_MEMORY per lane (2 * SYNC_POINTS)
	bcryptMaxBytes = 72
)

// Argon2id hashes passwords as PHC strings "$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>" with a 16-byte
// random salt, a 32-byte hash and unpadded standard base64.
//
// Zero fields take the defaults (64 MiB, t=4, p=1). Verify accepts every hash an earlier
// release may have stored: Argon2id and Argon2i (v=19) and bcrypt ($2a$, $2b$, $2y$).
// It is safe for concurrent use.
type Argon2id struct {
	Memory  uint32 // KiB
	Time    uint32 // passes
	Threads uint8  // lanes
}

var _ PasswordHasher = Argon2id{}

func (a Argon2id) params() (memory, time uint32, threads uint8) {
	memory, time, threads = a.Memory, a.Time, a.Threads
	if memory == 0 {
		memory = DefaultArgon2Memory
	}
	if time == 0 {
		time = DefaultArgon2Time
	}
	if threads == 0 {
		threads = DefaultArgon2Threads
	}
	return memory, time, threads
}

// Hash returns the PHC string of plain under a fresh random salt. It fails with
// ErrInvalidParams when memory is below 8 KiB per lane (libargon2's floor).
func (a Argon2id) Hash(plain string) (string, error) {
	memory, time, threads := a.params()
	if memory < argon2MinBlock*uint32(threads) {
		return "", fmt.Errorf("%w: memory %d KiB is below %d KiB per lane", ErrInvalidParams, memory, argon2MinBlock)
	}
	salt := make([]byte, argon2SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("security: reading salt: %w", err)
	}
	sum := argon2.IDKey([]byte(plain), salt, time, memory, threads, argon2HashLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2Version, memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(sum)), nil
}

// Verify reports whether plain matches hash, comparing in constant time. An empty or
// unrecognised hash never matches.
func (Argon2id) Verify(plain, hash string) bool {
	switch {
	case hash == "":
		return false
	case strings.HasPrefix(hash, "$argon2id$"):
		return verifyArgon2(plain, hash, "$argon2id", argon2.IDKey)
	case strings.HasPrefix(hash, "$argon2i$"):
		return verifyArgon2(plain, hash, "$argon2i", argon2.Key)
	case strings.HasPrefix(hash, "$2a$"), strings.HasPrefix(hash, "$2b$"), strings.HasPrefix(hash, "$2y$"):
		// $2x$ (crypt_blowfish's bug-compatible mode) is not emulated and never matches.
		return verifyBcrypt(plain, hash)
	}
	return false
}

// NeedsRehash mirrors password_needs_rehash(PASSWORD_ARGON2ID, options): true for any other
// algorithm, or when the encoded version, memory, time or lanes differ from this hasher's.
func (a Argon2id) NeedsRehash(hash string) bool {
	if !strings.HasPrefix(hash, "$argon2id$") {
		return true
	}
	memory, time, threads := a.params()
	v, m, t, p := scanArgon2Params(hash[len("$argon2id"):])
	return v != argon2Version || m != int64(memory) || t != int64(time) || p != int64(threads)
}

type argon2Func func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

// verifyArgon2 decodes a PHC string the way libargon2's decode_string does (strict decimals
// without leading zeros, strict unpadded base64, nothing trailing) and recomputes the hash.
func verifyArgon2(plain, hash, prefix string, derive argon2Func) bool {
	s := strings.TrimPrefix(hash, prefix)
	version := uint64(0x10) // libargon2: an absent v= means version 1.0
	if rest, ok := strings.CutPrefix(s, "$v="); ok {
		var good bool
		if version, s, good = cutDecimal(rest); !good {
			return false
		}
	}
	m, s, ok1 := cutField(s, "$m=")
	t, s, ok2 := cutField(s, ",t=")
	p, s, ok3 := cutField(s, ",p=")
	if !ok1 || !ok2 || !ok3 || version != argon2Version {
		// x/crypto/argon2 computes v=19 only; no stored hash carries another version.
		return false
	}
	rest, ok4 := strings.CutPrefix(s, "$")
	saltB64, hashB64, ok5 := strings.Cut(rest, "$")
	if !ok4 || !ok5 {
		return false
	}
	salt, err1 := decodePHCBase64(saltB64)
	want, err2 := decodePHCBase64(hashB64)
	if err1 != nil || err2 != nil || len(salt) < argon2MinSalt || len(want) < argon2MinHash {
		return false
	}
	if t < 1 || t > 1<<32-1 || p < 1 || p > 255 || m > 1<<32-1 || m < argon2MinBlock*p {
		return false
	}
	got := derive([]byte(plain), salt, uint32(t), uint32(m), uint8(p), uint32(len(want))) //nolint:gosec // G115: t, m, p bounded above; len(want) is a decoded hash
	return subtle.ConstantTimeCompare(got, want) == 1
}

func cutField(s, label string) (uint64, string, bool) {
	rest, ok := strings.CutPrefix(s, label)
	if !ok {
		return 0, s, false
	}
	return cutDecimal(rest)
}

// cutDecimal reads an unsigned decimal with no sign and no leading zero (libargon2's
// decode_decimal) and returns it with the remaining input.
func cutDecimal(s string) (uint64, string, bool) {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 || (s[0] == '0' && i > 1) {
		return 0, s, false
	}
	n, err := strconv.ParseUint(s[:i], 10, 64)
	if err != nil {
		return 0, s, false
	}
	return n, s[i:], true
}

// decodePHCBase64 is libargon2's from_base64: standard alphabet, no padding, zero trailing
// bits, nothing else (Go's decoder would otherwise skip CR/LF).
func decodePHCBase64(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		if !isBase64Std(s[i]) {
			return nil, errInvalidBase64
		}
	}
	return base64.RawStdEncoding.Strict().DecodeString(s)
}

var errInvalidBase64 = errors.New("security: invalid base64")

func isBase64Std(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// scanArgon2Params reads "$v=<n>$m=<n>,t=<n>,p=<n>" leniently, as signed decimals that may
// carry leading whitespace and zeros: fields after the first mismatch stay zero.
func scanArgon2Params(s string) (v, m, t, p int64) {
	out := []*int64{&v, &m, &t, &p}
	for i, label := range []string{"$v=", "$m=", ",t=", ",p="} {
		rest, ok := strings.CutPrefix(s, label)
		if !ok {
			return v, m, t, p
		}
		n, after, ok := scanLLD(rest)
		if !ok {
			return v, m, t, p
		}
		*out[i], s = n, after
	}
	return v, m, t, p
}

// scanLLD is C's %lld: optional leading whitespace, optional sign, at least one digit.
func scanLLD(s string) (int64, string, bool) {
	s = strings.TrimLeft(s, " \t\n\v\f\r")
	i := 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start {
		return 0, s, false
	}
	n, err := strconv.ParseInt(s[:i], 10, 64)
	if err != nil {
		return 0, s, false
	}
	return n, s[i:], true
}

// verifyBcrypt matches crypt_blowfish: the password ends at its first NUL
// byte and only its first 72 bytes count.
func verifyBcrypt(plain, hash string) bool {
	pw := []byte(plain)
	if i := bytes.IndexByte(pw, 0); i >= 0 {
		pw = pw[:i]
	}
	if len(pw) > bcryptMaxBytes {
		pw = pw[:bcryptMaxBytes]
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), pw) == nil
}
