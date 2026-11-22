package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// SupportedHashFormats names the hash strings Argon2id verifies, as CheckHash's errors list them.
const SupportedHashFormats = "$argon2id$ and $argon2i$ (v=19); bcrypt $2a$, $2b$, $2y$; " +
	"Django pbkdf2_sha256$ and scrypt$; passlib $pbkdf2-sha256$, $pbkdf2-sha512$ and $scrypt$; " +
	"Firebase $firebase-scrypt$"

// Bounds on what an imported hash string may ask for. A stored hash is data: the upper bounds
// keep a corrupt or hostile row from turning one sign-in into minutes of CPU or gigabytes of
// memory; the lower bounds refuse strings too weak or too short to be a real password hash.
const (
	maxImportedLen   = 1024      // characters of the whole hash string
	pbkdf2MinIter    = 1_000     // RFC 8018 §4.2's minimum
	pbkdf2MaxIter    = 5_000_000 // under three times Django's pbkdf2_sha256 default (1,800,000)
	scryptMinMemory  = 1 << 20   // 128·r·N bytes: 1 MiB (N=1024, r=8)
	scryptMaxMemory  = 256 << 20 // 128·r·N bytes: 256 MiB (N=2^18, r=8)
	scryptMaxWork    = 1 << 30   // 128·r·N·p bytes mixed in total
	scryptMaxP       = 16
	importedMinSalt  = 4 // bytes; the shortest salt of the published vectors (RFC 7914's "NaCl")
	importedMaxSalt  = 256
	importedMinKey   = 16 // bytes of derived key (hash) stored
	importedMaxKey   = 64
	firebaseKeyLen   = 32 // AES-256 key from scrypt
	firebaseMaxSep   = 16
	bcryptImportCost = 16      // imports only; Verify reads every bcrypt cost it read before
	argon2ImportMem  = 1 << 20 // KiB (1 GiB); imports only, as for bcrypt
	argon2ImportWork = 1 << 22 // KiB × passes; imports only
)

// ErrUnsupportedHash reports a password hash string the hasher cannot verify: an unknown format,
// a malformed string or a cost outside the accepted bounds. The error wrapping it says which,
// and lists SupportedHashFormats.
var ErrUnsupportedHash = errors.New("security: unsupported password hash")

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: %s; supported: %s", ErrUnsupportedHash, fmt.Sprintf(format, args...), SupportedHashFormats)
}

// imported is a verify-only hash string, parsed and bounds-checked: derive recomputes the stored
// value (want) from a candidate password.
type imported struct {
	want   []byte
	derive func(plain []byte) []byte
}

func (h imported) verify(plain string) bool {
	return subtle.ConstantTimeCompare(h.derive([]byte(plain)), h.want) == 1
}

// parseImported reads the verify-only formats: Django's and passlib's PBKDF2 and scrypt, and
// Firebase's scrypt. errNotImported means the string is none of them.
func parseImported(s string) (imported, error) {
	if len(s) > maxImportedLen {
		return imported{}, unsupported("longer than %d characters", maxImportedLen)
	}
	f := strings.Split(s, "$")
	switch {
	case f[0] == "pbkdf2_sha256":
		return parseDjangoPBKDF2(f)
	case f[0] == "scrypt":
		return parseDjangoScrypt(f)
	case f[0] != "" || len(f) < 2:
		return imported{}, errNotImported
	case f[1] == "pbkdf2-sha256":
		return parsePasslibPBKDF2(f, sha256.New)
	case f[1] == "pbkdf2-sha512":
		return parsePasslibPBKDF2(f, sha512.New)
	case f[1] == "scrypt":
		return parsePHCScrypt(f)
	case f[1] == "firebase-scrypt":
		return parseFirebaseScrypt(f)
	}
	return imported{}, errNotImported
}

var errNotImported = unsupported("unknown format")

// parseDjangoPBKDF2 reads Django's "pbkdf2_sha256$<iterations>$<salt>$<base64 hash>"; the salt
// is used as its text.
func parseDjangoPBKDF2(f []string) (imported, error) {
	if len(f) != 4 {
		return imported{}, unsupported("pbkdf2_sha256 wants 4 $-separated fields, got %d", len(f))
	}
	iter, err := decimal(f[1], "iterations")
	if err != nil {
		return imported{}, err
	}
	want, err := decodeImportedB64(f[3], "hash")
	if err != nil {
		return imported{}, err
	}
	return newPBKDF2(sha256.New, iter, []byte(f[2]), want)
}

// parsePasslibPBKDF2 reads passlib's "$pbkdf2-<digest>$<rounds>$<ab64 salt>$<ab64 hash>".
func parsePasslibPBKDF2(f []string, h func() hash.Hash) (imported, error) {
	if len(f) != 5 {
		return imported{}, unsupported("$%s$ wants <rounds>$<salt>$<hash>", f[1])
	}
	iter, err := decimal(f[2], "rounds")
	if err != nil {
		return imported{}, err
	}
	salt, err := decodeImportedB64(f[3], "salt")
	if err != nil {
		return imported{}, err
	}
	want, err := decodeImportedB64(f[4], "hash")
	if err != nil {
		return imported{}, err
	}
	return newPBKDF2(h, iter, salt, want)
}

func newPBKDF2(h func() hash.Hash, iter uint64, salt, want []byte) (imported, error) {
	if iter < pbkdf2MinIter || iter > pbkdf2MaxIter {
		return imported{}, unsupported("PBKDF2 iterations %d outside [%d, %d]", iter, pbkdf2MinIter, pbkdf2MaxIter)
	}
	if err := checkSaltAndKey(salt, want); err != nil {
		return imported{}, err
	}
	return imported{want: want, derive: func(plain []byte) []byte {
		key, err := pbkdf2.Key(h, string(plain), salt, int(iter), len(want)) //nolint:gosec // G115: iter bounded above
		if err != nil {
			return nil // never matches
		}
		return key
	}}, nil
}

// parseDjangoScrypt reads Django's "scrypt$<N>$<salt>$<r>$<p>$<base64 hash>"; the salt is used
// as its text.
func parseDjangoScrypt(f []string) (imported, error) {
	if len(f) != 6 {
		return imported{}, unsupported("scrypt wants 6 $-separated fields, got %d", len(f))
	}
	n, err := decimal(f[1], "N")
	if err != nil {
		return imported{}, err
	}
	r, err := decimal(f[3], "r")
	if err != nil {
		return imported{}, err
	}
	p, err := decimal(f[4], "p")
	if err != nil {
		return imported{}, err
	}
	if n < 2 || n&(n-1) != 0 || n > 1<<30 {
		return imported{}, unsupported("scrypt N %d is not a power of two up to 2^30", n)
	}
	want, err := decodeImportedB64(f[5], "hash")
	if err != nil {
		return imported{}, err
	}
	return newScrypt(n, r, p, []byte(f[2]), want)
}

// parsePHCScrypt reads "$scrypt$ln=<log2 N>,r=<r>,p=<p>$<salt>$<hash>" (passlib; standard or
// passlib base64).
func parsePHCScrypt(f []string) (imported, error) {
	if len(f) != 5 {
		return imported{}, unsupported("$scrypt$ wants ln=,r=,p=$<salt>$<hash>")
	}
	ln, rest, ok1 := cutField(f[2], "ln=")
	r, rest, ok2 := cutField(rest, ",r=")
	p, rest, ok3 := cutField(rest, ",p=")
	if !ok1 || !ok2 || !ok3 || rest != "" {
		return imported{}, unsupported("$scrypt$ parameters must be ln=<n>,r=<n>,p=<n>")
	}
	if ln < 1 || ln > 30 {
		return imported{}, unsupported("scrypt ln %d outside [1, 30]", ln)
	}
	salt, err := decodeImportedB64(f[3], "salt")
	if err != nil {
		return imported{}, err
	}
	want, err := decodeImportedB64(f[4], "hash")
	if err != nil {
		return imported{}, err
	}
	return newScrypt(1<<ln, r, p, salt, want)
}

func newScrypt(n, r, p uint64, salt, want []byte) (imported, error) {
	if err := checkScrypt(n, r, p); err != nil {
		return imported{}, err
	}
	if err := checkSaltAndKey(salt, want); err != nil {
		return imported{}, err
	}
	return imported{want: want, derive: func(plain []byte) []byte {
		key, err := scrypt.Key(plain, salt, int(n), int(r), int(p), len(want)) //nolint:gosec // G115: n, r, p bounded by checkScrypt
		if err != nil {
			return nil
		}
		return key
	}}, nil
}

// checkScrypt bounds scrypt's memory (128·r·N bytes) and total work (times p). n is a power of
// two of at most 2^30.
func checkScrypt(n, r, p uint64) error {
	if r < 1 || r > 1<<16 || p < 1 || p > scryptMaxP {
		return unsupported("scrypt r %d or p %d outside [1, 65536] and [1, %d]", r, p, scryptMaxP)
	}
	memory := 128 * r * n // ≤ 2^7 · 2^16 · 2^30: no overflow
	if memory < scryptMinMemory || memory > scryptMaxMemory || memory*p > scryptMaxWork {
		return unsupported("scrypt memory 128·r·N = %d bytes outside [%d, %d], or times p above %d",
			memory, scryptMinMemory, scryptMaxMemory, scryptMaxWork)
	}
	return nil
}

// parseFirebaseScrypt reads "$firebase-scrypt$ln=<mem_cost>,r=<rounds>,sep=<base64 salt
// separator>,key=<base64 signer key>$<base64 salt>$<base64 password hash>", the values of a
// Firebase Auth export and its project's hash parameters. The stored hash is the signer key
// encrypted with AES-256-CTR (zero IV) under scrypt(password, salt‖separator, 2^ln, r, 1, 32).
func parseFirebaseScrypt(f []string) (imported, error) {
	if len(f) != 5 {
		return imported{}, unsupported("$firebase-scrypt$ wants ln=,r=,sep=,key=$<salt>$<hash>")
	}
	ln, rest, ok1 := cutField(f[2], "ln=")
	r, rest, ok2 := cutField(rest, ",r=")
	rest, ok3 := strings.CutPrefix(rest, ",sep=")
	sepB64, keyParam, ok4 := strings.Cut(rest, ",")
	keyB64, ok5 := strings.CutPrefix(keyParam, "key=")
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return imported{}, unsupported("$firebase-scrypt$ parameters must be ln=<n>,r=<n>,sep=<base64>,key=<base64>")
	}
	if ln < 1 || ln > 30 {
		return imported{}, unsupported("firebase-scrypt ln %d outside [1, 30]", ln)
	}
	if err := checkScrypt(1<<ln, r, 1); err != nil {
		return imported{}, err
	}
	sep, err := decodeImportedB64(sepB64, "salt separator")
	if err != nil && sepB64 != "" {
		return imported{}, err
	}
	signer, err := decodeImportedB64(keyB64, "signer key")
	if err != nil {
		return imported{}, err
	}
	salt, err := decodeImportedB64(f[3], "salt")
	if err != nil {
		return imported{}, err
	}
	want, err := decodeImportedB64(f[4], "hash")
	if err != nil {
		return imported{}, err
	}
	if len(sep) > firebaseMaxSep || len(want) != len(signer) {
		return imported{}, unsupported("firebase-scrypt salt separator above %d bytes, or hash and signer key of different lengths", firebaseMaxSep)
	}
	if err := checkSaltAndKey(salt, want); err != nil {
		return imported{}, err
	}
	salted := append(append([]byte{}, salt...), sep...)
	n := 1 << ln
	return imported{want: want, derive: func(plain []byte) []byte {
		key, err := scrypt.Key(plain, salted, n, int(r), 1, firebaseKeyLen) //nolint:gosec // G115: r bounded by checkScrypt
		if err != nil {
			return nil
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil
		}
		out := make([]byte, len(signer))
		// Firebase's scheme fixes a zero IV; the key is fresh per password and salt, and this only
		// verifies (nothing is encrypted for storage).
		cipher.NewCTR(block, make([]byte, aes.BlockSize)).XORKeyStream(out, signer) //nolint:gosec // G407: see above

		return out
	}}, nil
}

func checkSaltAndKey(salt, want []byte) error {
	if len(salt) < importedMinSalt || len(salt) > importedMaxSalt {
		return unsupported("salt of %d bytes outside [%d, %d]", len(salt), importedMinSalt, importedMaxSalt)
	}
	if len(want) < importedMinKey || len(want) > importedMaxKey {
		return unsupported("hash of %d bytes outside [%d, %d]", len(want), importedMinKey, importedMaxKey)
	}
	return nil
}

func decimal(s, name string) (uint64, error) {
	n, rest, ok := cutDecimal(s)
	if !ok || rest != "" {
		return 0, unsupported("%s is not a decimal without sign or leading zero", name)
	}
	return n, nil
}

// decodeImportedB64 decodes standard base64 with or without padding, and passlib's variant
// ('.' for '+'). Nothing else is skipped.
func decodeImportedB64(s, name string) ([]byte, error) {
	s = strings.TrimSuffix(strings.TrimSuffix(s, "="), "=")
	b, err := decodePHCBase64(strings.ReplaceAll(s, ".", "+"))
	if err != nil || len(b) == 0 {
		return nil, unsupported("%s is not base64", name)
	}
	return b, nil
}

// checkArgon2 is CheckHash for $argon2id$ and $argon2i$: what Verify decodes, under the import
// bounds.
func checkArgon2(hash, prefix string) error {
	h, ok := parseArgon2(hash, prefix)
	if !ok {
		return unsupported("malformed %s$ string, or a version other than 19", prefix)
	}
	if h.memory > argon2ImportMem || h.memory*h.time > argon2ImportWork {
		return unsupported("argon2 memory %d KiB above %d, or memory × passes above %d", h.memory, argon2ImportMem, argon2ImportWork)
	}
	return nil
}

// checkBcrypt is CheckHash for bcrypt: a 60-character string in bcrypt's alphabet, cost in
// [4, 16].
func checkBcrypt(hash string) error {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil || len(hash) != 60 || strings.Trim(hash[7:], bcryptAlphabet) != "" {
		return unsupported("malformed bcrypt string")
	}
	if cost > bcryptImportCost {
		return unsupported("bcrypt cost %d above %d", cost, bcryptImportCost)
	}
	return nil
}

const bcryptAlphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
