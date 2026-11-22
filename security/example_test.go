package security_test

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/univeros/polaris.go/security"
)

func ExampleArgon2id() {
	// The zero value uses the defaults (64 MiB, t=4, p=1); a low cost keeps the example fast.
	hasher := security.Argon2id{Memory: 8192, Time: 1, Threads: 1}
	hash, err := hasher.Hash("correct horse battery staple")
	if err != nil {
		panic(err)
	}
	fmt.Println(hasher.Verify("correct horse battery staple", hash), hasher.NeedsRehash(hash))
	// Output: true false
}

func ExamplePepper() {
	pepper, err := security.NewPepper("an APP_KEY of at least 32 bytes, random in production")
	if err != nil {
		panic(err)
	}
	stored := pepper.Hash("refresh", "rt_secret") // store this, never the secret
	fmt.Println(len(stored), pepper.Matches("refresh", "rt_secret", stored))
	// Output: 64 true
}

func ExampleXChaCha20Poly1305() {
	enc, err := security.NewXChaCha20Poly1305("an APP_KEY of at least 32 bytes, random in production")
	if err != nil {
		panic(err)
	}
	payload, _ := enc.Encrypt("JBSWY3DPEHPK3PXP") // a TOTP seed at rest
	seed, _ := enc.Decrypt(payload)
	fmt.Println(seed)
	// Output: JBSWY3DPEHPK3PXP
}

// legacyHasher keeps users of an in-house scheme ("sha256$<salt>$<hex>", deliberately weak):
// Verify and CheckHash handle its prefix and delegate everything else to Argon2id, whose Hash and
// NeedsRehash it inherits, so each legacy hash becomes Argon2id on its user's first sign-in. Set
// it as polaris.Config.Hasher; Users().Import then accepts the legacy strings.
type legacyHasher struct{ security.Argon2id }

func (h legacyHasher) Verify(plain, hash string) bool {
	if salt, want, ok := strings.Cut(strings.TrimPrefix(hash, "sha256$"), "$"); ok && strings.HasPrefix(hash, "sha256$") {
		sum := sha256.Sum256([]byte(salt + plain))
		return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(want)) == 1
	}
	return h.Argon2id.Verify(plain, hash)
}

func (h legacyHasher) CheckHash(hash string) error {
	if strings.HasPrefix(hash, "sha256$") && strings.Count(hash, "$") == 2 {
		return nil
	}
	return h.Argon2id.CheckHash(hash)
}

func ExampleHashChecker() {
	h := legacyHasher{security.Argon2id{Memory: 8192, Time: 1, Threads: 1}}
	sum := sha256.Sum256([]byte("pepper" + "hunter2"))
	stored := "sha256$pepper$" + hex.EncodeToString(sum[:])

	fmt.Println(h.CheckHash(stored) == nil, h.Verify("hunter2", stored), h.NeedsRehash(stored))
	fmt.Println(errors.Is(h.CheckHash("md5$x$y"), security.ErrUnsupportedHash))
	// Output:
	// true true true
	// true
}
