package security_test

import (
	"fmt"

	"github.com/univeros/polaris-go/security"
)

func ExampleArgon2id() {
	// The zero value uses upstream's defaults (64 MiB, t=4, p=1); a low cost keeps the example fast.
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
