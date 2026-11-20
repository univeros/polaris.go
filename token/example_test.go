package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/token"
)

func Example() {
	// AUTH_JWT_PRIVATE_KEY / AUTH_JWT_PUBLIC_KEY in production.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	privateDER, _ := x509.MarshalPKCS8PrivateKey(key)

	codec, err := token.New(token.Config{
		Algorithm:  token.RS256,
		PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		KeyID:      "kid-2026-01",
		Issuer:     "https://auth.example.com",
		TTL:        15 * time.Minute,
		Clock:      clock.NewFrozen(time.Date(2026, 6, 7, 12, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		panic(err)
	}
	claims, err := token.AccessClaims{Subject: "user-1", ID: "jti-1", AMR: []string{"pwd"}}.Claims()
	if err != nil {
		panic(err)
	}
	jwt, err := codec.Issue(claims)
	if err != nil {
		panic(err)
	}
	tok, err := codec.Parse(jwt)
	if err != nil {
		panic(err)
	}
	fmt.Println(tok.Subject(), tok.Claim("amr"), tok.ExpiresAt().Format(time.RFC3339))
	// Output: user-1 [pwd] 2026-06-07T12:15:00Z
}

func ExampleNewJWKSet() {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	set, err := token.NewJWKSet(token.RS256, token.PublicKey{
		KeyID: "kid-2026-01",
		PEM:   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(set.Keys[0].Kty, set.Keys[0].Kid, set.Keys[0].E)
	// Output: RSA kid-2026-01 AQAB
}
