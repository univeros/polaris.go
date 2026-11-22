package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
)

// JwkSetTest

func TestJWKSetRendersAnRSAPublicKeyKeyedByKid(t *testing.T) {
	set, err := NewJWKSet(RS256, PublicKey{KeyID: "kid-42", PEM: loadKeys(t).RSA.Public})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("keys = %d", len(set.Keys))
	}
	jwk := set.Keys[0]
	if jwk.Kty != "RSA" || jwk.Use != "sig" || jwk.Alg != "RS256" || jwk.Kid != "kid-42" || jwk.N == "" || jwk.E != "AQAB" {
		t.Fatalf("jwk = %+v", jwk)
	}
	// RFC 7515 base64url: no '+', '/', or '=' padding.
	if regexp.MustCompile(`[+/=]`).MatchString(jwk.N + jwk.E) {
		t.Fatal("not base64url")
	}
	out, _ := json.Marshal(set)
	if !regexp.MustCompile(`^\{"keys":\[\{"kty":"RSA","use":"sig","alg":"RS256","kid":"kid-42","n":"[A-Za-z0-9_-]+","e":"AQAB"\}\]\}$`).Match(out) {
		t.Fatalf("wire order: %s", out)
	}
}

func TestJWKSetRejectsAnUnparseablePublicKey(t *testing.T) {
	_, err := NewJWKSet(RS256, PublicKey{KeyID: "kid-1", PEM: "-----BEGIN PUBLIC KEY-----not a key-----END PUBLIC KEY-----"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestJWKSetRejectsAValidNonRSAKey(t *testing.T) {
	_, err := NewJWKSet("ES256", PublicKey{KeyID: "kid-1", PEM: loadKeys(t).ECPublic})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("err = %v", err)
	}
}

func TestJWKSetPublishesBothKeysDuringRotation(t *testing.T) {
	k := loadKeys(t)
	set, err := NewJWKSet(RS256,
		PublicKey{KeyID: "new", PEM: k.RSA.Public},
		PublicKey{KeyID: "old", PEM: k.RSAAlternate.Public},
	)
	if err != nil || len(set.Keys) != 2 || set.Keys[0].Kid != "new" || set.Keys[1].Kid != "old" {
		t.Fatalf("set = %+v, %v", set, err)
	}
	// A kid repeated keeps its first slot and takes the last key.
	dup, _ := NewJWKSet(RS256, PublicKey{KeyID: "a", PEM: k.RSA.Public}, PublicKey{KeyID: "b", PEM: k.RSA.Public}, PublicKey{KeyID: "a", PEM: k.RSAAlternate.Public})
	if len(dup.Keys) != 2 || dup.Keys[0].Kid != "a" || dup.Keys[0].N != set.Keys[1].N {
		t.Fatalf("dup = %+v", dup)
	}
}

func TestJWKSetRendersEd25519AsOKP(t *testing.T) {
	pub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	set, err := NewJWKSet(EdDSA, PublicKey{KeyID: "ed", PEM: string(pub)})
	if err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(set)
	want := `{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","kid":"ed","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}]}`
	if string(doc) != want {
		t.Errorf("got %s\nwant %s", doc, want)
	}
	for _, bad := range []string{"short", strings.Repeat("\x00", ed25519.PublicKeySize)} {
		if _, err := NewJWKSet(EdDSA, PublicKey{KeyID: "bad", PEM: bad}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
