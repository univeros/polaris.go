package agent

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

// Port of AgentKeyTest.

func TestAgentKey(t *testing.T) {
	t.Run("testAnEs256KeyHasItsThumbprintAsKidAndNoPrivatePartInItsPublicJwk", func(t *testing.T) {
		key, err := GenerateKey(ES256)
		if err != nil {
			t.Fatal(err)
		}
		jwk := key.PublicJWK()
		if key.Alg() != ES256 || jwk.Kty != "EC" || jwk.Crv != "P-256" || jwk.Alg != "ES256" || jwk.Kid != key.KID() || jwk.Use != "sig" || jwk.N != "" {
			t.Fatalf("public JWK %+v", jwk)
		}
		data, _ := json.Marshal(jwk)
		if strings.Contains(string(data), `"d"`) {
			t.Fatalf("private part in %s", data)
		}
		if tp, _ := Thumbprint(JWK{Kty: "EC", Crv: "P-256", X: jwk.X, Y: jwk.Y}); tp != key.KID() {
			t.Fatalf("kid %s, thumbprint %s", key.KID(), tp)
		}
		jws, err := signJWS(key, "agent+jwt", map[string]string{"sub": "a"})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := rawHeader(t, jws), fmt.Sprintf(`{"typ":"agent+jwt","alg":"ES256","kid":"%s"}`, key.KID()); got != want {
			t.Fatalf("header %s, want %s", got, want)
		}
		if !verifiesWith(jws, jwk) {
			t.Fatal("does not verify with its public JWK")
		}
	})

	t.Run("testAnEdDsaKeyIsEd25519WithAGivenKid", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		key, err := NewKey(priv, "my-agent-key")
		if err != nil {
			t.Fatal(err)
		}
		jwk := key.PublicJWK()
		if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.Alg != "EdDSA" || jwk.Kid != "my-agent-key" || jwk.Y != "" {
			t.Fatalf("public JWK %+v", jwk)
		}
		jws, _ := signJWS(key, "JWT", map[string]string{"sub": "a"})
		if !verifiesWith(jws, jwk) {
			t.Fatal("does not verify with its public JWK")
		}
	})

	t.Run("testAKeyRoundTripsThroughItsStoredForm", func(t *testing.T) {
		for _, alg := range []Algorithm{ES256, EdDSA} {
			key, err := GenerateKey(alg)
			if err != nil {
				t.Fatal(err)
			}
			stored, err := key.Export()
			if err != nil {
				t.Fatal(err)
			}
			again, err := ImportKey(stored)
			if err != nil {
				t.Fatalf("%s: %v", alg, err)
			}
			if again.PublicJWK() != key.PublicJWK() || again.KID() != key.KID() {
				t.Fatalf("%s: %+v != %+v", alg, again.PublicJWK(), key.PublicJWK())
			}
		}
		for _, bad := range []string{`{"alg":"ES256"}`, `nope`, `{"alg":"RS256","secret":"x"}`, `{"alg":"EdDSA","secret":"AAAA"}`, `{"alg":"ES256","secret":"not pem"}`} {
			if _, err := ImportKey([]byte(bad)); err == nil {
				t.Fatalf("%s imported", bad)
			}
		}
	})

	t.Run("testTheThumbprintFollowsRfc7638", func(t *testing.T) {
		n := "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		if tp, err := Thumbprint(JWK{Kty: "RSA", E: "AQAB", N: n}); err != nil || tp != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
			t.Fatalf("thumbprint %q, %v", tp, err)
		}
		for _, bad := range []JWK{{Kty: "oct"}, {Kty: "EC", Crv: "P-256", X: "x"}, {Kty: "OKP"}, {Kty: "RSA", N: "n"}} {
			if _, err := Thumbprint(bad); err == nil {
				t.Fatalf("%+v has a thumbprint", bad)
			}
		}
	})
}

func TestKeyImportsPHPStoredFormsAndRefusesOtherKeys(t *testing.T) {
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sec1, _ := x509.MarshalECPrivateKey(ec)
	stored, _ := json.Marshal(map[string]string{"alg": "ES256", "secret": string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))})
	key, err := ImportKey(stored)
	if err != nil {
		t.Fatalf("SEC 1 PEM (openssl's EC form): %v", err)
	}
	if want, _ := NewKey(ec, ""); key.PublicJWK() != want.PublicJWK() {
		t.Fatal("SEC 1 PEM loads another key")
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if _, err := NewKey(p384, ""); err == nil {
		t.Fatal("a P-384 key is not ES256")
	}
	der, _ := x509.MarshalPKCS8PrivateKey(p384)
	stored, _ = json.Marshal(map[string]string{"alg": "ES256", "secret": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	if _, err := ImportKey(stored); err == nil {
		t.Fatal("a P-384 PEM imported")
	}
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	der, _ = x509.MarshalPKCS8PrivateKey(ed)
	stored, _ = json.Marshal(map[string]string{"alg": "ES256", "secret": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	if _, err := ImportKey(stored); err == nil {
		t.Fatal("an Ed25519 PEM imported as ES256")
	}
	if _, err := NewKey("secret", ""); err == nil {
		t.Fatal("a string is no key")
	}
	if _, err := NewKey(ed25519.PrivateKey(ed[:10]), ""); err == nil {
		t.Fatal("a short Ed25519 key")
	}
	if _, err := GenerateKey("RS256"); err == nil {
		t.Fatal("RS256 generated")
	}
	mismatched := append(append([]byte{}, ed[:32]...), make([]byte, 32)...)
	stored, _ = json.Marshal(map[string]any{"alg": "EdDSA", "secret": mismatched})
	if _, err := ImportKey(stored); err == nil {
		t.Fatal("a sodium key whose public half is not its seed's")
	}
}

func TestAKeyNeverPrintsItsPrivatePart(t *testing.T) {
	key, _ := GenerateKey(EdDSA)
	var logged strings.Builder
	slog.New(slog.NewJSONHandler(&logged, nil)).Info("k", "key", key)
	for _, s := range []string{fmt.Sprint(key), fmt.Sprintf("%v", key), logged.String()} {
		if !strings.Contains(s, key.KID()) || strings.Contains(s, "secret") || len(s) > 200 {
			t.Fatalf("printed %q", s)
		}
	}
}
