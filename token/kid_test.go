package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

// The default kid is the RFC 7638 thumbprint (decision 73): pinned against the RFCs' own examples.
func TestThumbprintIsRFC7638(t *testing.T) {
	// RFC 7638 §3.1: the RSA key of RFC 7517 Appendix A.1.
	n, _ := base64.RawURLEncoding.DecodeString("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw")
	der, err := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537})
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	// RFC 8037 Appendix A.2 and A.3: the Ed25519 public key and its thumbprint.
	x, _ := base64.RawURLEncoding.DecodeString("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo")

	for _, c := range []struct {
		alg       Algorithm
		key, want string
	}{
		{RS256, rsaPEM, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"},
		{RS256, strings.ReplaceAll(rsaPEM, "\n", "\r\n"), "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}, // re-encoding keeps it
		{EdDSA, string(x), "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"},
	} {
		got, err := Thumbprint(c.alg, c.key)
		if err != nil || got != c.want {
			t.Errorf("%s: thumbprint %q, %v; want %q", c.alg, got, err, c.want)
		}
	}
	for name, c := range map[string]struct {
		alg Algorithm
		key string
	}{
		"not a key":  {RS256, "nope"},
		"short okp":  {EdDSA, "short"},
		"other alg":  {"ES256", rsaPEM},
		"rsa as okp": {EdDSA, rsaPEM},
	} {
		if _, err := Thumbprint(c.alg, c.key); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// A token minted by an earlier release names the key by its legacy kid; it keeps verifying with
// the key that kid belongs to, and only with it (decision 73).
func TestVerifyJWTAcceptsTheLegacyKeyIDOfEachConfiguredKey(t *testing.T) {
	clk := at(t, "2026-06-07 12:00:00")
	k := loadKeys(t)
	exp := clk.Now().Add(time.Minute)
	verifier := newCodec(t, testConfig(t, clk, withPrevious(t), func(c *Config) {
		c.LegacyKeyID, c.PreviousLegacyKeyID = "legacy-current", "legacy-previous"
	}))
	signer := func(private, kid string) *Codec {
		return newCodec(t, testConfig(t, clk, func(c *Config) { c.PrivateKey, c.KeyID = private, kid }))
	}
	for name, tc := range map[string]struct {
		jwt string
		ok  bool
	}{
		"legacy current kid, current key":   {mustMint(t, signer(k.RSA.Private, "legacy-current"), Claims{}, exp), true},
		"legacy previous kid, previous key": {mustMint(t, signer(k.RSAAlternate.Private, "legacy-previous"), Claims{}, exp), true},
		"legacy current kid, previous key":  {mustMint(t, signer(k.RSAAlternate.Private, "legacy-current"), Claims{}, exp), false},
		"legacy previous kid, current key":  {mustMint(t, signer(k.RSA.Private, "legacy-previous"), Claims{}, exp), false},
		"current kid, current key":          {mustMint(t, signer(k.RSA.Private, testKID), Claims{}, exp), true},
		"previous kid, previous key":        {mustMint(t, signer(k.RSAAlternate.Private, "kid-old"), Claims{}, exp), true},
	} {
		if _, err := verifier.VerifyJWT(tc.jwt, 0); (err == nil) != tc.ok {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// Minting never uses the legacy kid.
	if got := segment(t, mustMint(t, verifier, Claims{}, exp), 0); got != `{"typ":"JWT","alg":"RS256","kid":"test-kid-1"}` {
		t.Errorf("header = %s", got)
	}
	// Without a legacy kid configured, the legacy value is an unknown key.
	plain := newCodec(t, testConfig(t, clk))
	if _, err := plain.VerifyJWT(mustMint(t, signer(k.RSA.Private, "legacy-current"), Claims{}, exp), 0); err == nil {
		t.Error("a legacy kid was accepted without being configured")
	}
	// A legacy kid for a previous key that is not configured is a configuration error.
	if _, err := New(testConfig(t, clk, func(c *Config) { c.PreviousLegacyKeyID = "legacy-previous" })); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("previous legacy kid without a previous key: err = %v", err)
	}
}
