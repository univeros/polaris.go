package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Without AUTH_JWT_KID the kid of every issued JWT and of the JWKS is derived from the public key
// as configured: SHA-256 hex of the PEM text (edges trimmed) or of the raw EdDSA key. Tokens and
// cached key sets name that kid, so the derivation is a stored format (docs/stored-formats.md).
func TestTheDefaultKeyIDIsTheRecordedOne(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var k struct {
		RSA   struct{ Private, Public string } `json:"rsa"`
		EdDSA struct {
			Secret string `json:"secret_base64"`
			Public string `json:"public_base64"`
		} `json:"eddsa"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ private, public, kid string }{
		{k.RSA.Private, k.RSA.Public, "3c2fe4ccb941a83a85c9dc3093ec1a6ba488c74c77c30f3707cc6e30d1240745"},
		{k.EdDSA.Secret, k.EdDSA.Public, "d86a564423cd8c9910ecd33d4e26628385ad036cd6a978a2c36bf5460cfce70d"},
	} {
		env := map[string]string{"APP_KEY": testAppKey, "AUTH_JWT_PRIVATE_KEY": c.private, "AUTH_JWT_PUBLIC_KEY": c.public}
		s, err := SecretsFromLookup(func(key string) (string, bool) { v, ok := env[key]; return v, ok })
		if err != nil {
			t.Fatal(err)
		}
		if s.KeyID() != c.kid {
			t.Errorf("default kid %s, recorded %s", s.KeyID(), c.kid)
		}
	}
}
