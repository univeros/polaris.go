package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// recordedKeys are the test RSA and EdDSA pairs of testdata/vectors/keys.json, as the environment
// holds them.
func recordedKeys(t *testing.T) (rsa, eddsa [2]string) {
	t.Helper()
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
	return [2]string{k.RSA.Private, k.RSA.Public}, [2]string{k.EdDSA.Secret, k.EdDSA.Public}
}

func recordedSecrets(t *testing.T, pair [2]string, extra ...string) Secrets {
	t.Helper()
	env := with(map[string]string{"APP_KEY": testAppKey, "AUTH_JWT_PRIVATE_KEY": pair[0], "AUTH_JWT_PUBLIC_KEY": pair[1]}, extra...)
	s, err := SecretsFromLookup(lookupMap(env))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Without AUTH_JWT_KID the kid of every issued JWT and of the JWKS is the RFC 7638 thumbprint of
// the public key (decision 73): the key, not its encoding, so re-encoding the PEM keeps it.
// Tokens and cached key sets name that kid, so it is a stored format (docs/stored-formats.md).
func TestTheDefaultKeyIDIsTheThumbprint(t *testing.T) {
	rsa, eddsa := recordedKeys(t)
	for _, c := range []struct {
		pair [2]string
		kid  string
	}{
		{rsa, "5-_-Xkr1BBOH_7AGcnCxo7PnLeIpMoOqbYkz9he2zbE"},
		{[2]string{rsa[0], strings.ReplaceAll(rsa[1], "\n", "\r\n")}, "5-_-Xkr1BBOH_7AGcnCxo7PnLeIpMoOqbYkz9he2zbE"},
		{eddsa, "xB2K64u26yW_2JuHaJRSnB1h1Kr8E5icw4UVWmUpnMc"},
	} {
		s := recordedSecrets(t, c.pair, "AUTH_JWT_PREVIOUS_PUBLIC_KEY", c.pair[1])
		if s.KeyID() != c.kid || s.PreviousKeyID() != c.kid {
			t.Errorf("default kid %s, previous %s; recorded %s", s.KeyID(), s.PreviousKeyID(), c.kid)
		}
	}
}

// The kid releases before decision 73 derived by default, the SHA-256 hex of the public key as
// configured (the PEM text with its edges trimmed, or the raw EdDSA key), stays accepted and
// published as an alias of each key, so tokens and key sets from those releases keep working.
func TestTheLegacyKeyIDIsTheRecordedOne(t *testing.T) {
	rsa, eddsa := recordedKeys(t)
	for _, c := range []struct {
		pair [2]string
		kid  string
	}{
		{rsa, "3c2fe4ccb941a83a85c9dc3093ec1a6ba488c74c77c30f3707cc6e30d1240745"},
		{eddsa, "d86a564423cd8c9910ecd33d4e26628385ad036cd6a978a2c36bf5460cfce70d"},
	} {
		s := recordedSecrets(t, c.pair, "AUTH_JWT_PREVIOUS_PUBLIC_KEY", c.pair[1])
		if s.LegacyKeyID() != c.kid || s.PreviousLegacyKeyID() != c.kid {
			t.Errorf("legacy kid %s, previous %s; recorded %s", s.LegacyKeyID(), s.PreviousLegacyKeyID(), c.kid)
		}
	}
}

// An explicit kid is used as it is and has no legacy alias; no previous key, no previous kids.
func TestAnExplicitKeyIDHasNoLegacyAlias(t *testing.T) {
	rsa, _ := recordedKeys(t)
	s := recordedSecrets(t, rsa, "AUTH_JWT_KID", "key-2026", "AUTH_JWT_PREVIOUS_PUBLIC_KEY", rsa[1], "AUTH_JWT_PREVIOUS_KID", "key-2025")
	if s.KeyID() != "key-2026" || s.PreviousKeyID() != "key-2025" || s.LegacyKeyID() != "" || s.PreviousLegacyKeyID() != "" {
		t.Errorf("kids %q %q, legacy %q %q", s.KeyID(), s.PreviousKeyID(), s.LegacyKeyID(), s.PreviousLegacyKeyID())
	}
	s = recordedSecrets(t, rsa, "AUTH_JWT_PREVIOUS_KID", "key-2025")
	if s.PreviousKeyID() != "" || s.PreviousLegacyKeyID() != "" {
		t.Errorf("without a previous key: %q %q", s.PreviousKeyID(), s.PreviousLegacyKeyID())
	}
}
