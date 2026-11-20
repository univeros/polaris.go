package token

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/clock"
)

const (
	testIssuer   = "https://auth.polaris.test"
	testAudience = "https://api.polaris.test"
	testKID      = "test-kid-1"
)

// testKeys are the fixed test-only keys shared with scripts/vectors.php.
type testKeys struct {
	RSA          struct{ Private, Public string } `json:"rsa"`
	RSAAlternate struct{ Private, Public string } `json:"rsa_alternate"`
	ECPublic     string                           `json:"ec_public"`
	EdDSA        struct {
		Secret string `json:"secret_base64"`
		Public string `json:"public_base64"`
	} `json:"eddsa"`
}

func loadKeys(t testing.TB) testKeys {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var k testKeys
	if err := json.Unmarshal(data, &k); err != nil {
		t.Fatal(err)
	}
	return k
}

func (k testKeys) edSecret() string {
	b, _ := base64.StdEncoding.DecodeString(k.EdDSA.Secret)
	return string(b)
}
func (k testKeys) edPublic() string {
	b, _ := base64.StdEncoding.DecodeString(k.EdDSA.Public)
	return string(b)
}

// at is FrozenClock::at for the UTC wall time "2006-01-02 15:04:05".
func at(t testing.TB, wall string) *clock.Frozen {
	t.Helper()
	ts, err := time.Parse(time.DateTime, wall)
	if err != nil {
		t.Fatal(err)
	}
	return clock.NewFrozen(ts)
}

// testConfig is TokenTestCase::config: the primary RSA pair, issuer, audience, 900 s.
func testConfig(t testing.TB, clk clock.Clock, mutate ...func(*Config)) Config {
	t.Helper()
	k := loadKeys(t)
	cfg := Config{
		Algorithm: RS256, PublicKey: k.RSA.Public, PrivateKey: k.RSA.Private, KeyID: testKID,
		Issuer: testIssuer, Audience: testAudience, TTL: 900 * time.Second, Clock: clk,
	}
	for _, m := range mutate {
		m(&cfg)
	}
	return cfg
}

func newCodec(t testing.TB, cfg Config) *Codec {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustClaims(t testing.TB, a AccessClaims) Claims {
	t.Helper()
	c, err := a.Claims()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustIssue(t testing.TB, c *Codec, claims Claims) string {
	t.Helper()
	jwt, err := c.Issue(claims)
	if err != nil {
		t.Fatal(err)
	}
	return jwt
}

// craft signs arbitrary header and payload JSON with the primary RSA key, for tokens the
// Codec would never mint.
func craft(t testing.TB, header, payload string) string {
	t.Helper()
	sign, err := newSigner(RS256, loadKeys(t).RSA.Private)
	if err != nil {
		t.Fatal(err)
	}
	input := b64(header) + "." + b64(payload)
	sig, err := sign([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// segment decodes one part of a compact JWT.
func segment(t testing.TB, jwt string, i int) string {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[i])
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
