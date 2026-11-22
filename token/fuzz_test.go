package token

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
)

// fuzzSeeds are the recorded known-answer vector tokens plus hand-made edge cases.
func fuzzSeeds(f *testing.F) []string {
	f.Helper()
	data, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", "jwt.json"))
	if err != nil {
		f.Fatal(err)
	}
	var v jwtVectors
	if err := json.Unmarshal(data, &v); err != nil {
		f.Fatal(err)
	}
	seeds := []string{"", ".", "..", "a.b.c", "eyJhbGciOiJub25lIn0.e30.", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.e30.AA"}
	for _, c := range v.Cases {
		seeds = append(seeds, c.Token)
	}
	return seeds
}

func fuzzCodec(f *testing.F) *Codec {
	f.Helper()
	clk := clock.NewFrozen(time.Unix(1780833600, 0))
	k := loadKeys(f)
	c, err := New(Config{Algorithm: RS256, PublicKey: k.RSA.Public, PrivateKey: k.RSA.Private, KeyID: testKID,
		Issuer: testIssuer, Audience: testAudience, TTL: 900 * time.Second, Clock: clk,
		PreviousPublicKey: k.RSAAlternate.Public, PreviousKeyID: "old"})
	if err != nil {
		f.Fatal(err)
	}
	return c
}

// FuzzParseRaw feeds hostile compact strings to every verifier: none may panic, and nothing
// unsigned may pass.
func FuzzParseRaw(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	c := fuzzCodec(f)
	f.Fuzz(func(t *testing.T, raw string) {
		tok, err := c.Parse(raw)
		if err == nil {
			checkAccessToken(t, c, tok)
		}
		_, _ = c.Verify(raw)
		_, _ = c.VerifyJWT(raw, time.Minute)
		_, _ = c.VerifyJWT(raw, 0)
	})
}

// FuzzSignedClaims signs arbitrary header and payload bytes with the codec's key, so the fuzzer
// reaches the claim rules behind the signature: none may panic, and Parse must only accept what
// an access token is.
func FuzzSignedClaims(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		parts := strings.Split(s, ".")
		if len(parts) != 3 {
			continue
		}
		h, _ := base64.RawURLEncoding.DecodeString(parts[0])
		p, _ := base64.RawURLEncoding.DecodeString(parts[1])
		f.Add(h, p)
	}
	f.Add([]byte(`{"typ":"JWT","alg":"EdDSA","kid":"test-kid-1"}`), []byte(`{"iss":"https://auth.polaris.test","aud":"https://api.polaris.test","iat":1780833600,"exp":1780834600,"sub":"u"}`))
	f.Add([]byte(`{"typ":"at+jwt","alg":"RS256","kid":"test-kid-1"}`), []byte(`{"iss":"https://auth.polaris.test","aud":"https://api.polaris.test","iat":1780833600,"exp":1780834600}`))
	f.Add([]byte(`{"alg":"RS256"}`), []byte(`{"iss":"https://auth.polaris.test","aud":["https://api.polaris.test"],"iat":1e300,"exp":-1e300,"nbf":"x","purpose":"login_mfa"}`))
	// EdDSA signs fast enough for the fuzzer to explore the claims; the rules do not depend on alg.
	k := loadKeys(f)
	c, err := New(Config{Algorithm: EdDSA, PublicKey: k.edPublic(), PrivateKey: k.edSecret(), KeyID: testKID,
		Issuer: testIssuer, Audience: testAudience, TTL: 900 * time.Second, Clock: clock.NewFrozen(time.Unix(1780833600, 0))})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, header, payload []byte) {
		input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
		sig, err := c.sign([]byte(input))
		if err != nil {
			t.Fatal(err)
		}
		raw := input + "." + base64.RawURLEncoding.EncodeToString(sig)
		if tok, err := c.Parse(raw); err == nil {
			checkAccessToken(t, c, tok)
		}
		if tok, err := c.Verify(raw); err == nil {
			_ = tok.Subject()
			_ = tok.IssuedAt()
			_ = tok.Claims()
		}
		if tok, err := c.VerifyJWT(raw, time.Minute); err == nil {
			_ = tok.Header("typ")
		}
	})
}

// checkAccessToken is what Parse promises about a token it accepted.
func checkAccessToken(t *testing.T, c *Codec, tok *Token) {
	t.Helper()
	if tok.Claim("purpose") != nil {
		t.Fatalf("Parse accepted a single-purpose token: %v", tok.Claims())
	}
	if typ, ok := tok.Header("typ").(string); ok && typ != "" && asciiUpper(typ) != "JWT" {
		t.Fatalf("Parse accepted typ %q", typ)
	}
	if tok.Claim("iss") != c.issuer || !permittedFor(tok.claims, c.audience) {
		t.Fatalf("Parse accepted iss/aud %v / %v", tok.Claim("iss"), tok.Claim("aud"))
	}
	if tok.IssuedAt().IsZero() {
		t.Fatalf("Parse accepted a token without iat")
	}
	_ = tok.Subject()
	p := NewPrincipal(tok.Claims())
	_ = p.Organization()
}
