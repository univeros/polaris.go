package verify_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/verify"
)

// FuzzVerify is Verify on arbitrary header and claims bytes signed by the issuer's own key, and
// on a raw string. Nothing may panic, and nothing but an RS256 access token of the issuer without
// an aud is accepted.
func FuzzVerify(f *testing.F) {
	i := newIssuer(f)
	v := i.verifier(f, verify.Config{})
	if _, err := v.Verify(context.Background(), i.session(f, i.rsa)); err != nil { // warm the key cache
		f.Fatal(err)
	}
	key := contracttest.TestRSAKey()
	f.Add([]byte(`{"typ":"JWT","alg":"RS256","kid":"rsa-1"}`), []byte(`{"iss":"https://auth.polaris.test","exp":1800000600}`), "")
	f.Add([]byte(`{"typ":"at+jwt","alg":"none","kid":"rsa-1"}`), []byte(`{"iss":"https://auth.polaris.test","exp":1e999,"aud":[1]}`), "a.b.c")
	f.Add([]byte(`{"typ":"JWT","alg":"EdDSA","kid":"ed-1"}`), []byte(`{"iss":"https://auth.polaris.test","exp":"x","cnf":{}}`), "..")
	f.Fuzz(func(t *testing.T, header, claims []byte, raw string) {
		input := b64(header) + "." + b64(claims)
		sum := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		if c, err := v.Verify(context.Background(), input+"."+b64(sig)); err == nil {
			if !strings.Contains(string(header), `"RS256"`) || !strings.Contains(strings.ToLower(string(header)), "jwt") ||
				c.All["iss"] != issuerURL || c.All["aud"] != nil || c.All["cnf"] != nil {
				t.Fatalf("accepted %s %s", header, claims)
			}
		}
		_, _ = v.Verify(context.Background(), raw)
	})
}
