package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
)

// FuzzDPoPProof signs arbitrary header and claims bytes with one P-256 key (the header's jwk may
// or may not be that key) and verifies them as a DPoP proof; raw goes through unsigned. Nothing
// may panic; an accepted proof is accepted once.
func FuzzDPoPProof(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pad := func(n *big.Int) string { b := make([]byte, 32); n.FillBytes(b); return b64(b) }
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": pad(key.X), "y": pad(key.Y)}
	now := time.Unix(1_800_000_000, 0)
	url := testBase + "/oauth2/token"
	hj, _ := json.Marshal(map[string]any{"typ": dpopTyp, "alg": "ES256", "jwk": jwk})
	cj, _ := json.Marshal(map[string]any{"jti": "j1", "htm": "POST", "htu": url, "iat": now.Unix(), "ath": sha256b64("at")})
	f.Add(hj, cj, "")
	f.Add([]byte(`{"typ":"dpop+jwt","alg":"RS256","jwk":{"kty":"RSA","n":"AQ","e":"AQ"}}`), []byte(`{"iat":1e999}`), "a.b.c")
	f.Add([]byte(`{"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":""}}`), []byte(`{"iat":-9223372036854775808}`), "")
	f.Fuzz(func(t *testing.T, header, claims []byte, raw string) {
		clk := clock.NewFrozen(now)
		d := &dpop{once: &onceGuard{cache: cache.NewMemory(clk)}, clock: clk}
		input := b64(header) + "." + b64(claims)
		sum := sha256.Sum256([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		proof := input + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
		for _, at := range []string{"", "at"} {
			if jkt, err := d.verify(context.Background(), proof, "POST", url, at); err == nil && jkt != "" {
				if _, err := d.verify(context.Background(), proof, "POST", url, at); err == nil {
					t.Fatal("a DPoP proof was accepted twice")
				}
			}
		}
		_, _ = d.verify(context.Background(), raw, "POST", url, "")
		_ = JWTHeader(raw)
	})
}
