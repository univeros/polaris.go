package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
)

// FuzzDPoPProof is the resource server's proof check on signed arbitrary header and claims
// bytes, and on a raw string. Nothing may panic; an accepted proof is accepted once.
func FuzzDPoPProof(f *testing.F) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d := dpopKey{key}
	now := time.Unix(1_800_000_000, 0)
	const url, at = "https://tools.polaris.test/mcp", "access-token"
	hj, _ := json.Marshal(map[string]any{"typ": dpopTyp, "alg": "ES256", "jwk": d.jwk()})
	cj, _ := json.Marshal(map[string]any{"jti": "j1", "htm": "POST", "htu": url, "iat": now.Unix(), "ath": sha256b64(at)})
	f.Add(hj, cj, "")
	f.Add([]byte(`{"typ":"dpop+jwt","alg":"RS256","jwk":{"kty":"RSA","n":"AQ","e":"AQ"}}`), []byte(`{"iat":1e999}`), "a.b.c")
	f.Add([]byte(`{"typ":"dpop+jwt","alg":"EdDSA","jwk":{"kty":"OKP","crv":"Ed25519","x":""}}`), []byte(`{"iat":-9223372036854775808}`), "")
	f.Fuzz(func(t *testing.T, header, claims []byte, raw string) {
		clk := clock.NewFrozen(now)
		p := &dpopProofs{cache: cache.NewMemory(clk), clock: clk}
		input := b64(header) + "." + b64(claims)
		sum := sha256.Sum256([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		proof := input + "." + b64(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
		if _, err := p.thumbprint(context.Background(), proof, "POST", url, at); err == nil {
			if _, err := p.thumbprint(context.Background(), proof, "POST", url, at); err == nil {
				t.Fatal("a DPoP proof was accepted twice")
			}
		}
		_, _ = p.thumbprint(context.Background(), raw, "POST", url, at)
	})
}
