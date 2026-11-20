package agents

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

// FuzzRequestJWT signs arbitrary header and claims bytes with the agent's registered key, so
// the fuzzer reaches every check behind the signature; a raw string goes through the unsigned
// path. Nothing may panic, and an accepted JWT must name the agent, the URL called and a jti.
func FuzzRequestJWT(f *testing.F) {
	const url = unitBase + "/agents/execute"
	k := newTestKey(AlgEdDSA)
	a := Agent{ID: "agent-1", PublicJWK: k.jwk()}
	now := time.Unix(1_800_000_000, 0)
	hj, _ := json.Marshal(map[string]any{"typ": RequestJWTType, "alg": AlgEdDSA})
	cj, _ := json.Marshal(map[string]any{"sub": a.ID, "aud": url, "iat": now.Unix(), "exp": now.Unix() + 120, "jti": "j1",
		"htm": "POST", "htu": url, "body_hash": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", "capabilities": []any{"a"}})
	f.Add(hj, cj, "")
	f.Add([]byte(`{"typ":"agent+jwt","alg":"EdDSA","jwk":{}}`), []byte(`{"sub":"agent-1","iat":1e400,"exp":-1}`), "a.b.c")
	f.Add([]byte(`{"typ":"agent+jwt","alg":"ES256"}`), []byte(`{"sub":"agent-1","aud":"https://auth.polaris.test/agents/execute?x","iat":9223372036854775807,"exp":-9223372036854775808}`), "")
	f.Fuzz(func(t *testing.T, header, claims []byte, raw string) {
		clk := clock.NewFrozen(now)
		j := &requestJWTs{cache: cache.NewMemory(clk), clock: clk, maxAge: 300}
		input := enc(header) + "." + enc(claims)
		signed := input + "." + enc(ed25519.Sign(k.ed, []byte(input)))
		if _, err := j.verify(context.Background(), signed, a, "POST", url, nil); err == nil {
			var c map[string]any
			if json.Unmarshal(claims, &c) != nil || c["sub"] != a.ID || c["jti"] == "" {
				t.Fatalf("accepted %s", claims)
			}
			if _, err := j.verify(context.Background(), signed, a, "POST", url, nil); err == nil {
				t.Fatal("a request JWT was accepted twice")
			}
		}
		_, _ = j.verify(context.Background(), raw, a, "POST", url, nil)
		_, _ = peekRequestJWT(raw)
	})
}
