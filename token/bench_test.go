package token

import (
	"testing"
)

// BenchmarkParse verifies a session access token (signature, iss, aud, exp, nbf, typ), the work
// every authenticated request does.
func BenchmarkParse(b *testing.B) {
	k := loadKeys(b)
	for _, alg := range []struct {
		name   string
		mutate func(*Config)
	}{
		{"RS256", func(*Config) {}},
		{"EdDSA", func(c *Config) { c.Algorithm, c.PrivateKey, c.PublicKey = EdDSA, k.edSecret(), k.edPublic() }},
	} {
		b.Run(alg.name, func(b *testing.B) {
			c := newCodec(b, testConfig(b, at(b, "2026-01-01 00:00:00"), alg.mutate))
			claims, err := AccessClaims{Subject: "user-1", ID: "jti-1", AMR: []string{"pwd"}}.Claims()
			if err != nil {
				b.Fatal(err)
			}
			raw, err := c.Issue(claims)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				if _, err := c.Parse(raw); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
