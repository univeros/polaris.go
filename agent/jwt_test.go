package agent

import (
	"crypto/sha256"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// Port of RequestJwtTest.

var frozen = time.Unix(1760090400, 0)

func TestRequestJwt(t *testing.T) {
	t.Run("testTheRequestJwtCarriesTheProtocolsClaimsForTheExactUrlAndBody", func(t *testing.T) {
		key, _ := GenerateKey(ES256)
		body := []byte(`{"capability":"demo.echo","arguments":{"hello":"world"}}`)
		jwt, err := signRequest(key, "agent-1", "post", "https://auth.polaris.test/agents/execute?x=1#f", body, nil, DefaultRequestTTL, frozen)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := rawHeader(t, jwt), fmt.Sprintf(`{"typ":"agent+jwt","alg":"ES256","kid":"%s"}`, key.KID()); got != want {
			t.Fatalf("header %s, want %s", got, want)
		}
		_, c := decodeJWT(t, jwt)
		sum := sha256.Sum256(body)
		want := map[string]any{"sub": "agent-1", "aud": "https://auth.polaris.test/agents/execute", "iat": 1760090400.0, "exp": 1760090460.0, "htm": "POST", "htu": "https://auth.polaris.test/agents/execute", "body_hash": b64(sum[:])}
		for k, v := range want {
			if c[k] != v {
				t.Fatalf("%s = %v, want %v", k, c[k], v)
			}
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`).MatchString(c["jti"].(string)) {
			t.Fatalf("jti %v", c["jti"])
		}
		if _, ok := c["capabilities"]; ok {
			t.Fatal("capabilities without a restriction")
		}
		if !verifiesWith(jwt, key.PublicJWK()) {
			t.Fatal("does not verify with the public JWK")
		}
	})

	t.Run("testEdDsaCapabilitiesTtlAndNoBodyHashWithoutABody", func(t *testing.T) {
		key, _ := GenerateKey(EdDSA)
		jwt, err := signRequest(key, "agent-1", "GET", "https://auth.polaris.test/agents/session", nil, []string{"demo.echo"}, MaxRequestTTL, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		h, c := decodeJWT(t, jwt)
		if h["alg"] != "EdDSA" || fmt.Sprint(c["capabilities"]) != "[demo.echo]" || c["exp"].(float64)-c["iat"].(float64) != 300 {
			t.Fatalf("header %v claims %v", h, c)
		}
		if _, ok := c["body_hash"]; ok {
			t.Fatal("body_hash without a body")
		}
		if !verifiesWith(jwt, key.PublicJWK()) {
			t.Fatal("does not verify")
		}
		other, _ := signRequest(key, "a", "GET", "https://x.test/", nil, nil, DefaultRequestTTL, time.Now())
		if _, oc := decodeJWT(t, other); oc["jti"] == c["jti"] {
			t.Fatal("two JWTs share a jti")
		}
	})

	t.Run("testItNeverSignsForLongerThanTheServerAcceptsAndAnotherKeyDoesNotVerify", func(t *testing.T) {
		key, _ := GenerateKey(ES256)
		for _, ttl := range []time.Duration{301 * time.Second, 0} {
			if _, err := signRequest(key, "a", "GET", "https://x.test/", nil, nil, ttl, time.Now()); err == nil || !strings.Contains(err.Error(), "300") {
				t.Fatalf("ttl %s: %v", ttl, err)
			}
		}
		other, _ := GenerateKey(ES256)
		jwt, _ := signRequest(key, "a", "GET", "https://x.test/", nil, nil, DefaultRequestTTL, time.Now())
		if verifiesWith(jwt, other.PublicJWK()) {
			t.Fatal("verifies with another key")
		}
	})

	t.Run("testTheClientAssertionNamesTheAgentAndTheTokenEndpoint", func(t *testing.T) {
		key, _ := GenerateKey(ES256)
		assertion, err := signAssertion(key, "agent-1", "https://auth.polaris.test/oauth2/token", frozen)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := rawHeader(t, assertion), fmt.Sprintf(`{"typ":"JWT","alg":"ES256","kid":"%s"}`, key.KID()); got != want {
			t.Fatalf("header %s", got)
		}
		_, c := decodeJWT(t, assertion)
		got := []any{c["iss"], c["sub"], c["aud"], c["iat"], c["exp"]}
		if !slices.Equal(got, []any{"agent-1", "agent-1", "https://auth.polaris.test/oauth2/token", 1760090400.0, 1760090700.0}) {
			t.Fatalf("claims %v", got)
		}
	})
}

func TestCanonicalURLDropsQueryAndFragmentOnly(t *testing.T) {
	for in, want := range map[string]string{
		"https://h.test/a/b?x=1": "https://h.test/a/b", "https://h.test/a#f": "https://h.test/a", "https://h.test:8443/a/": "https://h.test:8443/a/",
	} {
		if got := canonicalURL(in); got != want {
			t.Fatalf("%s: %s", in, got)
		}
	}
}
