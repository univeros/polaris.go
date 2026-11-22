package mcp

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

// The protected resource: RFC 9728 metadata, bearer and DPoP access tokens, and their refusals.

const (
	testResource = "https://mcp.polaris.test/mcp"
	testMetadata = "https://mcp.polaris.test/.well-known/oauth-protected-resource/mcp"
	issuerURL    = "https://issuer.polaris.test"
	issuerJWKS   = "https://issuer.polaris.test/.well-known/jwks.json"
)

var (
	issuerKey   = sync.OnceValue(func() *rsa.PrivateKey { return mustRSA() })
	strangerKey = sync.OnceValue(func() *rsa.PrivateKey { return mustRSA() })
)

func mustRSA() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
}

func sign(t testing.TB, header, payload map[string]any, key crypto.Signer) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	input := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k, sum[:])
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

// issue mints an access token for the tests: claims override the defaults, a nil
// value removes the claim.
func issue(t testing.TB, now time.Time, claims map[string]any, kid string, key *rsa.PrivateKey) string {
	t.Helper()
	payload := map[string]any{"iss": issuerURL, "sub": "ada", "aud": testResource, "iat": now.Unix(), "nbf": now.Unix(),
		"exp": now.Unix() + 600, "jti": "jti", "scope": "org.read"}
	for k, v := range claims {
		if v == nil {
			delete(payload, k)
		} else {
			payload[k] = v
		}
	}
	return sign(t, map[string]any{"typ": "at+jwt", "alg": "RS256", "kid": kid}, payload, key)
}

func rsaJWK(kid string, k *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
}

// dpopKey is a client's DPoP key.
type dpopKey struct{ k *ecdsa.PrivateKey }

func newDPoPKey() dpopKey {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return dpopKey{k}
}

func (d dpopKey) jwk() map[string]any {
	return map[string]any{"kty": "EC", "crv": "P-256",
		"x": b64(d.k.X.FillBytes(make([]byte, 32))), "y": b64(d.k.Y.FillBytes(make([]byte, 32)))}
}

func (d dpopKey) thumbprint() string { s, _ := thumbprint(d.jwk()); return s }

func (d dpopKey) proof(t testing.TB, method, url, token, jti string, iat int64) string {
	claims := map[string]any{"htm": method, "htu": url, "iat": iat, "jti": jti}
	if token != "" {
		claims["ath"] = sha256b64(token)
	}
	return sign(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": d.jwk()}, claims, d.k)
}

// fakeJWKS answers the published JWK Set and records each fetch.
type fakeJWKS struct {
	mu      sync.Mutex
	doc     any
	fetched int
}

func (f *fakeJWKS) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetched++
	status := http.StatusOK
	if f.doc == nil {
		status = http.StatusNotFound
	}
	body, _ := json.Marshal(f.doc)
	return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
}

type protectCase struct {
	t     *testing.T
	clock *clock.Frozen
	cache cache.Cache
}

func newProtectCase(t *testing.T) *protectCase {
	clk := clock.NewFrozen(time.Now())
	return &protectCase{t: t, clock: clk, cache: cache.NewMemory(clk)}
}

func (c *protectCase) now() time.Time { return c.clock.Now() }

func (c *protectCase) local(mod func(*ProtectConfig)) *ProtectedResource {
	c.t.Helper()
	cfg := ProtectConfig{Resource: testResource, Issuer: issuerURL, Keys: map[string]crypto.PublicKey{"test": &issuerKey().PublicKey},
		Clock: c.clock, Cache: c.cache}
	if mod != nil {
		mod(&cfg)
	}
	pr, err := NewProtectedResource(cfg)
	if err != nil {
		c.t.Fatal(err)
	}
	return pr
}

func (c *protectCase) remote(rt http.RoundTripper) *ProtectedResource {
	c.t.Helper()
	pr, err := NewProtectedResource(ProtectConfig{Resource: testResource, Issuer: issuerURL, JWKSURL: issuerJWKS,
		HTTPClient: &http.Client{Transport: rt}, Clock: c.clock, Cache: c.cache})
	if err != nil {
		c.t.Fatal(err)
	}
	return pr
}

func request(token, scheme, proof string, body any) *http.Request {
	if body == nil {
		body = map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": map[string]any{}}
	}
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, testResource, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", scheme+" "+token)
	}
	if proof != "" {
		r.Header.Set("DPoP", proof)
	}
	return r
}

// through runs the request into a handler answering the verified claims.
func through(pr *ProtectedResource, r *http.Request) (*http.Response, map[string]any) {
	rec := httptest.NewRecorder()
	pr.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, "application/json", Claims(r.Context()), nil)
	})).ServeHTTP(rec, r)
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Result(), body
}

func status(t *testing.T, pr *ProtectedResource, r *http.Request, want int, msg string) {
	t.Helper()
	if resp, body := through(pr, r); resp.StatusCode != want {
		t.Errorf("%s: status %d, want %d (%v)", msg, resp.StatusCode, want, body)
	}
}

func TestAValidTokenReachesTheHandlerWithItsClaims(t *testing.T) {
	c := newProtectCase(t)
	resp, body := through(c.local(nil), request(issue(t, c.now(), nil, "test", issuerKey()), "Bearer", "", nil))
	if resp.StatusCode != 200 || body["sub"] != "ada" {
		t.Fatalf("got %d %v", resp.StatusCode, body)
	}
}

func TestWithoutATokenTheChallengeNamesTheMetadata(t *testing.T) {
	c := newProtectCase(t)
	resp, body := through(c.local(nil), request("", "", "", nil))
	if resp.StatusCode != 401 || resp.Header.Get("WWW-Authenticate") != `Bearer resource_metadata="`+testMetadata+`"` ||
		resp.Header.Get("Content-Type") != "application/problem+json" || resp.Header.Get("Cache-Control") != "no-store" ||
		body["type"] != "https://polaris.univeros.io/problems/mcp/unauthorized" || body["error"] != "mcp_unauthorized" || body["title"] != "Unauthorized" {
		t.Fatalf("got %d %v %v", resp.StatusCode, resp.Header, body)
	}
}

func TestABadTokenIsInvalidToken(t *testing.T) {
	c := newProtectCase(t)
	now := c.now()
	cases := map[string]string{
		"another resource":     issue(t, now, map[string]any{"aud": "https://other.test"}, "test", issuerKey()),
		"expired":              issue(t, now, map[string]any{"exp": now.Unix() - 120}, "test", issuerKey()),
		"not yet valid":        issue(t, now, map[string]any{"nbf": now.Unix() + 120}, "test", issuerKey()),
		"another issuer":       issue(t, now, map[string]any{"iss": "https://other.test"}, "test", issuerKey()),
		"a stranger signature": issue(t, now, nil, "test", strangerKey()),
		"an unknown kid":       issue(t, now, nil, "other", issuerKey()),
		"no expiry":            issue(t, now, map[string]any{"exp": nil}, "test", issuerKey()),
		"not a JWT":            "opaque",
		"no kid":               sign(t, map[string]any{"alg": "RS256"}, map[string]any{}, issuerKey()),
	}
	for name, token := range cases {
		resp, _ := through(c.local(nil), request(token, "Bearer", "", nil))
		h := resp.Header.Get("WWW-Authenticate")
		if resp.StatusCode != 401 || !strings.HasPrefix(h, `Bearer error="invalid_token", error_description="`) ||
			!strings.HasSuffix(h, `resource_metadata="`+testMetadata+`"`) {
			t.Errorf("%s: %d %s", name, resp.StatusCode, h)
		}
	}
	// The issuer itself is an accepted audience only when configured so (Polaris's own /mcp).
	status(t, c.local(nil), request(issue(t, now, map[string]any{"aud": issuerURL}, "test", issuerKey()), "Bearer", "", nil), 401, "issuer aud")
	status(t, c.local(func(cfg *ProtectConfig) { cfg.Audiences = []string{issuerURL} }),
		request(issue(t, now, map[string]any{"aud": []string{issuerURL, "x"}}, "test", issuerKey()), "Bearer", "", nil), 200, "issuer aud allowed")
}

func TestAMissingScopeIsInsufficientScopeNamingTheMissingOnes(t *testing.T) {
	c := newProtectCase(t)
	pr := c.local(func(cfg *ProtectConfig) { cfg.Scopes = []string{"org.read", "deploy", "members.read"} })
	resp, body := through(pr, request(issue(t, c.now(), map[string]any{"scope": "org.read openid"}, "test", issuerKey()), "Bearer", "", nil))
	want := `Bearer error="insufficient_scope", scope="deploy members.read", resource_metadata="` + testMetadata + `"`
	if resp.StatusCode != 403 || resp.Header.Get("WWW-Authenticate") != want || body["title"] != "Insufficient scope" ||
		body["type"] != "https://polaris.univeros.io/problems/mcp/insufficient_scope" {
		t.Fatalf("got %d %v %v", resp.StatusCode, resp.Header, body)
	}
	if got, _ := json.Marshal(body["missing_scopes"]); string(got) != `["deploy","members.read"]` {
		t.Errorf("missing_scopes %s", got)
	}
	status(t, c.local(func(cfg *ProtectConfig) { cfg.Scopes = []string{"org.read"} }),
		request(issue(t, c.now(), map[string]any{"scope": []string{"org.read"}}, "test", issuerKey()), "Bearer", "", nil), 200, "a scope list")
}

func TestADPoPBoundTokenNeedsAProofForTheRequestByItsKey(t *testing.T) {
	c := newProtectCase(t)
	pr := c.local(nil)
	key := newDPoPKey()
	now := c.now().Unix()
	token := issue(t, c.now(), map[string]any{"cnf": map[string]any{"jkt": key.thumbprint()}}, "test", issuerKey())
	proof := func(url, jti string) string { return key.proof(t, "POST", url, token, jti, now) }

	status(t, pr, request(token, "Bearer", "", nil), 401, "bound token with the Bearer scheme")
	status(t, pr, request(token, "DPoP", "", nil), 401, "no proof")
	status(t, pr, request(token, "DPoP", proof("https://mcp.polaris.test/other", "a"), nil), 401, "a proof for another URL")
	status(t, pr, request(token, "DPoP", key.proof(t, "POST", testResource, "", "b", now), nil), 401, "a proof without ath")
	status(t, pr, request(token, "DPoP", key.proof(t, "POST", testResource, token, "c", now-600), nil), 401, "a stale proof")
	status(t, pr, request(token, "DPoP", newDPoPKey().proof(t, "POST", testResource, token, "d", now), nil), 401, "another key")
	status(t, pr, request(token, "DPoP", "not-a-jwt", nil), 401, "not a JWT")
	status(t, pr, request(token, "DPoP", sign(t, map[string]any{"typ": "jwt", "alg": "ES256"}, map[string]any{}, key.k), nil), 401, "wrong typ")
	status(t, pr, request(token, "DPoP", sign(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": map[string]any{"kty": "oct"}}, map[string]any{}, key.k), nil), 401, "unsupported key")
	priv := key.jwk()
	priv["d"] = "x"
	status(t, pr, request(token, "DPoP", sign(t, map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": priv}, map[string]any{}, key.k), nil), 401, "a private key")
	resp, body := through(pr, request(token, "DPoP", proof(testResource, "once"), nil))
	if resp.StatusCode != 200 || body["cnf"].(map[string]any)["jkt"] != key.thumbprint() {
		t.Fatalf("a good proof: %d %v", resp.StatusCode, body)
	}
	status(t, pr, request(token, "DPoP", proof(testResource, "once"), nil), 401, "the same proof again")
	status(t, pr, request(token, "DPoP", proof(testResource+"?q=1", "fresh"), nil), 200, "a fresh one, query ignored")
	status(t, pr, request(issue(t, c.now(), nil, "test", issuerKey()), "DPoP", proof(testResource, "e"), nil), 401, "a bearer token with the DPoP scheme")
}

func TestAgainstARemoteIssuerTheKeysAreFetchedOnceAndCached(t *testing.T) {
	c := newProtectCase(t)
	fake := &fakeJWKS{doc: map[string]any{"keys": []any{rsaJWK("test", &issuerKey().PublicKey)}}}
	pr := c.remote(fake)
	tok := func(kid string) *http.Request {
		return request(issue(t, c.now(), nil, kid, issuerKey()), "Bearer", "", nil)
	}

	status(t, pr, tok("test"), 200, "first")
	status(t, pr, tok("test"), 200, "second")
	if fake.fetched != 1 {
		t.Fatalf("the set is cached: %d fetches", fake.fetched)
	}
	status(t, pr, request(issue(t, c.now(), nil, "test", strangerKey()), "Bearer", "", nil), 401, "a stranger's signature")
	// An unknown kid fetches the set once more (a rotation); still unknown, the token is refused.
	status(t, pr, tok("rotated"), 401, "unknown kid")
	if fake.fetched != 2 {
		t.Fatalf("refetch on unknown kid: %d", fake.fetched)
	}
	// Another unknown kid within a minute fetches nothing.
	fake.doc = map[string]any{"keys": []any{rsaJWK("rotated", &issuerKey().PublicKey)}}
	for _, kid := range []string{"rotated", "other", "rotated"} {
		status(t, pr, tok(kid), 401, "unknown kid within the interval "+kid)
	}
	if fake.fetched != 2 {
		t.Fatalf("no refetch within %s: %d", MinJWKSRefetch, fake.fetched)
	}
	c.clock.Advance(MinJWKSRefetch)
	status(t, pr, tok("rotated"), 200, "the rotated key once the interval is over")
	if fake.fetched != 3 {
		t.Fatalf("fetches: %d", fake.fetched)
	}
	// A key whose alg is not the token's is refused.
	fake.doc = map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": "ps", "alg": "PS256", "n": "x", "e": "AQAB"}}}
	c.clock.Advance(DefaultJWKSTTL)
	status(t, pr, tok("ps"), 401, "a key for another alg")

	// An issuer that cannot be reached, or answers junk, refuses with a generic reason.
	for name, doc := range map[string]any{"down": nil, "junk": "junk"} {
		c2 := newProtectCase(t)
		resp, body := through(c2.remote(&fakeJWKS{doc: doc}), request(issue(t, c2.now(), nil, "test", issuerKey()), "Bearer", "", nil))
		if resp.StatusCode != 401 || !strings.Contains(body["detail"].(string), "could not be verified") {
			t.Errorf("%s: %d %v", name, resp.StatusCode, body)
		}
	}
}

func TestTheSessionBasedProtocolIsRejectedUnlessAllowed(t *testing.T) {
	c := newProtectCase(t)
	token := issue(t, c.now(), nil, "test", issuerKey())
	cases := map[string]func() *http.Request{
		"a session header": func() *http.Request {
			r := request(token, "Bearer", "", nil)
			r.Header.Set("Mcp-Session-Id", "019aa7e0-0000-7000-8000-000000000000")
			return r
		},
		"an older version": func() *http.Request {
			r := request(token, "Bearer", "", nil)
			r.Header.Set("MCP-Protocol-Version", "2025-11-25")
			return r
		},
		"an initialize call": func() *http.Request {
			return request(token, "Bearer", "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{}})
		},
	}
	for name, r := range cases {
		resp, body := through(c.local(nil), r())
		if resp.StatusCode != 400 || body["type"] != "https://polaris.univeros.io/problems/mcp/legacy_protocol" || body["protocol_version"] != ProtocolVersion {
			t.Errorf("%s: %d %v", name, resp.StatusCode, body)
		}
		status(t, c.local(func(cfg *ProtectConfig) { cfg.AllowLegacy = true }), r(), 200, name+", allowed")
	}
	r := request(token, "Bearer", "", nil)
	r.Header.Set("MCP-Protocol-Version", ProtocolVersion)
	status(t, c.local(nil), r, 200, "the current version")
	// The body stays readable for the server behind.
	var seen []byte
	rec := httptest.NewRecorder()
	c.local(nil).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen, _ = io.ReadAll(r.Body) })).
		ServeHTTP(rec, request(token, "Bearer", "", nil))
	if !strings.Contains(string(seen), "tools/list") {
		t.Errorf("body after the check: %q", seen)
	}
}

func TestItServesItsOwnMetadata(t *testing.T) {
	c := newProtectCase(t)
	pr := c.local(func(cfg *ProtectConfig) { cfg.Scopes = []string{"org.read"}; cfg.ResourceName = "Polaris" })
	resp, body := through(pr, httptest.NewRequest(http.MethodGet, testMetadata, nil))
	got, _ := json.Marshal(body)
	want, _ := json.Marshal(map[string]any{"resource": testResource, "authorization_servers": []string{issuerURL},
		"scopes_supported": []string{"org.read"}, "bearer_methods_supported": []string{"header"},
		"dpop_signing_alg_values_supported": Algorithms, "resource_name": "Polaris"})
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "public, max-age=3600" || string(got) != string(want) {
		t.Fatalf("got %d %s", resp.StatusCode, got)
	}
	if pr.MetadataURL() != testMetadata {
		t.Error(pr.MetadataURL())
	}
	for resource, want := range map[string]string{
		"https://app.test/":         "https://app.test/.well-known/oauth-protected-resource",
		"https://app.test/auth/mcp": "https://app.test/.well-known/oauth-protected-resource/auth/mcp",
	} {
		if got := c.local(func(cfg *ProtectConfig) { cfg.Resource = resource }).MetadataURL(); got != want {
			t.Errorf("%s: %s", resource, got)
		}
	}
	if _, body := through(c.local(nil), httptest.NewRequest(http.MethodGet, testMetadata, nil)); body["scopes_supported"] == nil {
		t.Error("scopes_supported must be [] without scopes")
	}
}

func TestConfigErrorsNameTheirFix(t *testing.T) {
	for name, cfg := range map[string]ProtectConfig{
		"no resource":   {Issuer: issuerURL, JWKSURL: issuerJWKS},
		"no issuer":     {Resource: testResource, JWKSURL: issuerJWKS},
		"no keys":       {Resource: testResource, Issuer: issuerURL},
		"two sources":   {Resource: testResource, Issuer: issuerURL, JWKSURL: issuerJWKS, Keys: map[string]crypto.PublicKey{"k": nil}},
		"http jwks uri": {Resource: testResource, Issuer: issuerURL, JWKSURL: "http://issuer.test/jwks"},
	} {
		if _, err := Protect(http.NotFoundHandler(), cfg); err == nil || !strings.Contains(err.Error(), "ProtectConfig") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Protect(http.NotFoundHandler(), ProtectConfig{Resource: testResource, Issuer: issuerURL, JWKSURL: issuerJWKS}); err != nil {
		t.Fatal(err)
	}
}

func TestTheJoseHelpers(t *testing.T) {
	// RFC 7638 §3.1's example thumbprint.
	jwk := map[string]any{"kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"}
	if got, _ := thumbprint(jwk); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Error(got)
	}
	if _, ok := thumbprint(map[string]any{"kty": "oct", "k": "x"}); ok {
		t.Error("oct has no thumbprint")
	}
	if jwtHeader("not.a-jwt") != nil {
		t.Error("header of a non-JWT")
	}
}
