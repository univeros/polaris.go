package verify_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/verify"
)

const (
	issuerURL = "https://auth.polaris.test"
	service   = "https://billing.polaris.test"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// issuer is a Polaris issuer: an RS256 and an EdDSA codec, and the JWK Set it publishes.
type issuer struct {
	clock *clock.Frozen
	rsa   *token.Codec // kid rsa-1
	ed    *token.Codec // kid ed-1
	srv   *httptest.Server

	mu      sync.Mutex
	keys    []token.JWK
	fetches int
	down    bool
}

func newIssuer(t testing.TB) *issuer {
	t.Helper()
	i := &issuer{clock: clock.NewFrozen(time.Unix(1_800_000_000, 0))}
	private, public := contracttest.TestRSAKeyPEM()
	i.rsa = codec(t, token.Config{Algorithm: token.RS256, PrivateKey: private, PublicKey: public, KeyID: "rsa-1", Issuer: issuerURL, TTL: 900 * time.Second, Clock: i.clock})
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	i.ed = codec(t, token.Config{Algorithm: token.EdDSA, PrivateKey: string(edPriv), PublicKey: string(edPub), KeyID: "ed-1", Issuer: issuerURL, TTL: 900 * time.Second, Clock: i.clock})
	rsaSet, err := token.NewJWKSet(token.RS256, token.PublicKey{KeyID: "rsa-1", PEM: public})
	if err != nil {
		t.Fatal(err)
	}
	edSet, err := token.NewJWKSet(token.EdDSA, token.PublicKey{KeyID: "ed-1", PEM: string(edPub)})
	if err != nil {
		t.Fatal(err)
	}
	i.keys = append(rsaSet.Keys, edSet.Keys...)
	i.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i.mu.Lock()
		defer i.mu.Unlock()
		i.fetches++
		if i.down {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(token.JWKSet{Keys: i.keys})
	}))
	t.Cleanup(i.srv.Close)
	return i
}

func codec(t testing.TB, cfg token.Config) *token.Codec {
	t.Helper()
	c, err := token.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (i *issuer) set(f func(i *issuer)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	f(i)
}

func (i *issuer) fetched() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.fetches
}

// verifier verifies against this issuer; cfg's zero fields are filled.
func (i *issuer) verifier(t testing.TB, cfg verify.Config) *verify.Verifier {
	t.Helper()
	if cfg.Issuer == "" {
		cfg.Issuer = issuerURL
	}
	cfg.JWKSURL = i.srv.URL + "/auth/.well-known/jwks.json"
	cfg.HTTPClient, cfg.Clock, cfg.Logger = i.srv.Client(), i.clock, quiet
	v, err := verify.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// session is a Polaris session access token for ada in org-1, in the claim shape session.Mint
// writes (token.AccessClaims); typ JWT, aud only when c has an Audience.
func (i *issuer) session(t testing.TB, c *token.Codec, extra ...any) string {
	t.Helper()
	claims, err := token.AccessClaims{Subject: "ada", ID: "j1", SessionID: "s1", OrganizationID: "org-1", Roles: []string{"member"},
		Scope: []string{"invoices.read", "invoices.write"}, EmailVerified: true, AMR: []string{"pwd"}}.Claims()
	if err != nil {
		t.Fatal(err)
	}
	for k := 0; k+1 < len(extra); k += 2 {
		claims = claims.With(extra[k].(string), extra[k+1])
	}
	raw, err := c.Issue(claims)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// oauth is an OAuth access token (typ at+jwt) for aud with a space-separated scope.
func (i *issuer) oauth(t testing.TB, aud, scope string) string {
	t.Helper()
	raw, err := i.rsa.Mint("at+jwt", token.Claims{}.With("sub", "ada").With("aud", aud).With("client_id", "c1").With("scope", scope).With("jti", "j2"),
		i.clock.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// forge signs header and payload with key (RSA, ECDSA, or an HMAC secret as []byte).
func forge(t testing.TB, header, payload map[string]any, key any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	input := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		var err error
		if sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:]); err != nil {
			t.Fatal(err)
		}
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	case []byte:
		m := hmac.New(sha256.New, k)
		m.Write([]byte(input))
		sig = m.Sum(nil)
	}
	return input + "." + b64(sig)
}

func (i *issuer) payload(extra map[string]any) map[string]any {
	now := i.clock.Now().Unix()
	p := map[string]any{"iss": issuerURL, "sub": "ada", "iat": now, "nbf": now, "exp": now + 600, "roles": []string{}}
	for k, v := range extra {
		if v == nil {
			delete(p, k)
		} else {
			p[k] = v
		}
	}
	return p
}

func TestVerifyAcceptsPolarisAccessTokens(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier(t, verify.Config{})
	for name, raw := range map[string]string{
		"an RS256 session token": i.session(t, i.rsa),
		"an EdDSA session token": i.session(t, i.ed),
	} {
		c, err := v.Verify(context.Background(), raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if c.Subject != "ada" || c.OrganizationID != "org-1" || !slices.Equal(c.Scopes, []string{"invoices.read", "invoices.write"}) ||
			!c.ExpiresAt.Equal(i.clock.Now().Add(900*time.Second)) || c.All["jti"] != "j1" {
			t.Fatalf("%s: claims %+v", name, c)
		}
	}
	c, err := i.verifier(t, verify.Config{Audiences: []string{service}}).Verify(context.Background(), i.oauth(t, service, "invoices.read openid"))
	if err != nil || c.Subject != "ada" || c.OrganizationID != "" || !slices.Equal(c.Scopes, []string{"invoices.read", "openid"}) || c.All["client_id"] != "c1" {
		t.Fatalf("an OAuth token: %+v %v", c, err)
	}
	if i.fetched() != 2 {
		t.Fatalf("each verifier fetches the JWK Set once and caches it: %d fetches", i.fetched())
	}
}

// idToken is an OpenID ID token as plugins/oauth mintIDToken writes it: Mint with typ "" (so
// "JWT"), the same key, aud the client_id, the OpenID claims, auth_time and nonce.
func (i *issuer) idToken(t testing.TB, clientID string) string {
	t.Helper()
	claims := token.Claims{}.With("sub", "ada").With("aud", clientID).With("jti", "id1").
		With("email", "ada@example.com").With("email_verified", true).With("name", "Ada").With("updated_at", i.clock.Now().Unix()).
		With("auth_time", i.clock.Now().Unix()).With("nonce", "n-0S6")
	raw, err := i.rsa.Mint("", claims, i.clock.Now().Add(15*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// An ID token is not an access token, even when its aud (the client_id) is an audience this
// service accepts: a service that is itself an OAuth client of the issuer.
func TestIDTokensAreNotAccessTokens(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier(t, verify.Config{Audiences: []string{service}})
	idToken := i.idToken(t, service)
	if _, err := v.Verify(context.Background(), idToken); !errors.Is(err, verify.ErrInvalidToken) {
		t.Fatalf("Verify accepted an ID token: %v", err)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+idToken)
	w := httptest.NewRecorder()
	v.Require()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("Require let an ID token through") })).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Require: %d", w.Code)
	}

	// What still passes: session tokens with and without AUTH_AUDIENCE, and at+jwt tokens.
	private, public := contracttest.TestRSAKeyPEM()
	withAudience := codec(t, token.Config{PrivateKey: private, PublicKey: public, KeyID: "rsa-1", Issuer: issuerURL, Audience: service, TTL: time.Hour, Clock: i.clock})
	for name, c := range map[string]struct {
		v   *verify.Verifier
		raw string
	}{
		"a session token, no AUTH_AUDIENCE":  {i.verifier(t, verify.Config{}), i.session(t, i.rsa)},
		"a session token with AUTH_AUDIENCE": {v, i.session(t, withAudience)},
		"an EdDSA session token":             {i.verifier(t, verify.Config{}), i.session(t, i.ed)},
		"an at+jwt for this service":         {v, i.oauth(t, service, "invoices.read")},
	} {
		if _, err := c.v.Verify(context.Background(), c.raw); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Every refusal is ErrInvalidToken, never a panic, never a downgrade.
func TestVerifyRefuses(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier(t, verify.Config{})
	withAud := i.verifier(t, verify.Config{Audiences: []string{service}})
	rsaKey := contracttest.TestRSAKey()
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})
	stranger, _ := rsa.GenerateKey(rand.Reader, 2048)
	strangerPEM, _ := x509.MarshalPKCS8PrivateKey(stranger)
	private, public := contracttest.TestRSAKeyPEM()
	otherIssuer := codec(t, token.Config{PrivateKey: private, PublicKey: public, KeyID: "rsa-1", Issuer: "https://evil.test", TTL: time.Hour, Clock: i.clock})
	withAudience := codec(t, token.Config{PrivateKey: private, PublicKey: public, KeyID: "rsa-1", Issuer: issuerURL, Audience: "https://other.test", TTL: time.Hour, Clock: i.clock})
	impostor := codec(t, token.Config{PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: strangerPEM})), PublicKey: public, KeyID: "rsa-1", Issuer: issuerURL, TTL: time.Hour, Clock: i.clock})
	receipt, _ := i.rsa.Sign("polaris-receipt+jwt", token.Claims{}.With("sub", "ada").With("exp", i.clock.Now().Add(time.Hour)))
	noExpiry, _ := i.rsa.Sign("", token.Claims{}.With("sub", "ada"))
	ticket := i.session(t, i.rsa, "purpose", "login_mfa")
	good := i.session(t, i.rsa)
	rs := map[string]any{"typ": "JWT", "alg": "RS256", "kid": "rsa-1"}

	cases := map[string]struct {
		v   *verify.Verifier
		raw string
	}{
		"empty":                           {v, ""},
		"not a JWT":                       {v, "pk_live_abc"},
		"a tampered signature":            {v, good[:len(good)-4] + "AAAA"},
		"another issuer":                  {v, i.session(t, otherIssuer)},
		"signed by another key":           {v, i.session(t, impostor)},
		"an aud nobody configured":        {v, i.session(t, withAudience)},
		"an OAuth token, no aud set":      {v, i.oauth(t, service, "invoices.read")},
		"another audience":                {withAud, i.oauth(t, "https://other.test", "invoices.read")},
		"no aud for a resource":           {withAud, good},
		"a login-MFA ticket":              {v, ticket},
		"a receipt (wrong typ)":           {v, receipt},
		"a DPoP proof typ":                {v, forge(t, map[string]any{"typ": "dpop+jwt", "alg": "RS256", "kid": "rsa-1"}, i.payload(nil), rsaKey)},
		"no typ":                          {v, forge(t, map[string]any{"alg": "RS256", "kid": "rsa-1"}, i.payload(nil), rsaKey)},
		"a non-string typ":                {v, forge(t, map[string]any{"typ": 1, "alg": "RS256", "kid": "rsa-1"}, i.payload(nil), rsaKey)},
		"no expiry":                       {v, noExpiry},
		"a string exp":                    {v, forge(t, rs, i.payload(map[string]any{"exp": "9999999999"}), rsaKey)},
		"no kid":                          {v, forge(t, map[string]any{"typ": "JWT", "alg": "RS256"}, i.payload(nil), rsaKey)},
		"an unknown kid":                  {v, forge(t, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "nope"}, i.payload(nil), rsaKey)},
		"alg none":                        {v, forge(t, map[string]any{"typ": "JWT", "alg": "none", "kid": "rsa-1"}, i.payload(nil), []byte{}) + "x"},
		"HS256 keyed with the public key": {v, forge(t, map[string]any{"typ": "JWT", "alg": "HS256", "kid": "rsa-1"}, i.payload(nil), publicPEM)},
		"ES256, not a Polaris alg":        {v, forge(t, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "rsa-1"}, i.payload(nil), ecKey)},
		"RS256 naming the EdDSA kid":      {v, forge(t, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "ed-1"}, i.payload(nil), rsaKey)},
		"expired":                         {v, forge(t, rs, i.payload(map[string]any{"exp": i.clock.Now().Unix() - 61}), rsaKey)},
		"not yet valid":                   {v, forge(t, rs, i.payload(map[string]any{"nbf": i.clock.Now().Unix() + 61}), rsaKey)},
		"issued in the future":            {v, forge(t, rs, i.payload(map[string]any{"iat": i.clock.Now().Unix() + 61}), rsaKey)},
		"DPoP-bound":                      {v, forge(t, rs, i.payload(map[string]any{"cnf": map[string]any{"jkt": "abc"}}), rsaKey)},
	}
	for name, c := range cases {
		if _, err := c.v.Verify(context.Background(), c.raw); !errors.Is(err, verify.ErrInvalidToken) {
			t.Errorf("%s: %v, want ErrInvalidToken", name, err)
		}
	}
	// The leeway is a minute: a token a few seconds past exp still verifies.
	if _, err := v.Verify(context.Background(), forge(t, rs, i.payload(map[string]any{"exp": i.clock.Now().Unix() - 30}), rsaKey)); err != nil {
		t.Fatalf("within the leeway: %v", err)
	}
}

func TestExpiryFollowsTheClock(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier(t, verify.Config{})
	raw := i.session(t, i.rsa)
	i.clock.Advance(900*time.Second + time.Minute)
	if _, err := v.Verify(context.Background(), raw); !errors.Is(err, verify.ErrInvalidToken) {
		t.Fatalf("an expired session token: %v", err)
	}
}

// A new key reaches the verifier through an unknown kid, at most once a minute.
func TestKeyRotation(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier(t, verify.Config{})
	if _, err := v.Verify(context.Background(), i.session(t, i.rsa)); err != nil {
		t.Fatal(err)
	}
	next, nextPriv, _ := ed25519.GenerateKey(rand.Reader)
	rotated := codec(t, token.Config{Algorithm: token.EdDSA, PrivateKey: string(nextPriv), PublicKey: string(next), KeyID: "ed-2", Issuer: issuerURL, TTL: time.Hour, Clock: i.clock})
	set, _ := token.NewJWKSet(token.EdDSA, token.PublicKey{KeyID: "ed-2", PEM: string(next)})
	i.set(func(i *issuer) { i.keys = append(i.keys, set.Keys...) })

	if _, err := v.Verify(context.Background(), i.session(t, rotated)); err != nil || i.fetched() != 2 {
		t.Fatalf("a token by the new key: %v after %d fetches", err, i.fetched())
	}
	unknown := forge(t, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "ghost"}, i.payload(nil), contracttest.TestRSAKey())
	for range 3 {
		if _, err := v.Verify(context.Background(), unknown); !errors.Is(err, verify.ErrInvalidToken) {
			t.Fatalf("an unknown kid: %v", err)
		}
	}
	if i.fetched() != 2 {
		t.Fatalf("unknown kids refetch at most once a minute: %d fetches", i.fetched())
	}
	i.clock.Advance(time.Minute)
	_, _ = v.Verify(context.Background(), unknown)
	if i.fetched() != 3 {
		t.Fatalf("a minute later an unknown kid refetches: %d fetches", i.fetched())
	}
	// The retired key leaves the set: once the cached set expires, its tokens stop verifying.
	i.set(func(i *issuer) { i.keys = set.Keys })
	i.clock.Advance(time.Hour)
	if _, err := v.Verify(context.Background(), i.session(t, i.rsa)); !errors.Is(err, verify.ErrInvalidToken) {
		t.Fatalf("a token by the retired key: %v", err)
	}
}

func TestJWKSDown(t *testing.T) {
	i := newIssuer(t)
	cold := i.verifier(t, verify.Config{})
	warm := i.verifier(t, verify.Config{})
	raw := i.session(t, i.rsa)
	if _, err := warm.Verify(context.Background(), raw); err != nil {
		t.Fatal(err)
	}
	i.set(func(i *issuer) { i.down = true })
	if _, err := cold.Verify(context.Background(), raw); !errors.Is(err, verify.ErrUnavailable) || errors.Is(err, verify.ErrInvalidToken) {
		t.Fatalf("no cached key: %v, want ErrUnavailable", err)
	}
	if _, err := warm.Verify(context.Background(), raw); err != nil {
		t.Fatalf("a cached key still verifies: %v", err)
	}
	i.clock.Advance(time.Hour)
	if _, err := warm.Verify(context.Background(), i.session(t, i.rsa)); !errors.Is(err, verify.ErrUnavailable) {
		t.Fatalf("a cached set past its TTL is not used stale: %v", err)
	}
	i.set(func(i *issuer) { i.down = false })
	i.clock.Advance(5 * time.Second) // a failed fetch is remembered that long (decision 69)
	if _, err := warm.Verify(context.Background(), i.session(t, i.rsa)); err != nil {
		t.Fatalf("the issuer is back: %v", err)
	}
}

// Without HTTPClient the fetch goes through the SSRF guard: a loopback issuer is refused.
func TestTheDefaultClientRefusesPrivateAddresses(t *testing.T) {
	i := newIssuer(t)
	v, err := verify.New(verify.Config{Issuer: issuerURL, JWKSURL: i.srv.URL + "/jwks.json", Clock: i.clock, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), i.session(t, i.rsa)); !errors.Is(err, verify.ErrUnavailable) || i.fetched() != 0 {
		t.Fatalf("loopback JWKS: %v after %d fetches", err, i.fetched())
	}
}

func TestNewNamesTheFix(t *testing.T) {
	_, err := verify.New(verify.Config{JWKSURL: "http://auth.example.com/jwks.json"})
	for _, want := range []string{"Config.Issuer is empty", "must be an https URL"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("New: %v, want %q", err, want)
		}
	}
	if _, err := verify.New(verify.Config{Issuer: issuerURL}); err == nil || !strings.Contains(err.Error(), "Config.JWKSURL is empty") {
		t.Errorf("New without JWKSURL: %v", err)
	}
}

func TestRequire(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier(t, verify.Config{})
	host := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := verify.ClaimsFrom(r.Context())
		if !ok {
			t.Error("no claims behind Require")
		}
		_, _ = io.WriteString(w, c.Subject+" "+c.OrganizationID)
	})
	serve := func(h http.Handler, authorization string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "/invoices", nil)
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	raw := i.session(t, i.rsa)
	for name, c := range map[string]struct {
		h             http.Handler
		authorization string
		status        int
		challenge     string
		body          string
	}{
		"no token":          {v.Require()(host), "", 401, `Bearer`, `"unauthorized"`},
		"another scheme":    {v.Require()(host), "Basic YWRhOnB3", 401, `Bearer`, `"unauthorized"`},
		"an invalid token":  {v.Require()(host), "Bearer nope", 401, `Bearer error="invalid_token", error_description="The token is not a JWT."`, `"unauthorized"`},
		"a missing scope":   {v.Require("invoices.read", "refunds.write")(host), "Bearer " + raw, 403, `Bearer error="insufficient_scope", scope="refunds.write"`, `"forbidden"`},
		"every scope held":  {v.Require("invoices.read")(host), "bearer " + raw, 200, "", "ada org-1"},
		"no scope required": {v.Require()(host), "Bearer " + raw, 200, "", "ada org-1"},
	} {
		w := serve(c.h, c.authorization)
		if w.Code != c.status || w.Header().Get("WWW-Authenticate") != c.challenge || !strings.Contains(w.Body.String(), c.body) {
			t.Errorf("%s: %d %q %s", name, w.Code, w.Header().Get("WWW-Authenticate"), w.Body)
		}
	}

	cold := i.verifier(t, verify.Config{})
	i.set(func(i *issuer) { i.down = true })
	if w := serve(cold.Require()(host), "Bearer "+raw); w.Code != 503 || !strings.Contains(w.Body.String(), `"unavailable"`) {
		t.Fatalf("issuer down: %d %s", w.Code, w.Body)
	}
	if _, ok := verify.ClaimsFrom(context.Background()); ok {
		t.Fatal("ClaimsFrom outside Require")
	}
}
