package oauth_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
)

// The environment of upstream's OAuthTestCase.
const (
	phpFlow     = `Polaris\OAuth\Tests\Functional\OAuthFlowTest`
	phpRegister = `Polaris\OAuth\Tests\Functional\OAuthRegistrationTest`
	password    = "correct horse battery staple"
	base        = "https://auth.polaris.test"
	consentURL  = "https://app.polaris.test/consent"
	deviceURL   = "https://app.polaris.test/device"
	redirectURI = "https://cli.polaris.test/callback"
	tokenURL    = base + "/oauth2/token"
)

// fakeHTTP answers the published documents by URL (404 otherwise) and records every fetch.
type fakeHTTP struct {
	mu        sync.Mutex
	documents map[string]any
	fetched   []string
}

func (f *fakeHTTP) publish(u string, doc any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.documents[u] = doc
}

func (f *fakeHTTP) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u := r.URL.String()
	f.fetched = append(f.fetched, u)
	status, doc := http.StatusOK, f.documents[u]
	if doc == nil {
		status, doc = http.StatusNotFound, map[string]any{"error": "not_found"}
	}
	body, _ := json.Marshal(doc)
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(body)), Request: r}, nil
}

func (f *fakeHTTP) fetches(u string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.fetched {
		if v == u {
			n++
		}
	}
	return n
}

// oauthCase is one ported test: a booted server with the oauth plugin and a client replaying the
// test's fixture.
type oauthCase struct {
	t    *testing.T
	srv  *polaristest.Server
	c    *contracttest.Client
	http *fakeHTTP
	keys *clientKeys
	ctx  context.Context
}

func testConfig(fake *fakeHTTP, dynamicRegistration bool) oauth.Config {
	return oauth.Config{
		BaseURL: base, ConsentURL: consentURL, DeviceURL: deviceURL,
		HTTPClient:          &http.Client{Transport: fake},
		DynamicRegistration: dynamicRegistration,
		PollInterval:        -1,
		Scopes:              map[string]string{"deploy": "Deploy the application"},
	}
}

// run runs each test of a PHP class with its own server and fixture.
func run(t *testing.T, phpClass string, dynamicRegistration bool, tests map[string]func(*oauthCase)) {
	t.Helper()
	dir := contracttest.UpstreamFixtures(t, "oauth-provider")
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			fake := &fakeHTTP{documents: map[string]any{}}
			srv := boot(t, fake, dynamicRegistration)
			fx := contracttest.For(t, dir, phpClass, name)
			test(&oauthCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), fx), http: fake,
				keys: newClientKeys(t), ctx: context.Background()})
		})
	}
}

func (o *oauthCase) json(resp *http.Response) map[string]any { return contracttest.JSON(o.t, resp) }

func (o *oauthCase) data(resp *http.Response) map[string]any {
	m, _ := o.json(resp)["data"].(map[string]any)
	return m
}

// login registers, verifies and logs the user in; their id and access token.
func (o *oauthCase) login(email string) (string, string) {
	o.t.Helper()
	o.c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var registered event.UserRegistered
	for _, e := range o.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			registered = r
		}
	}
	o.c.Post("/auth/email/verify", map[string]any{"token": registered.VerificationToken})
	access, _ := o.data(o.c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return registered.UserID, access
}

// organization creates an organization and switches the session to it.
func (o *oauthCase) organization(access, name string) (string, string) {
	o.t.Helper()
	orgID, _ := o.data(o.c.Post("/orgs", map[string]any{"name": name}, contracttest.Bearer(access)))["id"].(string)
	switched := o.c.Post("/auth/switch-org", map[string]any{"organization_id": orgID}, contracttest.Bearer(access))
	if switched.StatusCode != 200 {
		o.t.Fatalf("switch-org: %d", switched.StatusCode)
	}
	token, _ := o.data(switched)["access_token"].(string)
	return orgID, token
}

// client registers a client for the organization.
func (o *oauthCase) client(access, orgID string, fields map[string]any) map[string]any {
	o.t.Helper()
	body := map[string]any{"name": "Acme CLI", "redirect_uris": []string{redirectURI}}
	for k, v := range fields {
		body[k] = v
	}
	created := o.c.Post("/orgs/"+orgID+"/oauth/clients", body, contracttest.Bearer(access))
	if created.StatusCode != 201 {
		o.t.Fatalf("create client: %d %v", created.StatusCode, o.json(created))
	}
	return o.data(created)
}

// grantOwner gives the user the admin role owner on the instance (upstream Grants::grant).
func (o *oauthCase) grantOwner(userID string) {
	o.t.Helper()
	_, err := admin.Of(o.srv.Graph()).Grants().Grant(o.ctx, admin.Grant{UserID: userID, Role: admin.RoleOwner})
	o.must(err)
}

// boot installs the plugins upstream's OAuthTestCase does: audit, admin, then oauth.
func boot(t *testing.T, fake *fakeHTTP, dynamicRegistration bool) *polaristest.Server {
	return polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}),
		oauth.New(testConfig(fake, dynamicRegistration))))
}

func (o *oauthCase) must(err error) {
	o.t.Helper()
	if err != nil {
		o.t.Fatal(err)
	}
}

// form posts fields form-encoded to the absolute URL of path, as RFC 6749 clients send.
func (o *oauthCase) form(path string, fields map[string]string, opts ...contracttest.Option) *http.Response {
	values := url.Values{}
	for k, v := range fields {
		values.Set(k, v)
	}
	return o.c.Form(base+path, values, opts...)
}

// authorize is GET /oauth2/authorize, as an XHR client when json.
func (o *oauthCase) authorize(query map[string]string, json bool) *http.Response {
	values := url.Values{}
	for k, v := range query {
		values.Set(k, v)
	}
	var opts []contracttest.Option
	if json {
		opts = append(opts, contracttest.Header("Accept", "application/json"))
	}
	return o.c.Get(base+"/oauth2/authorize?"+values.Encode(), opts...)
}

// problem asserts an oauth problem document and returns it.
func (o *oauthCase) problem(resp *http.Response, status int, code, message string) map[string]any {
	o.t.Helper()
	body := o.json(resp)
	if resp.StatusCode != status || body["error"] != code || resp.Header.Get("Content-Type") != "application/problem+json" ||
		body["type"] != "https://polaris.univeros.io/problems/oauth/"+code {
		o.t.Errorf("%s: want %d %s, got %d %v", message, status, code, resp.StatusCode, body)
	}
	return body
}

func (o *oauthCase) status(resp *http.Response, want int, message string) {
	o.t.Helper()
	if resp.StatusCode != want {
		o.t.Errorf("%s: want %d, got %d %v", message, want, resp.StatusCode, o.json(resp))
	}
}

func (o *oauthCase) equal(got, want any, message string) {
	o.t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if !bytes.Equal(g, w) {
		o.t.Errorf("%s: got %s, want %s", message, g, w)
	}
}

func basic(id, secret string) contracttest.Option {
	return contracttest.Header("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(id+":"+secret)))
}

func dpopHeader(proof string) contracttest.Option { return contracttest.Header("DPoP", proof) }

// claims decodes a JWT's payload, unverified.
func claims(jwt string) map[string]any {
	parts := bytes.Split([]byte(jwt), []byte("."))
	if len(parts) != 3 {
		return map[string]any{}
	}
	raw, _ := base64.RawURLEncoding.DecodeString(string(parts[1]))
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}

// param is a query parameter of a URL.
func param(u, name string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return parsed.Query().Get(name)
}

func str(v any) string { s, _ := v.(string); return s }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pkce is a verifier and its S256 challenge.
func pkce() (string, string) {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	verifier := b64(buf)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, b64(sum[:])
}

// clientKeys is what a client holds in the tests: a P-256 key for DPoP proofs and an RSA key for
// private_key_jwt assertions.
type clientKeys struct {
	t   *testing.T
	ec  *ecdsa.PrivateKey
	rsa *rsa.PrivateKey
}

func newClientKeys(t *testing.T) *clientKeys {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return &clientKeys{t: t, ec: ec, rsa: r}
}

func (k *clientKeys) dpopJWK() map[string]any {
	pad := func(n *big.Int) string { b := make([]byte, 32); n.FillBytes(b); return b64(b) }
	return map[string]any{"kty": "EC", "crv": "P-256", "x": pad(k.ec.X), "y": pad(k.ec.Y)}
}

func (k *clientKeys) thumbprint() string {
	tp, err := oauth.Thumbprint(k.dpopJWK())
	if err != nil {
		k.t.Fatal(err)
	}
	return tp
}

// dpopProof is a proof for method and url, bound to accessToken when given.
func (k *clientKeys) dpopProof(method, u, accessToken string) string {
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	c := map[string]any{"jti": b64(jti), "htm": method, "htu": u, "iat": time.Now().Unix()}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		c["ath"] = b64(sum[:])
	}
	return k.sign(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": k.dpopJWK()}, c)
}

func (k *clientKeys) clientJWKS() map[string]any {
	e := big.NewInt(int64(k.rsa.E)).Bytes()
	return map[string]any{"keys": []any{map[string]any{
		"kty": "RSA", "kid": "client-1", "use": "sig", "alg": "RS256", "n": b64(k.rsa.N.Bytes()), "e": b64(e),
	}}}
}

// clientAssertion is a private_key_jwt assertion for clientID naming audience.
func (k *clientKeys) clientAssertion(clientID, audience string) string {
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	now := time.Now().Unix()
	return k.sign(map[string]any{"typ": "JWT", "alg": "RS256", "kid": "client-1"},
		map[string]any{"iss": clientID, "sub": clientID, "aud": audience, "jti": b64(jti), "iat": now, "exp": now + 300})
}

func (k *clientKeys) sign(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	input := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(input))
	var sig []byte
	switch header["alg"] {
	case "ES256":
		r, s, err := ecdsa.Sign(rand.Reader, k.ec, sum[:])
		if err != nil {
			k.t.Fatal(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	default:
		var err error
		if sig, err = rsa.SignPKCS1v15(rand.Reader, k.rsa, crypto.SHA256, sum[:]); err != nil {
			k.t.Fatal(err)
		}
	}
	return input + "." + b64(sig)
}
