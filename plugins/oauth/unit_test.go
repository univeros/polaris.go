package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
)

const testBase = "https://auth.polaris.test"

// boot installs the plugin on a full test server.
func boot(t *testing.T, cfg Config) (*Plugin, *polaristest.Server) {
	t.Helper()
	p := New(cfg)
	srv := polaristest.New(t, polaristest.WithPlugins(p))
	return p, srv
}

func wantCode(t *testing.T, err error, code, message string) {
	t.Helper()
	var oe *Error
	if !errors.As(err, &oe) || oe.Code != code {
		t.Errorf("%s: want %s, got %v", message, code, err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// addUser inserts an active, verified user.
func addUser(t *testing.T, srv *polaristest.Server, email string) model.User {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	u := model.User{ID: repository.NewID(), Email: email, EmailVerifiedAt: &now, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	must(t, srv.Graph().Repos.Users.Insert(context.Background(), u))
	return u
}

func TestConfigIsValidatedWithTheFix(t *testing.T) {
	for name, cfg := range map[string]Config{
		"consent url":  {ConsentURL: "not a url"},
		"device query": {DeviceURL: "https://app.test/device?x=1"},
		"dpop mode":    {DPoP: "maybe"},
		"base url":     {BaseURL: "ftp://x"},
		"lifetime":     {AccessTokenTTL: 1500 * time.Millisecond},
		"poll":         {PollInterval: 1500 * time.Millisecond},
		"scope name":   {Scopes: map[string]string{"bad scope": "x"}},
	} {
		if _, err := cfg.resolve(); err == nil || !strings.Contains(err.Error(), "Config.") {
			t.Errorf("%s: want an error naming the field, got %v", name, err)
		}
	}
	s, err := Config{PollInterval: -1, ConsentURL: "https://app.test/consent/"}.resolve()
	must(t, err)
	if s.pollInterval != 0 || s.accessTTL != 3600 || s.refreshTTL != 2592000 || s.dpop != DPoPOptional || s.consentURL != "https://app.test/consent" || !s.clientIDMetadata {
		t.Errorf("defaults %+v", s)
	}
	if err := New(Config{DPoP: "maybe"}).Init(nil); err == nil {
		t.Error("Init reports the configuration problem")
	}
}

func TestThumbprintMatchesRFC7638AndTheHeaderIsReadWithoutVerifying(t *testing.T) {
	jwk := map[string]any{"kty": "RSA", "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw", "e": "AQAB", "alg": "RS256", "kid": "2011-04-29"}
	got, err := Thumbprint(jwk)
	must(t, err)
	if got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("thumbprint %s", got)
	}
	_, err = Thumbprint(map[string]any{"kty": "oct"})
	wantCode(t, err, CodeInvalidDPoPProof, "unsupported kty")
	_, err = Thumbprint(map[string]any{"kty": "EC", "crv": "P-256"})
	wantCode(t, err, CodeInvalidDPoPProof, "missing member")
	if JWTHeader("not.a") != nil || JWTHeader("a.b.c") != nil {
		t.Error("not a JWT")
	}

	p, srv := boot(t, Config{})
	minted, err := srv.Graph().Tokens.Mint(AccessTokenType, token.Claims{}.With("sub", "u1").With("jti", "j1").
		With("aud", []string{testBase, "https://api.test"}).With("scope", "org.read"), time.Now().Add(time.Hour))
	must(t, err)
	if JWTHeader(minted)["typ"] != AccessTokenType {
		t.Error("typ")
	}
	claims, err := p.tokens.verifyAccess(minted)
	must(t, err)
	if claims["sub"] != "u1" || claims["scope"] != "org.read" {
		t.Errorf("claims %v", claims)
	}
	idToken, err := srv.Graph().Tokens.Mint("", token.Claims{}.With("sub", "u1").With("jti", "j2").With("aud", "client-1"), time.Now().Add(time.Hour))
	must(t, err)
	_, err = p.tokens.verifyAccess(idToken)
	wantCode(t, err, CodeInvalidToken, "an ID token is not an access token")
	for _, foreign := range []string{minted, idToken} {
		if _, err := srv.Graph().Tokens.Parse(foreign); err == nil {
			t.Error("core's session parser refuses what the provider signs")
		}
	}
}

// proof signs a DPoP proof with key.
func proof(t *testing.T, key *ecdsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	pad := func(n *big.Int) string { b := make([]byte, 32); n.FillBytes(b); return b64(b) }
	if header == nil {
		header = map[string]any{"typ": dpopTyp, "alg": "ES256", "jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": pad(key.X), "y": pad(key.Y)}}
	}
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	must(t, err)
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + b64(sig)
}

func TestADPoPProofIsFreshBoundAndUsedOnce(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFrozen(time.Unix(1_800_000_000, 0))
	d := &dpop{once: &onceGuard{cache: cache.NewMemory(clk)}, clock: clk}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	now := clk.Now().Unix()
	url := testBase + "/oauth2/token"
	claims := func(jti, method, htu string, iat int64) map[string]any {
		return map[string]any{"jti": jti, "htm": method, "htu": htu, "iat": iat}
	}
	if jkt, err := d.verify(ctx, "", "POST", url, ""); jkt != "" || err != nil {
		t.Error("no proof")
	}
	jkt, err := d.verify(ctx, proof(t, key, nil, claims("j1", "POST", url+"?x=1", now)), "POST", url, "")
	must(t, err)
	if jkt == "" {
		t.Error("thumbprint")
	}
	cases := map[string]string{
		"replayed jti":    proof(t, key, nil, claims("j1", "POST", url, now)),
		"stale":           proof(t, key, nil, claims("j2", "POST", url, now-1000)),
		"future":          proof(t, key, nil, claims("j3", "POST", url, now+10)),
		"another method":  proof(t, key, nil, claims("j4", "GET", url, now)),
		"no jti":          proof(t, key, nil, claims("", "POST", url, now)),
		"garbage":         "garbage",
		"wrong typ":       proof(t, key, map[string]any{"typ": "JWT", "alg": "ES256"}, claims("j5", "POST", url, now)),
		"private key":     proof(t, key, map[string]any{"typ": dpopTyp, "alg": "ES256", "jwk": map[string]any{"kty": "EC", "d": "x"}}, claims("j6", "POST", url, now)),
		"unreadable key":  proof(t, key, map[string]any{"typ": dpopTyp, "alg": "ES256", "jwk": map[string]any{"kty": "EC"}}, claims("j7", "POST", url, now)),
		"tampered":        proof(t, key, nil, claims("j8", "POST", url, now)) + "A",
		"key alg differs": proof(t, key, map[string]any{"typ": dpopTyp, "alg": "ES256", "jwk": map[string]any{"kty": "EC", "crv": "P-256", "alg": "ES384"}}, claims("j9", "POST", url, now)),
	}
	for name, p := range cases {
		_, err := d.verify(ctx, p, "POST", url, "")
		wantCode(t, err, CodeInvalidDPoPProof, name)
	}
	bound := claims("j10", "POST", url, now)
	bound["ath"] = sha256b64("tok")
	_, err = d.verify(ctx, proof(t, key, nil, bound), "POST", url, "other")
	wantCode(t, err, CodeInvalidDPoPProof, "another token")
}

func TestMetadataURLsMustBePublicHTTPSWithAPath(t *testing.T) {
	for _, ok := range []string{"https://client.example.com/app", "https://client.example.com:443/app/client.json", "https://[2001:4860::8888]/a", "https://8.8.8.8/x"} {
		if err := assertPublicHTTPSURL(ok, "A client ID metadata URL"); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://client.example/app", "https://client.example", "https://localhost/app", "https://app.localhost/x", "https://10.1.2.3/app",
		"https://127.0.0.1/app", "https://[::1]/app", "https://[fd00::1]/app", "https://169.254.1.1/app", "https://192.168.0.5/app", "https://box.local/app",
		"https://svc.internal/app", "https://foo.home.arpa/app", "https://x.onion/app", "https://a.test/app", "https://client.example.com/app#frag",
		"https://client.example/app", "https://client.example.com:8443/app", "https://localhost./app", "https://2130706433/app", "https://0x7f.1/app",
		"https://user@client.example.com/app", "https://[::ffff:8.8.8.8]/a", "HTTPS://client.example.com/app", "https://100.64.0.1/x"} {
		wantCode(t, assertPublicHTTPSURL(bad, "jwks_uri"), CodeInvalidClientMetadata, bad)
	}
}

func TestScopesArePermissionsPlusTheOpenIDAndConfiguredOnes(t *testing.T) {
	p, _ := boot(t, Config{Scopes: map[string]string{"deploy": "Deploy"}})
	got, err := p.scopes.parse("openid org.read  deploy", nil)
	must(t, err)
	if strings.Join(got, ",") != "openid,org.read,deploy" {
		t.Errorf("parse %v", got)
	}
	if got, _ := p.scopes.parse("  ", nil); len(got) != 0 {
		t.Error("blank")
	}
	if strings.Join(p.Permissions([]string{"openid", "org.read", "deploy"}), ",") != "org.read" {
		t.Error("permissions")
	}
	_, err = p.scopes.parse("nothing", nil)
	wantCode(t, err, CodeInvalidScope, "unknown")
	_, err = p.scopes.parse("deploy", &Client{Scopes: []string{"org.read"}})
	wantCode(t, err, CodeInvalidScope, "not the client's")
	_, err = within([]string{"users.manage"}, []string{"org.read"})
	wantCode(t, err, CodeInvalidScope, "widening")
	if p.scopes.described([]string{"gone"})[0]["description"] != "gone" {
		t.Error("unknown descriptions fall back to the name")
	}
}

func TestDiscoveryFollowsTheSettings(t *testing.T) {
	p, _ := boot(t, Config{DynamicRegistration: true, DPoP: DPoPOff, DisableClientIDMetadata: true})
	doc := p.openIDConfiguration()
	for _, absent := range []string{"device_authorization_endpoint", "dpop_signing_alg_values_supported"} {
		if _, ok := doc[absent]; ok {
			t.Errorf("%s advertised", absent)
		}
	}
	if doc["registration_endpoint"] != testBase+"/oauth2/register" || doc["userinfo_endpoint"] != testBase+"/oauth2/userinfo" || doc["client_id_metadata_document_supported"] != false {
		t.Errorf("document %v", doc)
	}
	if p.Issuer() != testBase || p.BaseURL() != testBase {
		t.Error("base url defaults to the issuer")
	}
}

func TestTheCredentialsAreReadFromTheBodyOrBasic(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	cr := clientCredentials(r, map[string]any{"client_id": "c", "client_secret": "s"})
	if cr.clientID != "c" || cr.secret != "s" || cr.basic {
		t.Errorf("post %+v", cr)
	}
	r.Header.Set("Authorization", "Basic "+"YyUzQTE6cyUyRng=") // c%3A1:s%2Fx
	cr = clientCredentials(r, map[string]any{"client_id": "ignored"})
	if cr.clientID != "c:1" || cr.secret != "s/x" || !cr.basic {
		t.Errorf("basic %+v", cr)
	}
	for _, h := range []string{"Basic !!!", "Basic YWJj", "Bearer x"} {
		if _, _, ok := basicAuth(h); ok {
			t.Errorf("%s is not basic credentials", h)
		}
	}
}

func TestClientMetadataIsValidated(t *testing.T) {
	ctx := context.Background()
	p, _ := boot(t, Config{DPoP: DPoPOff})
	cases := map[string]ClientFields{
		"name":            {},
		"long name":       {"name": strings.Repeat("x", 161)},
		"type":            {"name": "x", "type": "other"},
		"grant list":      {"name": "x", "grant_types": "authorization_code"},
		"grant":           {"name": "x", "grant_types": []any{"implicit"}},
		"scopes list":     {"name": "x", "scopes": "org.read"},
		"scope":           {"name": "x", "scopes": []any{1}},
		"method":          {"name": "x", "token_endpoint_auth_method": "tls"},
		"jwks":            {"name": "x", "jwks": map[string]any{}},
		"jwks_uri":        {"name": "x", "jwks_uri": 5},
		"jwks_uri host":   {"name": "x", "jwks_uri": "https://10.0.0.1/keys"},
		"logo":            {"name": "x", "logo_uri": "http://example.com/logo"},
		"redirect":        {"name": "x", "redirect_uris": []any{"javascript://alert(1)"}},
		"redirect form":   {"name": "x", "redirect_uris": []any{"/relative"}},
		"redirect list":   {"name": "x", "redirect_uris": "https://x.example/cb"},
		"custom scheme":   {"name": "x", "redirect_uris": []any{"myapp://cb"}},
		"dpop flag":       {"name": "x", "dpop_bound_access_tokens": "yes"},
		"public secret":   {"name": "x", "type": "public", "token_endpoint_auth_method": "client_secret_basic"},
		"confidential":    {"name": "x", "token_endpoint_auth_method": "none"},
		"keyless":         {"name": "x", "token_endpoint_auth_method": "private_key_jwt"},
		"public client":   {"name": "x", "type": "public", "grant_types": []any{"client_credentials"}},
		"code redirect":   {"name": "x"},
		"dpop off":        {"name": "x", "grant_types": []any{"client_credentials"}, "dpop_bound_access_tokens": true},
		"ciba":            {"name": "x", "grant_types": []any{GrantCIBA}},
		"trusted boolean": {"name": "x", "grant_types": []any{"client_credentials"}, "trusted": "yes"},
	}
	for name, fields := range cases {
		_, err := p.clients.create(ctx, fields, "", "", name == "trusted boolean")
		wantCode(t, err, CodeInvalidClientMetadata, name)
	}
	issued, err := p.CreateClient(ctx, ClientFields{"name": "App", "redirect_uris": []any{"com.example.app://cb", "http://127.0.0.1:8080/cb"},
		"logo_uri": "https://app.example/logo.png", "scope": "org.read openid"}, "", "", true)
	must(t, err)
	if issued.Secret == "" || strings.Join(issued.Client.Scopes, " ") != "org.read openid" {
		t.Errorf("issued %+v", issued.Client)
	}
	if strings.Contains(issued.LogValue().String(), issued.Secret) {
		t.Error("the secret never reaches a log")
	}
	updated, changes, err := p.UpdateClient(ctx, issued.Client, ClientFields{"name": "App 2", "disabled": true, "logo_uri": nil}, false)
	must(t, err)
	if updated.Name != "App 2" || updated.DisabledAt == nil || updated.LogoURI != "" || strings.Join(changes, ",") != "disabled_at,logo_uri,name" {
		t.Errorf("updated %+v %v", updated, changes)
	}
	found, err := p.Client(ctx, issued.Client.ClientID)
	must(t, err)
	if found.Name != "App 2" {
		t.Error("the update was stored")
	}
	if _, err := p.Client(ctx, "nobody"); !errors.Is(err, ErrClientNotFound) {
		t.Errorf("unknown client: %v", err)
	}
	_, _, err = p.UpdateClient(ctx, Client{ClientID: "https://x.example/c"}, ClientFields{}, false)
	wantCode(t, err, CodeInvalidRequest, "a metadata client is not managed")
	if p.DeleteClient(ctx, Client{}) == nil {
		t.Error("a metadata client cannot be deleted")
	}
	must(t, p.DeleteClient(ctx, found))
}

func TestTheAuthenticationMethodsAreEnforced(t *testing.T) {
	ctx := context.Background()
	p, _ := boot(t, Config{})
	post, err := p.CreateClient(ctx, ClientFields{"name": "Post", "grant_types": []any{"client_credentials"}, "token_endpoint_auth_method": "client_secret_post"}, "", "", false)
	must(t, err)
	cases := map[string]credentials{
		"no client id":    {},
		"unknown":         {clientID: "nobody"},
		"basic for post":  {clientID: post.Client.ClientID, secret: post.Secret, basic: true},
		"no secret":       {clientID: post.Client.ClientID},
		"assertion type":  {assertion: "a.b.c", assertionType: "other"},
		"assertion shape": {assertion: "garbage", assertionType: AssertionType},
		"assertion iss":   {assertion: "a.b.c", assertionType: AssertionType, clientID: "x"},
	}
	for name, cr := range cases {
		_, err := p.clients.authenticate(ctx, cr, testBase+"/oauth2/token", testBase)
		wantCode(t, err, CodeInvalidClient, name)
	}
	c, err := p.clients.authenticate(ctx, credentials{clientID: post.Client.ClientID, secret: post.Secret}, "", "")
	must(t, err)
	if c.ClientID != post.Client.ClientID {
		t.Error("authenticated")
	}
	// An assertion naming a client that authenticates with a secret, or an unknown algorithm.
	header := b64([]byte(`{"alg":"HS256","kid":"k"}`))
	payload := b64([]byte(`{"iss":"` + post.Client.ClientID + `"}`))
	_, err = p.clients.authenticate(ctx, credentials{assertion: header + "." + payload + ".sig", assertionType: AssertionType}, "", "")
	wantCode(t, err, CodeInvalidClient, "not a keyed client")
}

func TestKeySetsComeInlineOrFromTheJWKSURI(t *testing.T) {
	ctx := context.Background()
	fake := &docs{status: http.StatusOK, body: `{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"k"}]}`}
	p, _ := boot(t, Config{HTTPClient: &http.Client{Transport: fake}})
	c := Client{ClientID: "c", JWKSURI: "https://keys.example.com/jwks.json"}
	for range 2 {
		keys, err := p.clients.keySet(ctx, c)
		must(t, err)
		if len(keys) != 1 {
			t.Errorf("keys %v", keys)
		}
	}
	if fake.calls != 1 {
		t.Errorf("the key set is cached: %d fetches", fake.calls)
	}
	_, err := p.clients.keySet(ctx, Client{JWKSURI: "https://10.0.0.1/jwks"})
	wantCode(t, err, CodeInvalidClientMetadata, "a private jwks_uri")
	fake.body = `{"nokeys":true}`
	_, err = p.clients.keySet(ctx, Client{JWKSURI: "https://keys.example.com/other.json"})
	wantCode(t, err, CodeInvalidClient, "not a key set")
	if keys := jwksKeys(map[string]any{"keys": map[string]any{"b": 2, "a": 1}}); len(keys) != 2 || keys[0] != 1 {
		t.Errorf("an object of keys reads in key order: %v", keys)
	}
	_, err = verifyWithKeySet("a.b.c", map[string]any{}, "RS256", nil, time.Now())
	if err == nil {
		t.Error("an empty key set")
	}
	_, err = verifyWithKeySet("a.b.c", map[string]any{}, "RS256", []any{map[string]any{}}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "kid") {
		t.Error("an assertion without kid")
	}
	_, err = verifyWithKeySet("a.b.c", map[string]any{"kid": "0"}, "RS256", []any{map[string]any{"alg": "ES256"}}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "algorithm") {
		t.Errorf("a key for another algorithm: %v", err)
	}
	_, err = verifyWithKeySet("a.b.c", map[string]any{"kid": "z"}, "RS256", []any{map[string]any{"kid": "k"}}, time.Now())
	if err == nil {
		t.Error("an unknown kid")
	}
}

// docs answers every fetch with one document.
type docs struct {
	status int
	body   string
	calls  int
}

func (d *docs) RoundTrip(r *http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{StatusCode: d.status, Body: io.NopCloser(strings.NewReader(d.body)), Header: http.Header{}, Request: r}, nil
}

func TestFetchIsBoundedAndJSONOnly(t *testing.T) {
	ctx := context.Background()
	log := polaristest.New(t).Graph().Logger
	for name, d := range map[string]*docs{
		"status":     {status: 404, body: `{}`},
		"too large":  {status: 200, body: `{"x":"` + strings.Repeat("a", maxDocumentBytes) + `"}`},
		"not json":   {status: 200, body: `nope`},
		"not object": {status: 200, body: `"string"`},
	} {
		_, err := fetchJSON(ctx, noRedirects(&http.Client{Transport: d}), log, "https://x.example.com/doc", CodeInvalidClientMetadata)
		wantCode(t, err, CodeInvalidClientMetadata, name)
	}
	doc, err := fetchJSON(ctx, noRedirects(&http.Client{Transport: &docs{status: 200, body: `[1]`}}), log, "https://x.example.com/doc", CodeInvalidClient)
	must(t, err)
	if len(doc) != 0 {
		t.Error("a list reads as an empty object")
	}
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer local.Close()
	_, err = fetchJSON(ctx, noRedirects(nil), log, local.URL+"/doc", CodeInvalidClientMetadata)
	wantCode(t, err, CodeInvalidClientMetadata, "the default client refuses a loopback address")
	redirecting := httptest.NewServer(http.RedirectHandler("https://example.com/", http.StatusFound))
	defer redirecting.Close()
	_, err = fetchJSON(ctx, noRedirects(redirecting.Client()), log, redirecting.URL+"/doc", CodeInvalidClientMetadata)
	wantCode(t, err, CodeInvalidClientMetadata, "a redirect is never followed")
}

func TestCodesTokensDevicesAndBackchannelRequestsExpireAndSpendOnce(t *testing.T) {
	ctx := context.Background()
	p, srv := boot(t, Config{DeviceURL: "https://app.test/device", PollInterval: 5 * time.Second})
	clk := clock.NewFrozen(time.Now().UTC().Truncate(time.Second))
	user := addUser(t, srv, "ada@example.com")
	issued, err := p.CreateClient(ctx, ClientFields{"name": "TV", "redirect_uris": []any{"https://tv.example/cb"},
		"grant_types": []any{GrantAuthorizationCode, GrantRefreshToken, GrantDeviceCode, GrantCIBA}}, "", "", true)
	must(t, err)
	c := issued.Client

	codes := &codes{db: srv.DB, pepper: srv.Graph().Pepper, ttl: time.Minute, clock: clk}
	verifier := strings.Repeat("v", 43)
	req := pendingRequest{Scopes: []string{"org.read"}, RedirectURI: "https://tv.example/cb", CodeChallenge: sha256b64(verifier)}
	value, err := codes.issue(ctx, c, user.ID, "", req, nil)
	must(t, err)
	_, err = codes.consume(ctx, value, Client{ClientID: "other"}, "", verifier)
	wantCode(t, err, CodeInvalidGrant, "another client")
	_, err = codes.consume(ctx, value, c, "https://tv.example/other", verifier)
	wantCode(t, err, CodeInvalidGrant, "another redirect")
	_, err = codes.consume(ctx, "unknown", c, "", verifier)
	wantCode(t, err, CodeInvalidGrant, "unknown code")
	stored, err := codes.consume(ctx, value, c, "", verifier)
	must(t, err)
	_, err = codes.consume(ctx, value, c, "", verifier)
	var reused codeReused
	if !errors.As(err, &reused) || reused.codeID != stored.ID || reused.Error() == "" {
		t.Errorf("the replay names the code: %v", err)
	}
	expired, err := codes.issue(ctx, c, user.ID, "", req, nil)
	must(t, err)
	clk.Advance(2 * time.Minute)
	_, err = codes.consume(ctx, expired, c, "", verifier)
	wantCode(t, err, CodeInvalidGrant, "expired code")

	// Tokens: refresh rotates within the family, an expired refresh token is refused.
	resp, err := p.IssueTokens(ctx, c, Grant{UserID: user.ID, Scopes: []string{"org.read"}})
	must(t, err)
	if strings.Contains(resp.LogValue().String(), resp.AccessToken) {
		t.Error("tokens never reach a log")
	}
	_, err = p.tokens.refresh(ctx, "prt_unknown", c, "", nil)
	wantCode(t, err, CodeInvalidGrant, "unknown refresh token")
	_, err = p.tokens.refresh(ctx, resp.RefreshToken, Client{ClientID: "other"}, "", nil)
	wantCode(t, err, CodeInvalidGrant, "another client's refresh token")
	refreshed, err := p.tokens.refresh(ctx, resp.RefreshToken, c, "", []string{"org.read"})
	must(t, err)
	family := func(raw string) string {
		r, err := p.tokens.lookup(ctx, raw)
		must(t, err)
		return r.FamilyID
	}
	if family(refreshed.AccessToken) != family(resp.AccessToken) {
		t.Error("the family continues")
	}
	if n, err := p.RevokeClientTokens(ctx, c.ClientID); err != nil || n != 3 {
		t.Errorf("revoke client tokens: %d %v", n, err)
	}
	out, err := p.tokens.introspect(ctx, refreshed.AccessToken)
	must(t, err)
	if out["active"] != false {
		t.Error("a revoked token is inactive")
	}
	if r, err := p.tokens.revoke(ctx, "garbage", c); r != nil || err != nil {
		t.Error("an unknown token is not an error")
	}

	// Device codes: pending, slowed down, decided once, spent once.
	dev := &devices{poller: poller{db: srv.DB, table: TableDeviceCodes, interval: 5, clock: clk, what: "device code"},
		pepper: srv.Graph().Pepper, deviceURL: "https://app.test/device", ttl: 600}
	started, err := dev.start(ctx, c, []string{"org.read"}, "")
	must(t, err)
	_, err = dev.pollCode(ctx, started.DeviceCode, c)
	wantCode(t, err, CodeAuthorizationPending, "pending")
	_, err = dev.pollCode(ctx, started.DeviceCode, c)
	wantCode(t, err, CodeSlowDown, "too soon")
	device, err := dev.byUserCode(ctx, strings.ToLower(started.UserCode))
	must(t, err)
	must(t, dev.decide(ctx, device, true, user.ID, "", nil))
	wantCode(t, dev.decide(ctx, device, false, user.ID, "", nil), CodeInvalidGrant, "decided once")
	clk.Advance(10 * time.Second)
	spent, err := dev.pollCode(ctx, started.DeviceCode, c)
	must(t, err)
	if spent.UserID != user.ID || spent.Status != statusUsed {
		t.Errorf("spent %+v", spent)
	}
	clk.Advance(10 * time.Second)
	_, err = dev.pollCode(ctx, started.DeviceCode, c)
	wantCode(t, err, CodeInvalidGrant, "spent once")
	_, err = dev.byUserCode(ctx, "BCDF")
	wantCode(t, err, CodeInvalidGrant, "short user code")
	_, err = (&devices{deviceURL: ""}).start(ctx, c, nil, "")
	wantCode(t, err, CodeUnauthorizedClient, "no device page")
	clk.Advance(time.Hour)
	_, err = dev.pollCode(ctx, started.DeviceCode, c)
	wantCode(t, err, CodeExpiredToken, "expired device code")

	// Backchannel: the hint is normalised; decided by the user it names.
	backchannel := &ciba{poller: poller{db: srv.DB, table: TableCIBARequests, interval: 0, clock: clk, what: "request"}, repos: srv.Graph().Repos, ttl: 600}
	_, _, err = backchannel.request(ctx, c, nil, "", "", "")
	wantCode(t, err, CodeInvalidRequest, "a hint is required")
	_, _, err = backchannel.request(ctx, c, nil, "ada@example.com", "<script>\n", "")
	wantCode(t, err, CodeInvalidRequest, "plain text binding message")
	_, _, err = backchannel.request(ctx, Client{}, nil, "ada@example.com", "", "")
	wantCode(t, err, CodeUnauthorizedClient, "no ciba grant")
	_, asked, err := backchannel.request(ctx, c, []string{"org.read"}, "  ADA@example.com ", "Deploy?", "")
	must(t, err)
	if asked.UserID != user.ID {
		t.Error("the hint is normalised")
	}
	_, err = backchannel.decide(ctx, asked.ID, "someone-else", true, "", nil)
	wantCode(t, err, CodeNotFound, "another user's request")
	denied, err := backchannel.decide(ctx, asked.ID, user.ID, false, "", nil)
	must(t, err)
	if denied.Status != statusDenied {
		t.Error("denied")
	}
	_, err = backchannel.decide(ctx, asked.ID, user.ID, true, "", nil)
	wantCode(t, err, CodeInvalidGrant, "decided once")
	_, err = backchannel.pollRequest(ctx, asked.ID, c)
	wantCode(t, err, CodeAccessDenied, "refused")
	_, err = backchannel.pollRequest(ctx, "not-a-uuid", c)
	wantCode(t, err, CodeInvalidGrant, "unknown request")
	clk.Advance(time.Hour)
	_, err = backchannel.decide(ctx, asked.ID, user.ID, true, "", nil)
	wantCode(t, err, CodeNotFound, "expired request")
	if pending, err := backchannel.pending(ctx, user.ID); err != nil || len(pending) != 0 {
		t.Error("nothing pending")
	}

	// Prune drops what expired (the plugin's own clock is the real one: nothing has).
	counts, err := p.Prune(ctx)
	must(t, err)
	if len(counts) != 4 {
		t.Errorf("prune %v", counts)
	}
}

func TestTheGoAPIIssuesExchangesAndVerifies(t *testing.T) {
	ctx := context.Background()
	p, srv := boot(t, Config{})
	user := addUser(t, srv, "ada@example.com")
	issued, err := p.CreateClient(ctx, ClientFields{"name": "Agent", "grant_types": []any{GrantTokenExchange, GrantClientCredentials}}, "", "", false)
	must(t, err)
	c := issued.Client
	resp, err := p.IssueTokens(ctx, c, Grant{UserID: user.ID, Scopes: []string{"openid", "profile", "org.read"}, Nonce: "n"})
	must(t, err)
	if resp.RefreshToken != "" || resp.IDToken == "" {
		t.Errorf("no refresh without the grant, an ID token with openid: %+v", resp)
	}
	_, err = p.Exchange(ctx, Client{}, ExchangeRequest{})
	wantCode(t, err, CodeUnauthorizedClient, "no exchange grant")
	for name, req := range map[string]ExchangeRequest{
		"no subject":  {SubjectTokenType: TokenTypeAccessToken},
		"bad type":    {SubjectToken: resp.AccessToken, SubjectTokenType: "x"},
		"resource":    {SubjectToken: resp.AccessToken, SubjectTokenType: TokenTypeJWT, Resource: "ftp://x"},
		"actor type":  {SubjectToken: resp.AccessToken, SubjectTokenType: TokenTypeJWT, ActorToken: resp.AccessToken},
		"bad subject": {SubjectToken: "garbage", SubjectTokenType: TokenTypeJWT},
	} {
		if _, err := p.Exchange(ctx, c, req); err == nil {
			t.Errorf("%s: refused", name)
		}
	}
	exchanged, err := p.Exchange(ctx, c, ExchangeRequest{SubjectToken: resp.AccessToken, SubjectTokenType: TokenTypeAccessToken,
		ActorToken: resp.AccessToken, ActorTokenType: TokenTypeAccessToken, Scopes: []string{"org.read"}})
	must(t, err)
	introspected, err := p.tokens.introspect(ctx, exchanged.AccessToken)
	must(t, err)
	if introspected["act"].(map[string]any)["sub"] != user.ID || introspected["scope"] != "org.read" {
		t.Errorf("the actor token's subject acts: %v", introspected)
	}

	r := httptest.NewRequest(http.MethodGet, testBase+"/orgs", nil)
	if jkt, err := p.VerifyDPoP(r, ""); jkt != "" || err != nil {
		t.Error("no proof")
	}
	r.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	principal, err := p.ResolveBearer(r)
	must(t, err)
	if principal.Subject() != user.ID || principal.Claim("auth_time") != nil || !hasAMR(principal) {
		t.Errorf("principal %v", principal.Claims())
	}
	if perms, ok := principal.Delegation(); !ok || strings.Join(perms, ",") != "org.read" {
		t.Errorf("delegated %v", perms)
	}
	r.Header.Set("Authorization", "DPoP "+resp.AccessToken)
	if _, err := p.ResolveBearer(r); err == nil {
		t.Error("a bearer token with the DPoP scheme")
	}
	r.Header.Set("Authorization", "Bearer not-a-jwt")
	if tok, err := p.ResolveBearer(r); tok != nil || err != nil {
		t.Error("not ours")
	}
	must(t, srv.Graph().Repos.Users.Update(ctx, user, func() model.User { u := user; u.Status = model.UserStatusDisabled; return u }()))
	r.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	if _, err := p.ResolveBearer(r); err == nil {
		t.Error("a disabled user's token")
	}
}

func TestErasedUsersAndOrganizationsLeaveNothing(t *testing.T) {
	ctx := context.Background()
	p, srv := boot(t, Config{})
	user := addUser(t, srv, "ada@example.com")
	issued, err := p.CreateClient(ctx, ClientFields{"name": "Org app", "grant_types": []any{GrantClientCredentials}}, "org-1", user.ID, false)
	must(t, err)
	_, err = p.IssueTokens(ctx, issued.Client, Grant{UserID: user.ID})
	must(t, err)
	must(t, p.consents.grant(ctx, user.ID, issued.Client.ClientID, "", []string{"org.read"}))
	listener := p.Listeners(nil)[0]
	listener(ctx, event.UserDeleted{UserID: user.ID})
	listener(ctx, event.OrganizationDeleted{OrganizationID: "org-1"})
	for _, table := range []string{TableConsents, TableTokens, TableClients} {
		if n, err := srv.DB.Count(ctx, table, store.Criteria{}); err != nil || n != 0 {
			t.Errorf("%s: %d rows left", table, n)
		}
	}
	if len(AuditCatalog()) != 13 || (Event{Name: EventTokenIssued}).EventName() != EventTokenIssued {
		t.Error("audit names")
	}
	if (&Error{Code: CodeInvalidGrant, Description: "x"}).Error() != "oauth: invalid_grant: x" {
		t.Error("error text")
	}
}

func TestTheDefaultOperatorsAreTheSuperadmins(t *testing.T) {
	ctx := context.Background()
	p, srv := boot(t, Config{})
	user := addUser(t, srv, "root@example.com")
	session, err := srv.Graph().Tokens.Issue(token.Claims{}.With("sub", user.ID).With("jti", "j"))
	must(t, err)
	r := httptest.NewRequest(http.MethodGet, "/admin/oauth/clients", nil)
	if _, refused := p.operator(ctx, r, false, ""); refused == nil || refused.Status != http.StatusUnauthorized {
		t.Error("no bearer")
	}
	r.Header.Set("Authorization", "Bearer "+session)
	if _, refused := p.operator(ctx, r, false, ""); refused == nil || refused.Status != http.StatusUnauthorized {
		t.Error("not a superadmin")
	}
	impersonating, err := srv.Graph().Tokens.Issue(token.Claims{}.With("sub", user.ID).With("jti", "j2").With(impersonationClaim, "x"))
	must(t, err)
	r.Header.Set("Authorization", "Bearer "+impersonating)
	if _, refused := p.operator(ctx, r, false, ""); refused == nil || refused.Status != http.StatusForbidden {
		t.Error("impersonation")
	}
	p.settings.operators = func(*http.Request) (*Operator, error) {
		return &Operator{ID: "k", APIKey: true, Role: "viewer", Scope: "org-1"}, nil
	}
	if _, refused := p.operator(ctx, r, true, "org-1"); refused == nil || refused.Status != http.StatusForbidden {
		t.Error("a viewer does not own")
	}
	op, refused := p.operator(ctx, r, false, "org-1")
	if refused != nil || op.actor != "" || op.id != "k" {
		t.Error("an API key reads its organization, acting as nobody, recorded as its id")
	}
	if _, refused := p.operator(ctx, r, false, "org-2"); refused == nil {
		t.Error("outside its scope")
	}
}
