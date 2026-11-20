package social

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// The recorded providers of upstream's tests/Support (exported to the external tests).
const (
	RecordedKID        = "test-2026"
	GoogleSub          = "110169484474386276334"
	appleSub           = "001234.abcdef1234567890abcdef1234567890.1234"
	microsoftSub       = "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHza9xbEXZk"
	microsoftIssuer    = "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
	RecordedRedirect   = "https://app.polaris.test/signed-in"
	googleUserinfo     = "https://openidconnect.googleapis.com/v1/userinfo"
	recordedGoogleSite = "https://accounts.google.com"
)

// Recorded answers the recorded provider bodies by URL (query ignored, 404 otherwise), minting
// id_tokens under the test key for the nonce last read from an authorization URL, with Claims[id]
// merged over the minted claims.
type Recorded struct {
	t        testing.TB
	mu       sync.Mutex
	routes   map[string]func(*http.Request) (int, any)
	nonce    string
	key      *rsa.PrivateKey
	requests []recordedRequest
	Claims   map[string]map[string]any
}

type recordedRequest struct {
	URL  string
	Form url.Values
	Auth string
}

// NewRecorded loads testdata/*.json and the test keys.
func NewRecorded(t testing.TB) *Recorded {
	t.Helper()
	block, _ := pem.Decode(readTestdata(t, "idp-rsa.pem"))
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	r := &Recorded{t: t, routes: map[string]func(*http.Request) (int, any){}, key: k.(*rsa.PrivateKey), Claims: map[string]map[string]any{}}
	var jwks any
	if err := json.Unmarshal(readTestdata(t, "jwks.json"), &jwks); err != nil {
		t.Fatal(err)
	}
	minters := map[string]func() string{
		"google": func() string {
			return r.MintFor("google", recordedGoogleSite, "google-client", GoogleSub, "ada@example.com", true, "Ada Lovelace")
		},
		"apple": func() string {
			return r.MintFor("apple", "https://appleid.apple.com", "com.example.app", appleSub, "alan@example.com", true, "")
		},
		"microsoft": func() string {
			return r.MintFor("microsoft", microsoftIssuer, "ms-client", microsoftSub, "linus@example.com", true, "Linus Torvalds")
		},
	}
	for _, name := range []string{"google", "github", "apple", "microsoft"} {
		var recorded map[string]any
		if err := json.Unmarshal(readTestdata(t, name+".json"), &recorded); err != nil {
			t.Fatal(err)
		}
		for u, body := range recorded {
			switch {
			case body == "<jwks>":
				r.On(u, jwks)
			case at(body, "id_token") == "<minted>":
				doc, mint := body.(map[string]any), minters[name]
				r.routes[u] = func(*http.Request) (int, any) {
					minted := map[string]any{}
					for k, v := range doc {
						minted[k] = v
					}
					minted["id_token"] = mint()
					return http.StatusOK, minted
				}
			default:
				r.On(u, body)
			}
		}
	}
	r.On("https://acme.example/oauth/token", map[string]any{"access_token": "acme-access", "token_type": "Bearer", "expires_in": 7200, "refresh_token": "acme-refresh", "scope": "profile"})
	r.On("https://acme.example/oauth/me", map[string]any{"id": "acme-42", "email": "eve@example.com", "verified": true, "name": "Eve"})
	r.On("https://acme.okta.example/.well-known/openid-configuration", map[string]any{"issuer": "https://acme.okta.example",
		"authorization_endpoint": "https://acme.okta.example/oauth2/v1/authorize", "token_endpoint": "https://acme.okta.example/oauth2/v1/token",
		"userinfo_endpoint": "https://acme.okta.example/oauth2/v1/userinfo", "jwks_uri": "https://acme.okta.example/oauth2/v1/keys"})
	r.On("https://acme.okta.example/oauth2/v1/keys", jwks)
	r.routes["https://acme.okta.example/oauth2/v1/token"] = func(*http.Request) (int, any) {
		return http.StatusOK, map[string]any{"access_token": "okta-access", "token_type": "Bearer", "expires_in": 3600,
			"id_token": r.MintFor("okta", "https://acme.okta.example", "okta-client", "okta-7", "frank@example.com", true, "Frank")}
	}
	r.On("https://acme.okta.example/oauth2/v1/userinfo", map[string]any{"sub": "okta-7", "email": "frank@example.com", "email_verified": true, "name": "Frank"})
	return r
}

// On answers body (200) for u; a later call replaces the answer.
func (r *Recorded) On(u string, body any) { r.Answer(u, http.StatusOK, body) }

// Answer answers status and body for u.
func (r *Recorded) Answer(u string, status int, body any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routes[u] = func(*http.Request) (int, any) { return status, body }
}

// SetNonce is the nonce the next minted id_token carries ("" for none).
func (r *Recorded) SetNonce(nonce string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nonce = nonce
}

// Requests are the URLs fetched so far, oldest first.
func (r *Recorded) requested() []recordedRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recordedRequest(nil), r.requests...)
}

// RoundTrip implements http.RoundTripper.
func (r *Recorded) RoundTrip(req *http.Request) (*http.Response, error) {
	var form url.Values
	if req.Body != nil {
		raw, _ := io.ReadAll(req.Body)
		form, _ = url.ParseQuery(string(raw))
	}
	r.mu.Lock()
	route, ok := r.routes[strings.SplitN(req.URL.String(), "?", 2)[0]]
	r.requests = append(r.requests, recordedRequest{URL: req.URL.String(), Form: form, Auth: req.Header.Get("Authorization")})
	r.mu.Unlock()
	status, body := http.StatusNotFound, any("")
	if ok {
		status, body = route(req)
	}
	raw, _ := json.Marshal(body)
	if s, isString := body.(string); isString {
		raw = []byte(s)
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw)), Request: req}, nil
}

// Mint signs an id_token with the test key: the standard claims and the nonce last read.
func (r *Recorded) Mint(issuer, audience, subject, email string, verified bool, name string) string {
	return r.MintFor("", issuer, audience, subject, email, verified, name)
}

// MintFor is Mint with Claims[provider] merged over.
func (r *Recorded) MintFor(provider, issuer, audience, subject, email string, verified bool, name string) string {
	r.mu.Lock()
	nonce, extra := r.nonce, r.Claims[provider]
	r.mu.Unlock()
	now := time.Now().Unix()
	claims := map[string]any{"iss": issuer, "aud": audience, "sub": subject, "iat": now, "exp": now + 3600}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if email != "" {
		claims["email"], claims["email_verified"] = email, verified
	}
	if name != "" {
		claims["name"] = name
	}
	for k, v := range extra {
		claims[k] = v
	}
	return SignRS256(r.t, r.key, RecordedKID, claims)
}

// SignRS256 signs claims as a compact JWS under kid.
func SignRS256(t testing.TB, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, _ := signed.CompactSerialize()
	return compact
}

func readTestdata(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// AcmeDefinition is the definition a host passes for its own OAuth 2 server.
func AcmeDefinition() *Definition {
	return &Definition{Name: "Acme", AuthorizationURL: "https://acme.example/oauth/authorize", TokenURL: "https://acme.example/oauth/token",
		UserinfoURL: "https://acme.example/oauth/me", Scopes: []string{"profile"}, NoPKCE: true,
		Profile: func(d map[string]any) Profile {
			return Profile{Subject: str(d["id"]), Email: text(d["email"]), EmailVerified: d["verified"] == true, Name: text(d["name"])}
		}}
}

// RecordedConfig is upstream's SocialTestCase configuration on base.
func RecordedConfig(t testing.TB, base string, r *Recorded) Config {
	return Config{
		BaseURL: base,
		Providers: map[string]Provider{
			"google":    {ClientID: "google-client", ClientSecret: "google-secret"},
			"github":    {ClientID: "github-client", ClientSecret: "github-secret"},
			"apple":     {ClientID: "com.example.app", TeamID: "TEAM123", KeyID: "KEY123", PrivateKey: string(readTestdata(t, "apple-client.pem"))},
			"microsoft": {ClientID: "ms-client", ClientSecret: "ms-secret", Tenant: "common"},
			"acme":      {ClientID: "acme-client", ClientSecret: "acme-secret", Definition: AcmeDefinition()},
		},
		HTTPClient:           &http.Client{Transport: r},
		RedirectURIs:         []string{RecordedRedirect},
		AllowDifferentEmails: []string{"github"},
	}
}
