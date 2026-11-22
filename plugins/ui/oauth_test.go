package ui_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/plugins/ui"
	"github.com/univeros/polaris.go/polaristest"
)

const redirectURI = "https://cli.example.net/cb"

// oauthApp is a host with the pages and the OAuth provider, which finds the pages on its own.
func oauthApp(t *testing.T) (*app, oauth.IssuedClient) {
	t.Helper()
	web := ui.New(ui.Config{})
	srv := polaristest.New(t, polaristest.WithPlugins(web, oauth.New(oauth.Config{})),
		polaristest.WithAuth(func(c *config.Auth) { c.Issuer = origin }))
	a := mount(t, srv, web)
	a.account("ada@example.com")
	client, err := srv.Graph().Plugin(oauth.ID).(*oauth.Plugin).CreateClient(t.Context(), oauth.ClientFields{
		"name": "Acme <CLI>", "redirect_uris": []string{redirectURI},
		"grant_types": []string{oauth.GrantAuthorizationCode, oauth.GrantRefreshToken, oauth.GrantDeviceCode},
	}, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	return a, client
}

func authorizeURL(clientID, scope string) string {
	sum := sha256.Sum256([]byte("a-verifier-that-is-long-enough-for-pkce-0123456789"))
	return "/oauth2/authorize?" + url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
		"scope": {scope}, "state": {"xyz"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}.Encode()
}

func TestOAuthConsent(t *testing.T) {
	a, client := oauthApp(t)
	b := a.browser()

	toConsent := b.get(authorizeURL(client.Client.ClientID, "openid email"))
	if toConsent.Code != http.StatusFound || !strings.HasPrefix(toConsent.Header().Get("Location"), origin+"/auth/ui/consent?request=") {
		t.Fatalf("authorize: %d %q", toConsent.Code, toConsent.Header().Get("Location"))
	}
	consentPath := strings.TrimPrefix(toConsent.Header().Get("Location"), origin)
	toRefresh := b.follow(toConsent) // not signed in: through refresh to sign-in, then back
	toSignIn := b.follow(toRefresh)
	location(t, toSignIn, "/auth/ui/sign-in?return_to="+url.QueryEscape(consentPath))
	b.follow(toSignIn)
	back := b.post("/auth/ui/sign-in", url.Values{"email": {"ada@example.com"}, "password": {password}, "return_to": {consentPath}})
	location(t, back, consentPath)

	page := b.follow(back)
	expect(t, page, 200, "Acme &lt;CLI&gt; wants to access your account", "<code>openid</code>", "<code>email</code>", redirectURI)
	if csp := page.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "form-action 'self' https://cli.example.net;") {
		t.Fatalf("the decision's redirect is not a form target: %s", csp)
	}
	request := strings.TrimPrefix(consentPath, "/auth/ui/consent?request=")
	approved := b.post("/auth/ui/consent", url.Values{"request": {request}, "approve": {"true"}})
	if loc := approved.Header().Get("Location"); approved.Code != 303 || !strings.HasPrefix(loc, redirectURI+"?code=") || !strings.Contains(loc, "state=xyz") {
		t.Fatalf("approve: %d %q", approved.Code, loc)
	}

	again := b.follow(b.get(authorizeURL(client.Client.ClientID, "openid"))) // granted before: no screen
	if loc := again.Header().Get("Location"); again.Code != 303 || !strings.HasPrefix(loc, redirectURI+"?code=") {
		t.Fatalf("remembered consent: %d %q %s", again.Code, loc, again.Body)
	}

	ask := b.get(authorizeURL(client.Client.ClientID, "openid profile"))
	expect(t, b.follow(ask), 200, "Allow")
	request = strings.TrimPrefix(ask.Header().Get("Location"), origin+"/auth/ui/consent?request=")
	denied := b.post("/auth/ui/consent", url.Values{"request": {request}, "approve": {"false"}})
	if loc := denied.Header().Get("Location"); !strings.Contains(loc, "error=access_denied") {
		t.Fatalf("deny: %d %q", denied.Code, loc)
	}
	expect(t, b.get("/auth/ui/consent?request=unknown"), 400, "unknown or has expired")
	expect(t, b.get("/auth/ui/consent"), 400)
}

func TestOAuthDevice(t *testing.T) {
	a, client := oauthApp(t)
	form := url.Values{"scope": {"openid"}}
	r := httptest.NewRequest(http.MethodPost, origin+"/oauth2/device/code", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.SetBasicAuth(client.Client.ClientID, client.Secret)
	rec := httptest.NewRecorder()
	a.h.ServeHTTP(rec, r)
	var device map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &device)
	if device["verification_uri"] != origin+"/auth/ui/device" {
		t.Fatalf("device code: %d %v", rec.Code, device)
	}

	b := a.browser()
	complete, _ := device["verification_uri_complete"].(string)
	location(t, b.signIn("ada@example.com"), "/")
	expect(t, b.get("/auth/ui/device"), 200, `name="user_code"`)
	expect(t, b.get("/auth/ui/device?user_code=ZZZZ-ZZZZ"), 404, "unknown or has expired")
	page := b.get(strings.TrimPrefix(complete, origin))
	expect(t, page, 200, "Acme &lt;CLI&gt; on your device wants to access your account", "<code>openid</code>")
	userCode := regexpValue(t, page.Body.String(), "user_code")
	expect(t, b.post("/auth/ui/device", url.Values{"user_code": {userCode}, "approve": {"true"}}), 200, "The device is connected")
	expect(t, b.post("/auth/ui/device", url.Values{"user_code": {userCode}, "approve": {"true"}}), 404, "unknown or has expired") // decided once

	signedOut := a.browser()
	location(t, signedOut.get("/auth/ui/device?user_code=ABCD"), "/auth/ui/refresh?return_to=%2Fauth%2Fui%2Fdevice%3Fuser_code%3DABCD")
}

func regexpValue(t *testing.T, body, name string) string {
	t.Helper()
	i := strings.Index(body, `name="`+name+`" value="`)
	if i < 0 {
		t.Fatalf("no %s field:\n%s", name, body)
	}
	rest := body[i+len(`name="`+name+`" value="`):]
	return rest[:strings.IndexByte(rest, '"')]
}
