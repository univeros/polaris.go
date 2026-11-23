package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/wiring"
)

// pages is a plugin serving a consent and a device page, as plugins/ui does.
type pages struct{}

func (pages) ID() string { return "pages" }

func (pages) OAuthPages(*wiring.Graph) (consentURL, deviceURL string) {
	return "https://pages.test/consent", "https://pages.test/device"
}

// A registered PageProvider's pages fill the ConsentURL and the DeviceURL the host left empty, each
// on its own, whatever the order of the plugins; a host's own URL wins.
func TestAPageProviderFillsTheURLsTheHostLeftEmpty(t *testing.T) {
	const (
		appConsent = "https://app.test/consent"
		appDevice  = "https://app.test/device"
	)
	for name, c := range map[string]struct {
		cfg             oauth.Config
		before, after   []wiring.Plugin
		consent, device string // "" none
	}{
		"no provider":          {},
		"a provider before":    {before: []wiring.Plugin{pages{}}, consent: "https://pages.test/consent", device: "https://pages.test/device"},
		"a provider after":     {after: []wiring.Plugin{pages{}}, consent: "https://pages.test/consent", device: "https://pages.test/device"},
		"the host's consent":   {cfg: oauth.Config{ConsentURL: appConsent}, before: []wiring.Plugin{pages{}}, consent: appConsent, device: "https://pages.test/device"},
		"the host's device":    {cfg: oauth.Config{DeviceURL: appDevice}, before: []wiring.Plugin{pages{}}, consent: "https://pages.test/consent", device: appDevice},
		"the host's, both":     {cfg: oauth.Config{ConsentURL: appConsent, DeviceURL: appDevice}, after: []wiring.Plugin{pages{}}, consent: appConsent, device: appDevice},
		"the host's, no pages": {cfg: oauth.Config{ConsentURL: appConsent, DeviceURL: appDevice}, consent: appConsent, device: appDevice},
	} {
		t.Run(name, func(t *testing.T) {
			p := oauth.New(c.cfg)
			srv := polaristest.New(t, polaristest.WithPlugins(append(append(c.before, p), c.after...)...))
			issued, err := p.CreateClient(context.Background(), oauth.ClientFields{"name": "App", "redirect_uris": []any{redirectURI}, "type": "public",
				"grant_types": []any{oauth.GrantAuthorizationCode, oauth.GrantDeviceCode}, "scopes": []any{"openid"}}, "", "", false)
			if err != nil {
				t.Fatal(err)
			}
			do := func(r *http.Request) (*httptest.ResponseRecorder, map[string]any) {
				w := httptest.NewRecorder()
				srv.Handler().ServeHTTP(w, r)
				var doc map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &doc)
				return w, doc
			}

			// A browser's authorization request goes to the consent page; without one it reads data.
			_, challenge := pkce()
			q := url.Values{"response_type": {"code"}, "client_id": {issued.Client.ClientID}, "redirect_uri": {redirectURI}, "scope": {"openid"},
				"code_challenge": {challenge}, "code_challenge_method": {"S256"}}
			w, _ := do(httptest.NewRequest(http.MethodGet, "/oauth2/authorize?"+q.Encode(), nil))
			if got := w.Header().Get("Location"); c.consent == "" && w.Code != 200 ||
				c.consent != "" && (w.Code != 302 || !strings.HasPrefix(got, c.consent+"?request=")) {
				t.Errorf("authorize: %d %q %s, want %q", w.Code, got, w.Body, c.consent)
			}

			// The device flow sends its user to the device page; without one it is off.
			form := url.Values{"client_id": {issued.Client.ClientID}, "scope": {"openid"}}
			r := httptest.NewRequest(http.MethodPost, "/oauth2/device/code", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w, device := do(r)
			if c.device == "" && w.Code == 200 || c.device != "" && (w.Code != 200 || device["verification_uri"] != c.device) {
				t.Errorf("device: %d %v, want %q", w.Code, device, c.device)
			}
			_, meta := do(httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
			if _, on := meta["device_authorization_endpoint"]; on != (c.device != "") || meta["issuer"] == nil {
				t.Errorf("metadata: device flow %v: %v", on, meta)
			}
		})
	}
}
