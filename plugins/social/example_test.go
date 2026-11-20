package social_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/plugins/social"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

// acmeServer stands in for an OAuth 2 server: its token and profile endpoints.
type acmeServer struct{}

func (acmeServer) RoundTrip(r *http.Request) (*http.Response, error) {
	body := map[string]any{"access_token": "acme-access", "token_type": "Bearer", "expires_in": 3600}
	if r.URL.Path == "/me" {
		body = map[string]any{"id": "42", "email": "ada@example.com", "verified": true, "name": "Ada"}
	}
	raw, _ := json.Marshal(body)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
}

// A sign-in through any OAuth 2 server (the catalog's providers need only a client id and
// secret): start, the provider's callback, then the exchange of the hand-off code for core's
// login envelope.
func Example() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://app.example.com"
	db := memstore.New(append(schema.Core(), social.Models()...)...) // sqlstore.Open(...) in production

	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      db,
		Plugins: []polaris.Plugin{social.New(social.Config{
			BaseURL:      "https://app.example.com",
			RedirectURIs: []string{"https://app.example.com/signed-in"},
			Providers: map[string]social.Provider{
				// "google": {ClientID: "…", ClientSecret: "…"}, and so on for the catalog.
				"acme": {ClientID: "acme-client", ClientSecret: "acme-secret", Definition: &social.Definition{
					AuthorizationURL: "https://acme.example/authorize", TokenURL: "https://acme.example/token", UserinfoURL: "https://acme.example/me",
					Profile: func(d map[string]any) social.Profile {
						return social.Profile{Subject: fmt.Sprint(d["id"]), Email: fmt.Sprint(d["email"]), EmailVerified: d["verified"] == true, Name: fmt.Sprint(d["name"])}
					},
				}},
			},
			HTTPClient: &http.Client{Transport: acmeServer{}}, // omit in production
		})},
	})
	if err != nil {
		log.Fatal(err)
	}
	var cookies []*http.Cookie // the browser's: start binds the flow to it with a cookie
	call := func(method, target string, body any) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(method, target, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		p.Handler().ServeHTTP(w, r)
		cookies = append(cookies, w.Result().Cookies()...)
		return w
	}

	var started struct{ Data struct{ URL, State string } }
	_ = json.Unmarshal(call("POST", "/social/acme/start", nil).Body.Bytes(), &started)
	// The browser goes to started.Data.URL; the provider sends it back to the callback, in the
	// same browser (another browser's callback is refused: login CSRF).
	back := call("GET", "/social/acme/callback?code=from-acme&state="+url.QueryEscape(started.Data.State), nil)
	landed, _ := url.Parse(back.Header().Get("Location"))
	fmt.Println(back.Code, landed.Host+landed.Path, landed.Query().Get("state") == started.Data.State)

	// The application compares the state, then exchanges the code once.
	var session struct {
		Data struct {
			TokenType string `json:"token_type"`
			User      struct{ Email string }
		}
	}
	_ = json.Unmarshal(call("POST", "/social/exchange", map[string]any{"code": landed.Query().Get("code")}).Body.Bytes(), &session)
	fmt.Println(session.Data.TokenType, session.Data.User.Email)
	// Output:
	// 302 app.example.com/signed-in true
	// Bearer ada@example.com
}
