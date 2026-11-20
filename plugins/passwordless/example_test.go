package passwordless_test

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/notify/notifytest"
	"github.com/univeros/polaris-go/plugins/passwordless"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

// A magic link signs a new address up: the email links to /magic-link/verify, which redirects to
// the application with a one-minute code; the application trades the code for the session.
func Example() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"                               // magic links point here (Config.BaseURL overrides it)
	db := memstore.New(append(schema.Core(), passwordless.Models()...)...) // sqlstore.Open(...) in production
	mailer := &notifytest.Mailer{}                                         // your SES/SMTP adapter in production

	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: db, Mailer: mailer,
		Plugins: []polaris.Plugin{passwordless.New(passwordless.Config{RedirectURIs: []string{"https://app.example.com/signed-in"}})},
	})
	if err != nil {
		log.Fatal(err)
	}
	send := func(method, target, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		p.Handler().ServeHTTP(w, r)
		return w
	}

	fmt.Println(send(http.MethodPost, "/magic-link/send", `{"email":"ada@example.com"}`).Code)
	link, _ := url.Parse(mailer.Sent()[0].Data["link"].(string)) // https://auth.example.com/magic-link/verify?token=…
	redirect := send(http.MethodGet, link.RequestURI(), "")
	back, _ := url.Parse(redirect.Header().Get("Location")) // https://app.example.com/signed-in?code=…
	fmt.Println(redirect.Code, back.Host+back.Path)
	session := send(http.MethodPost, "/magic-link/exchange", `{"code":"`+back.Query().Get("code")+`"}`)
	fmt.Println(session.Code, strings.Contains(session.Body.String(), `"refresh_token"`))
	// Output:
	// 202
	// 302 app.example.com/signed-in
	// 200 true
}
