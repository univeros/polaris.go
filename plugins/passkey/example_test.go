package passkey_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/passkey"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/token"
)

// A passkey registered from a session, then a discoverable sign-in (conditional UI). The browser
// side is navigator.credentials.create() / .get() with the options each route answers; here a
// software authenticator plays it.
func Example() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://app.example.com"
	db := memstore.New(append(schema.Core(), passkey.Models()...)...) // sqlstore.Open(...) in production

	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      db,
		Plugins: []polaris.Plugin{passkey.New(passkey.Config{Origins: []string{"https://app.example.com"}, RPName: "App"})},
	})
	if err != nil {
		log.Fatal(err)
	}
	call := func(target string, body any, bearer string) map[string]any {
		raw, _ := json.Marshal(body)
		r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		p.Handler().ServeHTTP(w, r)
		var out struct{ Data map[string]any }
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out.Data
	}

	// A signed-in user (POST /auth/login in a real flow).
	ctx, now := context.Background(), time.Now()
	_ = p.Graph().Repos().Users.Insert(ctx, model.User{ID: "user-1", Email: "ada@example.com", EmailVerifiedAt: &now, CreatedAt: now, UpdatedAt: now})
	authTime := now.Unix()
	session, _ := p.Graph().Sessions().Issue(ctx, token.SessionPrincipal{UserID: "user-1", EmailVerified: true, AMR: []string{"pwd"}, AuthTime: &authTime}, token.ClientContext{})

	browser := passkey.NewAuthenticator(nil) // a test-only software authenticator: the browser in production
	options := call("/passkey/register/options", nil, session.AccessToken)
	registered := call("/passkey/register/verify", map[string]any{"credential": browser.Create(options, "https://app.example.com", true), "name": "Laptop"}, session.AccessToken)
	fmt.Println(registered["passkey"].(map[string]any)["name"])

	request := call("/passkey/authenticate/options", nil, "") // on page load, for autofill
	signedIn := call("/passkey/authenticate/verify", map[string]any{"credential": browser.Get(request, "https://app.example.com", "user-1", true, 1)}, "")
	fmt.Println(signedIn["token_type"], signedIn["user"].(map[string]any)["email"])
	// Output:
	// Laptop
	// Bearer ada@example.com
}
