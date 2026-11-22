package username_test

import (
	"context"
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
	"github.com/univeros/polaris.go/plugins/username"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

// A user with a username signs in with it, in any case, through core's password path.
func Example() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	db := memstore.New(append(schema.Core(), username.Models()...)...) // sqlstore.Open(...) in production

	names := username.New(username.Config{}) // the default rules: 3-30 of [A-Za-z0-9_.], reserved names
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: db, Plugins: []polaris.Plugin{names},
	})
	if err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()
	now := time.Now()
	hash, _ := p.Graph().Hasher().Hash("correct horse battery staple")
	_ = p.Graph().Repos().Users.Insert(ctx, model.User{ID: "user-1", Email: "ada@example.com", PasswordHash: &hash, EmailVerifiedAt: &now, CreatedAt: now, UpdatedAt: now})
	if _, err := names.Usernames().Set(ctx, "user-1", "Ada.L", ""); err != nil { // PATCH /username does this
		log.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodPost, "/username/sign-in", strings.NewReader(`{"username":"ADA.L","password":"correct horse battery staple"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	fmt.Println(w.Code, strings.Contains(w.Body.String(), `"refresh_token"`))
	// Output: 200 true
}
