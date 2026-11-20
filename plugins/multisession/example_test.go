package multisession_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/plugins/multisession"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store/memstore"
)

// Every sign-in answers the device id; the client sends it back (header or cookie) to list the
// accounts on the device, switch between them and read the last sign-in method.
func Example() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	db := memstore.New(append(schema.Core(), multisession.Models()...)...) // sqlstore.Open(...) in production
	hasher := security.Argon2id{Memory: 1024, Time: 1}                     // the zero value in production

	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: db, Hasher: hasher,
		Plugins: []polaris.Plugin{multisession.New(multisession.Config{})},
	})
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	hash, _ := hasher.Hash("correct horse battery staple")
	_ = p.Graph().Repos.Users.Insert(context.Background(), model.User{ID: "user-1", Email: "ada@example.com", PasswordHash: &hash, EmailVerifiedAt: &now, CreatedAt: now, UpdatedAt: now})

	send := func(method, path, body, device string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if device != "" {
			r.Header.Set(multisession.Header, device)
		}
		w := httptest.NewRecorder()
		p.Handler().ServeHTTP(w, r)
		return w
	}
	login := send(http.MethodPost, "/auth/login", `{"email":"ada@example.com","password":"correct horse battery staple"}`, "")
	device := login.Header().Get(multisession.Header) // also the polaris_ms_device cookie
	fmt.Println(login.Code, len(device))
	fmt.Println(send(http.MethodGet, "/multi-session/last-method", "", device).Body.String())
	// Output:
	// 200 64
	// {"data":{"last_method":"pwd"}}
}
