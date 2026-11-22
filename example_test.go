package polaris_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

// An app keeps a profile per account (OnUserCreated runs in the account's transaction), adds its
// own claim to access tokens, creates an account and a session from Go, and reads the principal
// on its own route.
func Example() {
	ctx := context.Background()
	private, public := contracttest.TestRSAKeyPEM() // use your AUTH_JWT_* keys (polaris.FromEnv)
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	profiles := map[string]string{}
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: "an-application-key-of-32-bytes!!", JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(schema.Core()...), // sqlstore.Open(ctx, store.Postgres, dsn) in production
		Hooks: polaris.Hooks{
			OnUserCreated: func(ctx context.Context, u polaris.User) error { profiles[u.ID] = "free"; return nil },
			Claims: func(ctx context.Context, in polaris.ClaimsInput) (map[string]any, error) {
				return map[string]any{"app_plan": profiles[in.UserID]}, nil
			},
		},
	})
	if err != nil {
		panic(err)
	}

	ada, err := p.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
	if err != nil {
		panic(err)
	}
	tokens, err := p.Sessions().Issue(ctx, polaris.SignIn{UserID: ada.ID})
	if err != nil {
		panic(err)
	}

	api := p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		fmt.Println(who.UserID == ada.ID, who.Kind, who.Claims["app_plan"])
	}))
	r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	api.ServeHTTP(httptest.NewRecorder(), r)
	// Output: true user free
}

// Users from another system keep their passwords: import each with the hash it stored (here a
// bcrypt hash; Django, passlib and Firebase hashes work the same way), and the first sign-in
// replaces it with Argon2id.
func ExampleUsers_Import() {
	ctx := context.Background()
	private, public := contracttest.TestRSAKeyPEM() // use your AUTH_JWT_* keys (polaris.FromEnv)
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: "an-application-key-of-32-bytes!!", JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(schema.Core()...), // sqlstore.Open(ctx, store.Postgres, dsn) in production
	})
	if err != nil {
		panic(err)
	}

	// In a migration, loop over your rows inside one transaction: sqlstore.WithTx(ctx, tx).
	ada, err := p.Users().Import(ctx, polaris.ImportedUser{
		Email:         "ada@example.com",
		PasswordHash:  "$2y$04$9xkaXv9u52gB5CSHs990Rujqpwb54f2v3nd7nRc.mRPDPsGvyU1R6", // the password is "bcrypt"
		EmailVerified: true,
	})
	if err != nil {
		panic(err) // errors.Is(err, polaris.ErrInvalidInput): a hash the hasher cannot verify
	}

	login := httptest.NewRequest(http.MethodPost, "/auth/login",
		strings.NewReader(`{"email": "ada@example.com", "password": "bcrypt"}`))
	login.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, login) // verifies the bcrypt hash, stores an Argon2id one
	fmt.Println(ada.Email, rec.Code)
	// Output: ada@example.com 200
}
