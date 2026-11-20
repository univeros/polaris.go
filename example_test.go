package polaris_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
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
