package polaris_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

// signedIn is a Polaris instance and the access token of a user it signed in.
func signedIn() (*polaris.Polaris, string) {
	ctx := context.Background()
	private, public := contracttest.TestRSAKeyPEM() // your AUTH_JWT_* keys (polaris.FromEnv)
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: "an-application-key-of-32-bytes!!", JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(schema.Core()...),
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
	return p, tokens.AccessToken
}

func get(h http.Handler, bearer string) int {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

// A public page that greets a signed-in user: anonymous requests pass, a bad token does not.
func ExamplePolaris_Authenticate() {
	p, accessToken := signedIn()
	home := p.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if who, ok := polaris.PrincipalFrom(r.Context()); ok {
			fmt.Println("welcome back,", who.Kind)
			return
		}
		fmt.Println("welcome, guest")
	}))
	fmt.Println(get(home, ""))
	fmt.Println(get(home, accessToken))
	fmt.Println(get(home, "forged"))
	// Output:
	// welcome, guest
	// 200
	// welcome back, user
	// 200
	// 401
}

// Require is Protect as middleware; RequireKind keeps API keys, OAuth clients and agents off a
// route meant for people.
func ExamplePolaris_Require() {
	p, accessToken := signedIn()
	ok := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	chain := func(h http.Handler, mw ...func(http.Handler) http.Handler) http.Handler {
		for i := len(mw) - 1; i >= 0; i-- {
			h = mw[i](h)
		}
		return h
	}
	fmt.Println(get(chain(ok, p.Require()), ""))
	fmt.Println(get(chain(ok, p.Require(), polaris.RequireKind(polaris.KindUser)), accessToken))
	fmt.Println(get(chain(ok, p.Require(), polaris.RequireOrganization), accessToken))
	fmt.Println(get(chain(ok, p.Require("members.update")), accessToken))
	// Output:
	// 401
	// 200
	// 403
	// 403
}
