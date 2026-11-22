package verify_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/verify"
)

// authService is the Polaris host, in a service of its own: it signs a user in and publishes its
// keys. It returns the user's id and access token.
func authService() (srv *httptest.Server, userID, accessToken string) {
	ctx := context.Background()
	private, public := contracttest.TestRSAKeyPEM() // your AUTH_JWT_* keys
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
	return httptest.NewTLSServer(p.Handler()), ada.ID, tokens.AccessToken
}

// A billing service, with no access to the auth database, accepts the access tokens the Polaris
// host issues.
func Example() {
	auth, adaID, accessToken := authService()
	defer auth.Close()

	v, err := verify.New(verify.Config{
		Issuer:     "https://auth.example.com",
		JWKSURL:    auth.URL + "/auth/.well-known/jwks.json",
		HTTPClient: auth.Client(), // the default client refuses private addresses, this test server's among them
	})
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /invoices", v.Require()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := verify.ClaimsFrom(r.Context())
		fmt.Println("invoices of ada:", c.Subject == adaID)
	})))

	for _, bearer := range []string{accessToken, "forged"} {
		r := httptest.NewRequest(http.MethodGet, "/invoices", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		fmt.Printf("%d %q\n", w.Code, w.Header().Get("WWW-Authenticate"))
	}
	// Output:
	// invoices of ada: true
	// 200 ""
	// 401 "Bearer error=\"invalid_token\", error_description=\"The token is not a JWT.\""
}

// Verify checks a token that does not arrive in an Authorization header: a WebSocket's first
// message, a queued job's metadata.
func ExampleVerifier_Verify() {
	auth, adaID, accessToken := authService()
	defer auth.Close()
	v, err := verify.New(verify.Config{Issuer: "https://auth.example.com", JWKSURL: auth.URL + "/auth/.well-known/jwks.json", HTTPClient: auth.Client()})
	if err != nil {
		panic(err)
	}
	c, err := v.Verify(context.Background(), accessToken)
	fmt.Println(err, c.Subject == adaID, slices.Contains(c.Scopes, "org.read"))
	// Output: <nil> true false
}
