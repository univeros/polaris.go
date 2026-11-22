package polaris_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// A session the host opens in an organization: its tokens carry the organization and the user's
// roles and permissions there, as after POST /auth/switch-org. An unverified email is refused
// with its own error.
func ExampleSessions_Issue() {
	ctx := context.Background()
	p, _ := signedIn()
	ada, _ := p.Users().ByEmail(ctx, "ada@example.com")
	org, _ := p.Orgs().Create(ctx, ada.ID, "Acme", "")

	tokens, err := p.Sessions().Issue(ctx, polaris.SignIn{UserID: ada.ID, OrganizationID: org.ID})
	if err != nil {
		panic(err)
	}
	p.Protect(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		fmt.Println(who.OrganizationID == org.ID, who.Roles)
	})).ServeHTTP(httptest.NewRecorder(), bearer(tokens.AccessToken))

	bob, _ := p.Users().Create(ctx, polaris.NewUser{Email: "bob@example.com"}) // not verified yet
	_, err = p.Sessions().Issue(ctx, polaris.SignIn{UserID: bob.ID})
	fmt.Println(errors.Is(err, polaris.ErrEmailNotVerified), errors.Is(err, polaris.ErrForbidden))
	// Output:
	// true [owner]
	// true true
}

// An invitation from Go: the host gets the token to deliver its own way (a link to its page,
// which posts it to POST /auth/invites/accept).
func ExampleOrgs_Invite() {
	ctx := context.Background()
	p, _ := signedIn()
	ada, _ := p.Users().ByEmail(ctx, "ada@example.com")
	org, _ := p.Orgs().Create(ctx, ada.ID, "Acme", "")

	inv, token, err := p.Orgs().Invite(ctx, org.ID, ada.ID, "Grace@Example.com", "admin")
	if err != nil {
		panic(err)
	}
	fmt.Println(inv.Email, inv.Roles, inv.InvitedBy == ada.ID, token != "")
	// link := "https://app.example.com/join?token=" + url.QueryEscape(token)

	_, _, err = p.Orgs().Invite(ctx, org.ID, ada.ID, "ada@example.com", "member")
	fmt.Println(errors.Is(err, polaris.ErrConflict)) // already a member
	// Output:
	// grace@example.com [admin] true true
	// true
}

// Config.Middleware around a host route that Protect does not guard: the same chain, once.
func ExamplePolaris_Wrap() {
	private, public := contracttest.TestRSAKeyPEM() // your AUTH_JWT_* keys (polaris.FromEnv)
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	requestID := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-Id", "req-1")
			next.ServeHTTP(w, r)
		})
	}
	p, err := polaris.New(polaris.Config{
		Secrets:    config.Secrets{AppKey: "an-application-key-of-32-bytes!!", JWTPrivateKey: private, JWTPublicKey: public},
		Auth:       auth,
		DB:         memstore.New(schema.Core()...),
		Middleware: []func(http.Handler) http.Handler{requestID},
	})
	if err != nil {
		panic(err)
	}
	health := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") })

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler())               // wrapped already
	mux.Handle("GET /healthz", p.Wrap(health)) // public, and wrapped too
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	fmt.Println(w.Body.String(), w.Header().Get("X-Request-Id"))
	// Output: ok req-1
}

// Zero-setup local development: run with POLARIS_DEV=1 and DevEnv generates whatever secret the
// environment lacks. Without POLARIS_DEV=1 it refuses, so a production deploy that forgot its
// secrets fails at boot instead of running on throwaway ones.
func ExampleDevEnv() {
	ctx := context.Background()
	if err := polaris.DevEnv("http://localhost:8080"); err != nil { // POLARIS_DEV=1 go run ./cmd/app
		log.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:dev.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := polaris.FromEnv(db) // reads what DevEnv set
	if err != nil {
		log.Fatal(err)
	}
	if _, err := polaris.New(cfg); err != nil {
		log.Fatal(err)
	}
}

func bearer(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}
