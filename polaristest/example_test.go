package polaristest_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/polaristest"
)

// An application's own test of a protected route: boot Polaris (SQLite in a temp dir, test keys,
// recorders), create a signed-in user from Go and call the route with the access token. The body
// is what goes in a func TestX(t *testing.T); an example has no t, so this one is compiled, not
// run.
func ExampleNew() {
	var t *testing.T // the test's t

	srv := polaristest.New(t) // polaristest.WithPlugins(…), WithConfig(…) for the app's set-up
	ctx := context.Background()
	ada, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := srv.Sessions().Issue(ctx, polaris.SignIn{UserID: ada.ID})
	if err != nil {
		t.Fatal(err)
	}

	route := srv.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	r := httptest.NewRequest(http.MethodGet, "/api/me", nil)
	r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w := httptest.NewRecorder()
	route.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	if names := srv.Events.Names(); len(names) == 0 {
		t.Fatal("no event recorded") // srv.Events, srv.Mailer and srv.SMS record what Polaris sent
	}
}

// A host whose tests boot its own server (its newServer builds the polaris.Config) keeps the
// production Argon2id out of them: hashing at 64 MiB per password makes a -race suite crawl.
func ExampleHasher() {
	var t *testing.T // the test's t

	cfg, err := polaris.FromEnv(nil /* the test database */)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Hasher = polaristest.Hasher() // tests only; the hash format is the production one
	if _, err := polaris.New(cfg); err != nil {
		t.Fatal(err)
	}
}
