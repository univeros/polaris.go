package polaris_test

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/session"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// hookLog records what the hooks saw.
type hookLog struct {
	mu      sync.Mutex
	created []polaris.User
	deleted []string
}

func (h *hookLog) hooks() polaris.Hooks {
	return polaris.Hooks{
		OnUserCreated: func(_ context.Context, u polaris.User) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.created = append(h.created, u)
			return nil
		},
		OnUserDeleted: func(_ context.Context, id string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.deleted = append(h.deleted, id)
			return nil
		},
		Claims: func(_ context.Context, in polaris.ClaimsInput) (map[string]any, error) {
			return map[string]any{"app_plan": "pro:" + in.UserID}, nil
		},
	}
}

func is(t *testing.T, err, want error, what string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestTheProgrammaticAPI(t *testing.T) {
	ctx := context.Background()
	log := &hookLog{}
	srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) { c.Hooks = log.hooks() }))
	users, orgs, sessions := srv.Users(), srv.Orgs(), srv.Sessions()

	ada, err := users.Create(ctx, polaris.NewUser{Email: " Ada@Example.com", Password: "correct horse battery staple", DisplayName: "Ada", EmailVerified: true})
	ok(t, err)
	if ada.Email != "ada@example.com" || !ada.EmailVerified || ada.DisplayName != "Ada" || ada.Status != "active" || len(log.created) != 1 || log.created[0].ID != ada.ID {
		t.Fatalf("created %+v, hook saw %+v", ada, log.created)
	}
	if len(srv.Mailer.Sent()) != 0 {
		t.Fatal("a verified account gets no verification mail")
	}
	bob, err := users.Create(ctx, polaris.NewUser{Email: "bob@example.com"})
	ok(t, err)
	if bob.EmailVerified || len(srv.Mailer.Sent()) != 1 {
		t.Fatal("an unverified account gets the verification mail, as on registration")
	}
	_, err = users.Create(ctx, polaris.NewUser{Email: "ADA@example.com"})
	is(t, err, polaris.ErrConflict, "taken email")
	_, err = users.Create(ctx, polaris.NewUser{Email: "not-an-email"})
	is(t, err, polaris.ErrInvalidInput, "bad email")
	_, err = users.Create(ctx, polaris.NewUser{Email: "eve@example.com", Password: "short"})
	var weak *polaris.PasswordError
	if is(t, err, polaris.ErrInvalidInput, "weak password"); !errors.As(err, &weak) || len(weak.Violations) == 0 {
		t.Fatalf("violations: %v", err)
	}
	if got, err := users.ByEmail(ctx, "ADA@example.com"); err != nil || got.ID != ada.ID {
		t.Fatalf("by email %+v %v", got, err)
	}
	_, err = users.Get(ctx, "nobody")
	is(t, err, polaris.ErrNotFound, "unknown user")

	org, err := orgs.Create(ctx, ada.ID, "Acme Inc", "")
	ok(t, err)
	if org.Slug != "acme-inc" || org.CreatedBy != ada.ID {
		t.Fatalf("org %+v", org)
	}
	_, err = orgs.Create(ctx, "nobody", "Ghost", "")
	is(t, err, polaris.ErrNotFound, "unknown owner")
	_, err = orgs.Create(ctx, ada.ID, "", "")
	is(t, err, polaris.ErrInvalidInput, "no name")
	_, err = orgs.Create(ctx, ada.ID, "Acme again", "acme-inc")
	is(t, err, polaris.ErrConflict, "taken slug")
	ok(t, orgs.AddMember(ctx, org.ID, bob.ID, "member"))
	is(t, orgs.AddMember(ctx, org.ID, bob.ID, "member"), polaris.ErrConflict, "already a member")
	is(t, orgs.AddMember(ctx, org.ID, ada.ID, "nope"), polaris.ErrConflict, "the owner is a member")
	if list, err := orgs.ListFor(ctx, bob.ID); err != nil || len(list) != 1 || list[0].ID != org.ID {
		t.Fatalf("list %v %v", list, err)
	}
	if got, err := orgs.Get(ctx, org.ID); err != nil || got.Name != "Acme Inc" {
		t.Fatalf("get %+v %v", got, err)
	}

	bobIn := polaris.Principal{UserID: bob.ID, OrganizationID: org.ID}
	if !srv.Can(ctx, bobIn, "org.read") || srv.Can(ctx, bobIn, "members.update") || srv.Can(ctx, bobIn) {
		t.Fatal("a member reads, does not manage, and no permission is no grant")
	}
	is(t, orgs.SetRoles(ctx, org.ID, bob.ID, "nope"), polaris.ErrInvalidInput, "unknown role")
	ok(t, orgs.SetRoles(ctx, org.ID, bob.ID, "admin"))
	if !srv.Can(ctx, bobIn, "members.update") {
		t.Fatal("an admin manages members")
	}
	is(t, orgs.SetRoles(ctx, org.ID, ada.ID, "member"), polaris.ErrConflict, "demoting the last owner")
	is(t, orgs.RemoveMember(ctx, org.ID, ada.ID), polaris.ErrConflict, "removing the last owner")
	ok(t, orgs.RemoveMember(ctx, org.ID, bob.ID))
	if srv.Can(ctx, bobIn, "org.read") {
		t.Fatal("a removed member holds nothing")
	}

	// A session the host opened works on its routes like a password sign-in, with its claims.
	tokens, err := sessions.Issue(ctx, polaris.SignIn{UserID: ada.ID, AMR: []string{"hwk"}})
	ok(t, err)
	var who polaris.Principal
	protected := srv.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { who, _ = polaris.PrincipalFrom(r.Context()) }))
	call := func(access string) int {
		r := httptest.NewRequest(http.MethodGet, "/api", nil)
		r.Header.Set("Authorization", "Bearer "+access)
		w := httptest.NewRecorder()
		protected.ServeHTTP(w, r)
		return w.Code
	}
	if code := call(tokens.AccessToken); code != 200 || who.UserID != ada.ID || who.Kind != polaris.KindUser || who.Delegated ||
		who.Claims["app_plan"] != "pro:"+ada.ID || len(who.Permissions) != 0 {
		t.Fatalf("issued session: %d %+v", code, who)
	}
	refreshed, err := sessions.Refresh(ctx, tokens.RefreshToken)
	ok(t, err)
	_, err = sessions.Refresh(ctx, tokens.RefreshToken)
	is(t, err, polaris.ErrInvalidCredentials, "a rotated refresh token")
	ok(t, sessions.Revoke(ctx, refreshed.SessionID))
	_, err = sessions.Refresh(ctx, refreshed.RefreshToken)
	is(t, err, polaris.ErrInvalidCredentials, "a revoked session")
	again, err := sessions.Issue(ctx, polaris.SignIn{UserID: ada.ID})
	ok(t, err)
	ok(t, sessions.RevokeAll(ctx, ada.ID))
	_, err = sessions.Refresh(ctx, again.RefreshToken)
	is(t, err, polaris.ErrInvalidCredentials, "after logout everywhere")
	if strings.Contains(tokens.String(), tokens.AccessToken) {
		t.Fatal("Tokens prints a secret")
	}

	ok(t, users.Disable(ctx, ada.ID))
	_, err = sessions.Issue(ctx, polaris.SignIn{UserID: ada.ID})
	is(t, err, polaris.ErrForbidden, "a disabled account")
	ok(t, users.Enable(ctx, ada.ID))
	is(t, users.SetPassword(ctx, ada.ID, "short"), polaris.ErrInvalidInput, "weak password")
	ok(t, users.SetPassword(ctx, ada.ID, "another correct horse battery"))

	ok(t, users.Delete(ctx, bob.ID))
	if gone, _ := users.Get(ctx, bob.ID); gone.Email == "bob@example.com" || gone.Status != "disabled" || !slices.Equal(log.deleted, []string{bob.ID}) {
		t.Fatalf("erased %+v, hook saw %v", gone, log.deleted)
	}
	is(t, users.Enable(ctx, bob.ID), polaris.ErrConflict, "an erased account")
	for _, name := range []string{"user.registered", "org.created", "member.joined", "member.roles_changed", "member.removed", "user.logged_in", "user.disabled", "user.deleted"} {
		if !slices.Contains(srv.Events.Names(), name) {
			t.Errorf("no %s event", name)
		}
	}
}

func TestOnUserCreatedRunsInTheAccountsTransaction(t *testing.T) {
	ctx := context.Background()
	refuse := errors.New("profile service down")
	srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) {
		c.Hooks.OnUserCreated = func(context.Context, polaris.User) error { return refuse }
	}))
	_, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com"})
	if !errors.Is(err, refuse) {
		t.Fatalf("create: %v", err)
	}
	c := contracttest.NewClient(t, srv.Handler(), nil)
	if r := c.Post("/auth/register", map[string]any{"email": "bob@example.com", "password": "correct horse battery staple"}); r.StatusCode != 500 {
		t.Fatalf("register with a failing hook: %d", r.StatusCode)
	}
	for _, email := range []string{"ada@example.com", "bob@example.com"} {
		_, err := srv.Users().ByEmail(ctx, email)
		is(t, err, polaris.ErrNotFound, "a refused account is not created")
	}
}

func TestClaimsHookRefusesReservedNames(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"org", "sub", "roles", "api_key", "polaris_tenant"} {
		srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) {
			c.Hooks.Claims = func(context.Context, polaris.ClaimsInput) (map[string]any, error) {
				return map[string]any{name: "spoofed"}, nil
			}
		}))
		ada, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
		ok(t, err)
		if _, err := srv.Sessions().Issue(ctx, polaris.SignIn{UserID: ada.ID}); !errors.Is(err, session.ErrReservedClaim) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A host transaction carries a programmatic create and its hook's writes: rolled back, neither
// exists; committed, both do. A Polaris refusal inside it undoes only Polaris's own savepoint.
func TestWithTxJoinsTheHostTransaction(t *testing.T) {
	ctx := context.Background()
	var db *sqlstore.Store
	srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) {
		db = c.DB.(*sqlstore.Store)
		c.Hooks.OnUserCreated = func(ctx context.Context, u polaris.User) error {
			return db.Exec(ctx, "INSERT INTO app_profiles (user_id) VALUES ("+placeholder(db)+")", u.ID)
		}
	}))
	ok(t, db.Exec(ctx, "CREATE TABLE app_profiles (user_id VARCHAR(36) PRIMARY KEY)"))
	profiles := func() int {
		var n int
		ok(t, db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM app_profiles").Scan(&n))
		return n
	}

	tx, err := db.DB().BeginTx(ctx, nil)
	ok(t, err)
	ada, err := srv.Users().Create(sqlstore.WithTx(ctx, tx), polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
	ok(t, err)
	ok(t, tx.Rollback())
	if _, err := srv.Users().Get(ctx, ada.ID); !errors.Is(err, polaris.ErrNotFound) || profiles() != 0 {
		t.Fatalf("after the host's rollback: %v, %d profiles", err, profiles())
	}

	tx, err = db.DB().BeginTx(ctx, nil)
	ok(t, err)
	in := sqlstore.WithTx(ctx, tx)
	ada, err = srv.Users().Create(in, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
	ok(t, err)
	_, err = srv.Users().Create(in, polaris.NewUser{Email: "ada@example.com"})
	is(t, err, polaris.ErrConflict, "a refusal inside the host transaction")
	org, err := srv.Orgs().Create(in, ada.ID, "Acme", "")
	ok(t, err)
	ok(t, tx.Commit())
	if _, err := srv.Orgs().Get(ctx, org.ID); err != nil || profiles() != 1 {
		t.Fatalf("after the host's commit: %v, %d profiles", err, profiles())
	}
}

func placeholder(db *sqlstore.Store) string {
	if db.Dialect() == "postgres" {
		return "$1"
	}
	return "?"
}

func TestHostListenersAndMiddleware(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	var seen []string
	listener := func(_ context.Context, e event.Event) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, e.EventName())
	}
	var order []string
	mark := func(name string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) {
		c.Events = nil // the default bus
		c.Listeners = []event.Listener{listener}
		c.Middleware = []func(http.Handler) http.Handler{mark("outer"), mark("inner")}
	}))
	_, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
	ok(t, err)
	if !slices.Contains(seen, "user.registered") {
		t.Fatalf("host listener saw %v", seen)
	}
	srv.Handler().ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/.well-known/jwks.json", nil))
	srv.Protect(http.NotFoundHandler()).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api", nil))
	if !slices.Equal(order, []string{"outer", "inner", "outer", "inner"}) {
		t.Fatalf("middleware order %v", order)
	}

	_, err = polaris.New(polaris.Config{Listeners: []event.Listener{nil}, Middleware: []func(http.Handler) http.Handler{nil}})
	if err == nil || !strings.Contains(err.Error(), "Config.Listeners") || !strings.Contains(err.Error(), "Config.Middleware") {
		t.Fatalf("nil entries: %v", err)
	}
}

// Every account is created through identity.InsertUser, so Hooks.OnUserCreated cannot be skipped
// by a new sign-up path: no other code writes auth_users rows.
func TestEveryAccountIsCreatedThroughInsertUser(t *testing.T) {
	direct := regexp.MustCompile(`Users(\(\))?\.Insert\(|Insert\(ctx, "auth_users"`)
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		if path == filepath.Join("internal", "identity", "accounts.go") || strings.HasPrefix(path, "repository"+string(filepath.Separator)) ||
			strings.HasPrefix(path, filepath.Join("store", "storetest")) { // the adapter conformance suite

			return nil
		}
		src, err := os.ReadFile(path)
		if err == nil && direct.Match(src) {
			t.Errorf("%s writes auth_users directly; call Identity().InsertUser so the host's hook runs", path)
		}
		return err
	})
	ok(t, err)
}
