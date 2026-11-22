package polaris_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// principalOf answers the principal Protect resolves for an access token.
func principalOf(t *testing.T, p *polaris.Polaris, access string) polaris.Principal {
	t.Helper()
	var who polaris.Principal
	h := p.Protect(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { who, _ = polaris.PrincipalFrom(r.Context()) }))
	r := httptest.NewRequest(http.MethodGet, "/api", nil)
	r.Header.Set("Authorization", "Bearer "+access)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("Protect answered %d", w.Code)
	}
	return who
}

func TestIssueScopesTheSessionToAnOrganization(t *testing.T) {
	ctx := context.Background()
	srv := polaristest.New(t)
	ada, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
	ok(t, err)
	bob, err := srv.Users().Create(ctx, polaris.NewUser{Email: "bob@example.com", EmailVerified: true})
	ok(t, err)
	org, err := srv.Orgs().Create(ctx, ada.ID, "Acme", "")
	ok(t, err)

	tokens, err := srv.Sessions().Issue(ctx, polaris.SignIn{UserID: ada.ID, OrganizationID: org.ID})
	ok(t, err)
	who := principalOf(t, srv.Polaris, tokens.AccessToken)
	if who.OrganizationID != org.ID || !slices.Contains(who.Roles, "owner") || !slices.Contains(who.Permissions, "org.read") {
		t.Fatalf("scoped session: %+v", who)
	}
	refreshed, err := srv.Sessions().Refresh(ctx, tokens.RefreshToken)
	ok(t, err)
	if got := principalOf(t, srv.Polaris, refreshed.AccessToken); got.OrganizationID != org.ID {
		t.Fatalf("a refresh leaves the organization: %+v", got)
	}
	if names := srv.Events.Names(); !slices.Contains(names, "user.logged_in") || !slices.Contains(names, "auth.org_switched") {
		t.Fatalf("events %v: a sign-in and a switch, as over HTTP", names)
	}

	_, err = srv.Sessions().Issue(ctx, polaris.SignIn{UserID: bob.ID, OrganizationID: org.ID})
	is(t, err, polaris.ErrForbidden, "a non-member")
	_, err = srv.Sessions().Issue(ctx, polaris.SignIn{UserID: bob.ID, OrganizationID: "no-such-org"})
	is(t, err, polaris.ErrNotFound, "an unknown organization")
	ok(t, srv.Orgs().AddMember(ctx, org.ID, bob.ID, "member"))
	tokens, err = srv.Sessions().Issue(ctx, polaris.SignIn{UserID: bob.ID, OrganizationID: org.ID})
	ok(t, err)
	if who := principalOf(t, srv.Polaris, tokens.AccessToken); who.OrganizationID != org.ID || slices.Contains(who.Permissions, "members.update") {
		t.Fatalf("a member's scoped session: %+v", who)
	}
}

func TestIssueNamesTheUnverifiedEmail(t *testing.T) {
	ctx := context.Background()
	srv := polaristest.New(t) // config.Defaults requires a verified email to sign in
	carol, err := srv.Users().Create(ctx, polaris.NewUser{Email: "carol@example.com"})
	ok(t, err)
	_, err = srv.Sessions().Issue(ctx, polaris.SignIn{UserID: carol.ID})
	is(t, err, polaris.ErrEmailNotVerified, "an unverified account")
	is(t, err, polaris.ErrForbidden, "an unverified account")

	dave, err := srv.Users().Create(ctx, polaris.NewUser{Email: "dave@example.com", EmailVerified: true})
	ok(t, err)
	ok(t, srv.Users().Disable(ctx, dave.ID))
	_, err = srv.Sessions().Issue(ctx, polaris.SignIn{UserID: dave.ID})
	if is(t, err, polaris.ErrForbidden, "a disabled account"); errors.Is(err, polaris.ErrEmailNotVerified) {
		t.Fatal("a disabled account is not an unverified one")
	}
}

func TestOrgsInviteHandsTheHostTheToken(t *testing.T) {
	ctx := context.Background()
	srv := polaristest.New(t)
	ada, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", EmailVerified: true})
	ok(t, err)
	org, err := srv.Orgs().Create(ctx, ada.ID, "Acme", "")
	ok(t, err)

	inv, token, err := srv.Orgs().Invite(ctx, org.ID, ada.ID, " Bob@Example.com", "admin")
	ok(t, err)
	if inv.ID == "" || inv.OrganizationID != org.ID || inv.Email != "bob@example.com" || !slices.Equal(inv.Roles, []string{"admin"}) ||
		inv.InvitedBy != ada.ID || !inv.ExpiresAt.After(time.Now()) || token == "" {
		t.Fatalf("invitation %+v, token %q", inv, token)
	}
	if !slices.Contains(srv.Events.Names(), "member.invited") {
		t.Fatalf("events %v", srv.Events.Names())
	}
	if sent := srv.Mailer.Sent(); len(sent) != 1 || sent[0].Template != notify.TemplateOrgInvite {
		t.Fatalf("the configured mailer delivers it too, as for the route: %+v", sent)
	}

	// The invitee accepts with the token over HTTP and holds the invited roles.
	bob, err := srv.Users().Create(ctx, polaris.NewUser{Email: "bob@example.com", EmailVerified: true})
	ok(t, err)
	session, err := srv.Sessions().Issue(ctx, polaris.SignIn{UserID: bob.ID})
	ok(t, err)
	c := contracttest.NewClient(t, srv.Handler(), nil)
	if r := c.Post("/auth/invites/accept", map[string]any{"token": token}, contracttest.Bearer(session.AccessToken)); r.StatusCode != http.StatusOK {
		t.Fatalf("accept: %d", r.StatusCode)
	}
	if !srv.Can(ctx, polaris.Principal{UserID: bob.ID, OrganizationID: org.ID}, "members.update") {
		t.Fatal("bob is not an admin")
	}

	carol, err := srv.Users().Create(ctx, polaris.NewUser{Email: "carol@example.com", EmailVerified: true})
	ok(t, err)
	ok(t, srv.Orgs().AddMember(ctx, org.ID, carol.ID, "member"))
	_, _, err = srv.Orgs().Invite(ctx, org.ID, ada.ID, "bob@example.com", "member")
	is(t, err, polaris.ErrConflict, "an active member")
	_, _, err = srv.Orgs().Invite(ctx, org.ID, ada.ID, "dan@example.com", "nope")
	is(t, err, polaris.ErrInvalidInput, "an unknown role")
	_, _, err = srv.Orgs().Invite(ctx, org.ID, ada.ID, "dan@example.com")
	is(t, err, polaris.ErrInvalidInput, "no role")
	_, _, err = srv.Orgs().Invite(ctx, org.ID, ada.ID, "not-an-email", "member")
	is(t, err, polaris.ErrInvalidInput, "a bad email")
	_, _, err = srv.Orgs().Invite(ctx, org.ID, carol.ID, "dan@example.com", "owner")
	is(t, err, polaris.ErrForbidden, "roles beyond the inviter's authority")
	_, _, err = srv.Orgs().Invite(ctx, "no-such-org", ada.ID, "dan@example.com", "member")
	is(t, err, polaris.ErrNotFound, "an unknown organization")
}

// A Store.Tx is the host's transaction, and event delivery has two phases. Listeners that write
// to the store (the audit recorder, the erasure listeners, Config.TxListeners) run inside it and
// commit or roll back with it; the others (the mail, Config.Listeners) run after the commit and
// never after a rollback.
func TestStoreTxDeliversEventsInTwoPhases(t *testing.T) {
	ctx := context.Background()
	var db *sqlstore.Store
	var mu sync.Mutex
	var deferred []string
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{})), polaristest.WithConfig(func(c *polaris.Config) {
		db = c.DB.(*sqlstore.Store)
		c.TxListeners = []event.Listener{func(ctx context.Context, e event.Event) {
			_, err := db.Conn(ctx).ExecContext(ctx, "INSERT INTO app_log (name) VALUES ("+placeholder(db)+")", e.EventName())
			ok(t, err)
		}}
		c.Listeners = []event.Listener{func(_ context.Context, e event.Event) {
			mu.Lock()
			defer mu.Unlock()
			deferred = append(deferred, e.EventName())
		}}
	}))
	_, err := db.Conn(ctx).ExecContext(ctx, "CREATE TABLE app_log (name VARCHAR(64) NOT NULL)")
	ok(t, err)
	count := func(ctx context.Context, table string, c store.Criteria) int64 {
		t.Helper()
		n, err := db.Count(ctx, table, c)
		ok(t, err)
		return n
	}
	ran := func(name string) bool {
		mu.Lock()
		defer mu.Unlock()
		return slices.Contains(deferred, name)
	}
	refuse := errors.New("the host's own rule")

	// A signup: the audit row and the host's TxListener row follow the transaction; the
	// verification mail and the host's Listener wait for the commit.
	err = db.Tx(ctx, func(ctx context.Context) error {
		_, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com"}) // unverified: a verification mail
		ok(t, err)
		if count(ctx, audit.TableEvents, store.Criteria{"name": audit.UserSignedUp}) != 1 || count(ctx, "app_log", nil) != 1 {
			t.Fatal("inside the transaction: the transactional listeners have not run")
		}
		if ran("user.registered") || len(srv.Mailer.Sent()) != 0 {
			t.Fatal("inside the transaction: a deferred listener ran")
		}
		return refuse
	})
	is(t, err, refuse, "the host's rollback")
	if count(ctx, audit.TableEvents, store.Criteria{"name": audit.UserSignedUp}) != 0 || count(ctx, "app_log", nil) != 0 || ran("user.registered") || len(srv.Mailer.Sent()) != 0 {
		t.Fatal("after the rollback: an audit row, a host row, a listener or a mail survived")
	}
	ok(t, db.Tx(ctx, func(ctx context.Context) error {
		_, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com"})
		return err
	}))
	if count(ctx, audit.TableEvents, store.Criteria{"name": audit.UserSignedUp}) != 1 || count(ctx, "app_log", nil) != 1 || !ran("user.registered") || len(srv.Mailer.Sent()) != 1 {
		t.Fatal("after the commit: every listener ran once and the mail went out")
	}

	// An erasure: the audit plugin's erasure listener deletes the user's activity row inside the
	// erasing transaction.
	bob, err := srv.Users().Create(ctx, polaris.NewUser{Email: "bob@example.com", EmailVerified: true})
	ok(t, err)
	_, err = srv.Sessions().Issue(ctx, polaris.SignIn{UserID: bob.ID}) // records bob's activity
	ok(t, err)
	activity := func(ctx context.Context) int64 {
		return count(ctx, audit.TableActivity, store.Criteria{"user_id": bob.ID})
	}
	if activity(ctx) != 1 {
		t.Fatal("no activity row to erase")
	}
	err = db.Tx(ctx, func(ctx context.Context) error {
		ok(t, srv.Users().Delete(ctx, bob.ID))
		if activity(ctx) != 0 {
			t.Fatal("inside the erasing transaction: the activity row is still there")
		}
		return refuse
	})
	is(t, err, refuse, "the host's rollback")
	if activity(ctx) != 1 || count(ctx, audit.TableEvents, store.Criteria{"name": audit.UserDeleted}) != 0 || ran("user.deleted") {
		t.Fatal("after the rollback: the erasure, its audit row or its listener survived")
	}
	ok(t, db.Tx(ctx, func(ctx context.Context) error { return srv.Users().Delete(ctx, bob.ID) }))
	if activity(ctx) != 0 || count(ctx, audit.TableEvents, store.Criteria{"name": audit.UserDeleted}) != 1 || !ran("user.deleted") {
		t.Fatal("after the commit: the erasure and its audit row are kept, the listener ran")
	}
}

func TestWrapRunsTheMiddlewareAroundAHostHandler(t *testing.T) {
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
		c.Middleware = []func(http.Handler) http.Handler{mark("outer"), mark("inner")}
	}))
	h := srv.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { order = append(order, "host") }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/health", nil))
	if !slices.Equal(order, []string{"outer", "inner", "host"}) {
		t.Fatalf("order %v", order)
	}
}

func TestDevEnvRefusesWithoutTheDevFlag(t *testing.T) {
	for _, name := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_ISSUER", polaris.EnvDev} {
		t.Setenv(name, "")
	}
	err := polaris.DevEnv("http://localhost:8080")
	if err == nil || !strings.Contains(err.Error(), polaris.EnvDev+"=1") {
		t.Fatalf("without %s: %v", polaris.EnvDev, err)
	}
	if os.Getenv("APP_KEY") != "" {
		t.Fatal("a refused DevEnv set APP_KEY")
	}

	t.Setenv(polaris.EnvDev, "1")
	t.Setenv("APP_KEY", "an-application-key-of-32-bytes!!") // a value already set is kept
	ok(t, polaris.DevEnv("http://localhost:8080"))
	if os.Getenv("APP_KEY") != "an-application-key-of-32-bytes!!" || os.Getenv("AUTH_ISSUER") != "http://localhost:8080" {
		t.Fatalf("APP_KEY %q, AUTH_ISSUER %q", os.Getenv("APP_KEY"), os.Getenv("AUTH_ISSUER"))
	}
	cfg, err := polaris.FromEnv(nil)
	ok(t, err)
	if cfg.Auth.Issuer != "http://localhost:8080" || cfg.Secrets.JWTPrivateKey == "" {
		t.Fatalf("FromEnv after DevEnv: issuer %q", cfg.Auth.Issuer)
	}
}
