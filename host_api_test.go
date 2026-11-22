package polaris_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/polaristest"
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

// A Store.Tx is the host's transaction: Polaris's writes, the hook's and the host's own commit
// or roll back together, and the events (with the mail they send) wait for the commit.
func TestStoreTxDefersEventsUntilCommit(t *testing.T) {
	ctx := context.Background()
	var db *sqlstore.Store
	srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) {
		db = c.DB.(*sqlstore.Store)
		c.Hooks.OnUserCreated = func(ctx context.Context, u polaris.User) error {
			_, err := db.Conn(ctx).ExecContext(ctx, "INSERT INTO app_profiles (user_id) VALUES ("+placeholder(db)+")", u.ID)
			return err
		}
	}))
	_, err := db.Conn(ctx).ExecContext(ctx, "CREATE TABLE app_profiles (user_id VARCHAR(36) PRIMARY KEY)")
	ok(t, err)
	profiles := func() int {
		var n int
		ok(t, db.Conn(ctx).QueryRowContext(ctx, "SELECT COUNT(*) FROM app_profiles").Scan(&n))
		return n
	}
	quiet := func(when string) {
		t.Helper()
		if len(srv.Events.All()) != 0 || len(srv.Mailer.Sent()) != 0 {
			t.Fatalf("%s: events %v, %d mails", when, srv.Events.Names(), len(srv.Mailer.Sent()))
		}
	}

	refuse := errors.New("the host's own rule")
	err = db.Tx(ctx, func(ctx context.Context) error {
		_, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com"}) // unverified: a verification mail
		ok(t, err)
		quiet("inside the transaction")
		return refuse
	})
	is(t, err, refuse, "the host's rollback")
	quiet("after the rollback")
	if _, err := srv.Users().ByEmail(ctx, "ada@example.com"); !errors.Is(err, polaris.ErrNotFound) || profiles() != 0 {
		t.Fatalf("after the rollback: %v, %d profiles", err, profiles())
	}

	ok(t, db.Tx(ctx, func(ctx context.Context) error {
		ada, err := srv.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com"})
		if err != nil {
			return err
		}
		_, err = srv.Orgs().Create(ctx, ada.ID, "Acme", "")
		quiet("inside the transaction")
		return err
	}))
	if names := srv.Events.Names(); !slices.Equal(names, []string{"user.registered", "org.created"}) || len(srv.Mailer.Sent()) != 1 || profiles() != 1 {
		t.Fatalf("after the commit: events %v, %d mails, %d profiles", names, len(srv.Mailer.Sent()), profiles())
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
