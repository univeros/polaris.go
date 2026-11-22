package admin_test

import (
	"context"
	"errors"
	"github.com/univeros/polaris.go/internal/services"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/token"
)

var now = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)

type env struct {
	p     *polaris.Polaris
	admin *admin.Plugin
	trail *audit.Plugin
	clk   *clock.Frozen
	db    *memstore.Store
}

func boot(t *testing.T, edit ...func(*config.Auth)) env {
	t.Helper()
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	for _, f := range edit {
		f(&auth)
	}
	e := env{admin: admin.New(admin.Config{}), trail: audit.New(audit.Config{}), clk: clock.NewFrozen(now)}
	e.db = memstore.New(slices.Concat(schema.Core(), audit.Models(), admin.Models())...)
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: e.db, Clock: e.clk, Plugins: []polaris.Plugin{e.admin, e.trail}, // any order
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := authz.Seed(context.Background(), e.db, services.Of(p.Graph()).Catalog, e.clk); err != nil {
		t.Fatal(err)
	}
	e.p = p
	return e
}

func (e env) user(t *testing.T, id string) model.User {
	t.Helper()
	u := model.User{ID: id, Email: id + "@example.com", Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := e.p.Graph().Repos().Users.Insert(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

func (e env) session(t *testing.T, userID string, extra token.Claims) string {
	t.Helper()
	raw, err := e.p.Graph().Sessions().Mint(context.Background(), token.SessionPrincipal{UserID: userID}, "sid-1", extra)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestEverythingIsWiredThroughTheGraph(t *testing.T) {
	e := boot(t)
	g := e.p.Graph()
	if admin.Of(g) != e.admin || len(g.Schema()) != len(schema.Core())+6 {
		t.Fatalf("plugin or schema (%d tables): core, audit's four and the two admin tables", len(g.Schema()))
	}
	routes := 0
	for _, r := range g.Manifest().Routes() {
		if !slices.Contains(r.Tags, admin.Tag) {
			continue
		}
		routes++
		if r.Auth != manifest.AuthPublic || !strings.HasPrefix(r.Path, "/admin/") || r.Plugin != admin.ID {
			t.Errorf("%s: auth %s path %s: the bearer is left to the admin middleware", r.Name, r.Auth, r.Path)
		}
	}
	if routes != 29 {
		t.Fatalf("%d admin routes, want 29", routes)
	}
	if !e.trail.Catalog().Has(admin.AuditUserBanned) || len(g.Listeners()) != 7 {
		t.Fatalf("the admin names joined the catalog; core's three, audit's three and the grant erasure (%d)", len(g.Listeners()))
	}
}

func TestTheAuditPluginIsRequired(t *testing.T) {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	_, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: memstore.New(), Plugins: []polaris.Plugin{admin.New(admin.Config{})},
	})
	if err == nil || !strings.Contains(err.Error(), "audit.New(audit.Config{})") {
		t.Fatalf("%v", err)
	}
}

func TestKeysAuthenticateByHashExpiryAndAllowlist(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	keys := e.admin.Keys()
	expires := now.Add(time.Hour)
	key, secret, err := keys.Create(ctx, admin.Key{Name: "Dashboard", Role: admin.RoleSupport, IPAllowlist: []string{"10.0.0.0/8"}, ExpiresAt: &expires, CreatedBy: "cli"})
	if err != nil || !strings.HasPrefix(secret, admin.KeyPrefix) || len(secret) != 47 || key.Scope != admin.ScopeInstance {
		t.Fatalf("%+v %q %v", key, secret, err)
	}
	if _, has := key.Map()["key_hash"]; has {
		t.Fatal("the hash never leaves")
	}
	stored, _ := e.db.FindOne(ctx, admin.TableKeys, store.Criteria{"id": key.ID})
	if stored.String("ip_allowlist") != `["10.0.0.0/8"]` || stored.String("key_hash") == secret {
		t.Fatalf("stored form: %v", stored)
	}

	got, ok, err := keys.Authenticate(ctx, secret, "10.1.2.3")
	if !ok || err != nil || got.ID != key.ID {
		t.Fatalf("%+v %v %v", got, ok, err)
	}
	if found, _, _ := keys.Find(ctx, key.ID); found.LastUsedAt == nil || !found.LastUsedAt.Equal(now) {
		t.Fatalf("last use stamped: %+v", found)
	}
	for _, c := range []struct{ secret, ip, why string }{
		{secret, "192.168.1.1", "outside the allowlist"},
		{secret, "", "no address, non-empty allowlist"},
		{admin.KeyPrefix + "nope", "10.1.2.3", "unknown"},
		{"not-a-key", "10.1.2.3", "not a key"},
	} {
		if _, ok, _ := keys.Authenticate(ctx, c.secret, c.ip); ok {
			t.Error(c.why)
		}
	}
	e.clk.Advance(2 * time.Hour)
	if _, ok, _ := keys.Authenticate(ctx, secret, "10.1.2.3"); ok {
		t.Error("expired")
	}
	if deleted, _ := keys.Delete(ctx, key.ID); !deleted {
		t.Fatal("delete")
	}
	if deleted, _ := keys.Delete(ctx, key.ID); deleted {
		t.Fatal("deleted twice")
	}
	if all, _ := keys.All(ctx); len(all) != 0 {
		t.Fatal(all)
	}
	for _, bad := range []admin.Key{{Name: "", Role: admin.RoleOwner}, {Name: "x", Role: "root"}, {Name: "x", Role: admin.RoleViewer, IPAllowlist: []string{"nowhere"}}} {
		if _, _, err := keys.Create(ctx, bad); !errors.Is(err, admin.ErrInvalid) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

// Rows written by earlier releases hold the allowlist with escaped slashes ("10.0.0.0\/8"); they
// keep reading and authenticating.
func TestAKeyStoredWithEscapedSlashesStillReads(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	keys := e.admin.Keys()
	key, secret, err := keys.Create(ctx, admin.Key{Name: "old", Role: admin.RoleSupport, IPAllowlist: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Update(ctx, admin.TableKeys, store.Criteria{"id": key.ID}, store.Data{"ip_allowlist": `["10.0.0.0\/8"]`}); err != nil {
		t.Fatal(err)
	}
	found, ok, err := keys.Find(ctx, key.ID)
	if !ok || err != nil || !slices.Equal(found.IPAllowlist, []string{"10.0.0.0/8"}) {
		t.Fatalf("%+v %v %v", found, ok, err)
	}
	if _, ok, _ := keys.Authenticate(ctx, secret, "10.1.2.3"); !ok {
		t.Fatal("an old row authenticates inside its allowlist")
	}
	if _, ok, _ := keys.Authenticate(ctx, secret, "192.168.1.1"); ok {
		t.Fatal("an old row refuses outside its allowlist")
	}
}

func TestGrantsAreOnePerUserAndLapse(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	grants := e.admin.Grants()
	first, err := grants.Grant(ctx, admin.Grant{UserID: "u1", Role: admin.RoleViewer})
	if err != nil {
		t.Fatal(err)
	}
	until := now.Add(14 * time.Hour)
	second, err := grants.Grant(ctx, admin.Grant{UserID: "u1", Role: admin.RoleAdmin, Scope: "org-a", ExpiresAt: &until, GrantedBy: "k1"})
	if err != nil || second.ID != first.ID || second.Role != admin.RoleAdmin || second.Scope != "org-a" || second.GrantedBy != "k1" {
		t.Fatalf("a new grant replaces the previous one: %+v %v", second, err)
	}
	if all, _ := grants.All(ctx); len(all) != 1 {
		t.Fatal(all)
	}
	if g, ok, _ := grants.For(ctx, "u1"); !ok || g.Role != admin.RoleAdmin {
		t.Fatal(g)
	}
	e.clk.Advance(24 * time.Hour)
	if _, ok, _ := grants.For(ctx, "u1"); ok {
		t.Fatal("lapsed")
	}
	if _, ok, _ := grants.Find(ctx, first.ID); !ok {
		t.Fatal("still listed until revoked")
	}
	if revoked, _ := grants.Revoke(ctx, first.ID); !revoked {
		t.Fatal("revoke")
	}
	if all, _ := grants.All(ctx); len(all) != 0 {
		t.Fatal(all)
	}
	if _, err := grants.Grant(ctx, admin.Grant{UserID: "u1", Role: "root"}); !errors.Is(err, admin.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestPrincipalsResolveKeysGrantsAndRefuseImpersonationTokens(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	u := e.user(t, "u1")
	session := e.session(t, "u1", token.Claims{})
	resolve := func(bearer string) admin.Resolution {
		t.Helper()
		res, err := e.admin.Resolve(ctx, bearer, "127.0.0.1")
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	for _, bearer := range []string{"", "garbage", session} {
		if resolve(bearer).Principal != nil {
			t.Errorf("%.20q is no operator", bearer)
		}
	}
	if _, err := e.admin.Grants().Grant(ctx, admin.Grant{UserID: "u1", Role: admin.RoleSupport, Scope: "org-a"}); err != nil {
		t.Fatal(err)
	}
	if p := resolve(session).Principal; p == nil || *p != (admin.Principal{ID: "u1", Type: admin.TypeUser, Role: admin.RoleSupport, Scope: "org-a"}) {
		t.Fatalf("%+v", p)
	}
	_, secret, _ := e.admin.Keys().Create(ctx, admin.Key{Name: "ci", Role: admin.RoleViewer})
	if p := resolve(secret).Principal; p == nil || p.Type != admin.TypeAPIKey {
		t.Fatalf("%+v", p)
	}
	impersonation := e.session(t, "u1", token.Claims{}.With(admin.ClaimImpersonatedBy, "k1"))
	if res := resolve(impersonation); res.Principal != nil || !res.Impersonated {
		t.Fatalf("%+v", res)
	}
	disabled := u
	disabled.Status = model.UserStatusDisabled
	if err := e.p.Graph().Repos().Users.Update(ctx, u, disabled); err != nil {
		t.Fatal(err)
	}
	if resolve(session).Principal != nil {
		t.Fatal("a disabled operator is no operator")
	}
}

func TestADenylistedSessionIsNoOperator(t *testing.T) {
	e := boot(t, func(a *config.Auth) { a.AccessToken.Denylist = true })
	ctx := context.Background()
	e.user(t, "u1")
	if _, err := e.admin.Grants().Grant(ctx, admin.Grant{UserID: "u1", Role: admin.RoleOwner}); err != nil {
		t.Fatal(err)
	}
	session := e.session(t, "u1", token.Claims{})
	if res, _ := e.admin.Resolve(ctx, session, ""); res.Principal == nil {
		t.Fatal("a live session")
	}
	e.clk.Advance(time.Second)
	if _, err := e.p.Graph().Sessions().RevokeAll(ctx, "u1", model.RevokedLogout); err != nil {
		t.Fatal(err)
	}
	if res, _ := e.admin.Resolve(ctx, session, ""); res.Principal != nil {
		t.Fatal("logout-everywhere ends the operator's access token too")
	}
}

func TestAKeyIsRecordedAsAnAPIKeyActor(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	e.user(t, "u1")
	_, secret, _ := e.admin.Keys().Create(ctx, admin.Key{Name: "ci", Role: admin.RoleAdmin})
	req := httptest.NewRequest(http.MethodPost, "/admin/users/u1/ban", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("User-Agent", "ops-dashboard")
	rec := httptest.NewRecorder()
	e.p.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	page, err := e.trail.Store().Read(ctx, audit.Query{Names: []string{admin.AuditUserBanned}})
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("%+v %v", page, err)
	}
	ev := page.Events[0]
	if ev.ActorType != audit.ActorAPIKey || ev.SubjectID != "u1" || ev.UserAgent != "ops-dashboard" || ev.Data["actor_role"] != "admin" {
		t.Fatalf("%+v", ev)
	}
}

func TestEndpointEdgeCases(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	e.user(t, "u1")
	_, owner, _ := e.admin.Keys().Create(ctx, admin.Key{Name: "ops", Role: admin.RoleOwner})
	c := contracttest.NewClient(t, e.p.Handler(), nil)
	as := contracttest.Bearer(owner)
	for _, tc := range []struct {
		method, path string
		body         any
		status       int
		code         string
	}{
		{"GET", "/admin/users?limit=0", nil, 422, "admin_invalid_input"},
		{"GET", "/admin/users?limit=many", nil, 422, "admin_invalid_input"},
		{"GET", "/admin/organizations?limit=-1", nil, 422, "admin_invalid_input"},
		{"GET", "/admin/users?limit=1.5", nil, 422, "admin_invalid_input"},
		{"GET", "/admin/users?limit=1e1", nil, 422, "admin_invalid_input"},
		{"GET", "/admin/users?limit=%202", nil, 422, "admin_invalid_input"},
		{"GET", "/admin/organizations?limit=+2", nil, 422, "admin_invalid_input"},
		{"GET", "/admin/audit?limit=2.0", nil, 422, "audit_invalid_query"},
		{"GET", "/admin/audit?from=yesterday", nil, 422, "audit_invalid_query"},
		{"GET", "/admin/audit?limit=", nil, 422, "audit_invalid_query"},
		{"POST", "/admin/users/u1/password", map[string]any{}, 422, "admin_invalid_input"},
		{"POST", "/admin/users/nobody/password", map[string]any{"password": "long enough passphrase"}, 404, "admin_not_found"},
		{"POST", "/admin/users/nobody/ban", nil, 404, "admin_not_found"},
		{"POST", "/admin/users/nobody/unban", nil, 404, "admin_not_found"},
		{"DELETE", "/admin/users/nobody", nil, 404, "admin_not_found"},
		{"POST", "/admin/users/nobody/impersonate", nil, 404, "admin_not_found"},
		{"DELETE", "/admin/users/nobody/mfa", nil, 404, "admin_not_found"},
		{"DELETE", "/admin/users/nobody/sessions", nil, 404, "admin_not_found"},
		{"GET", "/admin/users/nobody/mfa", nil, 404, "admin_not_found"},
		{"DELETE", "/admin/keys/nope", nil, 404, "admin_not_found"},
		{"POST", "/admin/grants", map[string]any{"role": "viewer"}, 422, "admin_invalid_input"},
		{"POST", "/admin/grants", map[string]any{"user_id": "u1", "role": "viewer", "expires_at": "soon"}, 422, "admin_invalid_input"},
		{"POST", "/admin/grants", map[string]any{"user_id": "u1", "role": "viewer", "scope": "no-such-org"}, 422, "admin_invalid_input"},
		{"POST", "/admin/organizations/nope/drains", map[string]any{"endpoint": "https://x.test", "secret": "sixteen chars ok", "filter": "org.*"}, 422, "admin_invalid_input"},
		{"GET", "/admin/organizations/nope/drains", nil, 404, "admin_not_found"},
		{"POST", "/admin/organizations/nope/drains/d1/test", nil, 404, "admin_not_found"},
		{"DELETE", "/admin/organizations/nope", nil, 404, "admin_not_found"},
		{"PATCH", "/admin/organizations/nope/members/u1/roles", map[string]any{"roles": []string{"admin"}}, 404, "admin_not_found"},
		{"PATCH", "/admin/organizations/nope/members/u1/roles", map[string]any{"roles": []any{""}}, 422, "admin_invalid_input"},
	} {
		resp := c.JSONRequest(tc.method, tc.path, tc.body, as)
		if b := contracttest.JSON(t, resp); resp.StatusCode != tc.status || b["error"] != tc.code {
			t.Errorf("%s %s: %d %v", tc.method, tc.path, resp.StatusCode, b)
		}
	}

	locked := e.user(t, "u2")
	next := locked
	next.Status = model.UserStatusLocked
	_ = e.p.Graph().Repos().Users.Update(ctx, locked, next)
	if resp := c.Post("/admin/users/u2/impersonate", nil, as); resp.StatusCode != http.StatusConflict {
		t.Fatalf("a locked account is not impersonated: %d", resp.StatusCode)
	}
	if resp := c.Get("/admin/users?status=locked", as); len(contracttest.JSON(t, resp)["data"].([]any)) != 1 {
		t.Fatal("status filter")
	}
	if resp := c.Post("/admin/grants", map[string]any{"user_id": "u1", "role": "viewer", "expires_at": "2030-01-01T00:00:00+02:00"}, as); contracttest.JSON(t, resp)["data"].(map[string]any)["expires_at"] != "2029-12-31T22:00:00Z" {
		t.Fatal("a time given with an offset is answered in UTC")
	}
}

func TestOperatorHooksForOtherPlugins(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	e.user(t, "u1")
	if _, err := e.admin.Grants().Grant(ctx, admin.Grant{UserID: "u1", Role: admin.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	session := e.session(t, "u1", token.Claims{})
	_, secret, _ := e.admin.Keys().Create(ctx, admin.Key{Name: "ci", Role: admin.RoleViewer})
	_, office, _ := e.admin.Keys().Create(ctx, admin.Key{Name: "office", Role: admin.RoleOwner, IPAllowlist: []string{"203.0.113.0/24"}})
	impersonation := e.session(t, "u1", token.Claims{}.With(admin.ClaimImpersonatedBy, "k1"))
	for credential, want := range map[string]bool{session: true, secret: true, office: false, impersonation: false, "": false, "pak_nope": false} {
		if got, err := e.admin.IsOperator(ctx, credential); err != nil || got != want {
			t.Errorf("%.24q: %v %v", credential, got, err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/clients", nil)
	req.RemoteAddr = "203.0.113.9:4000"
	req.Header.Set("Authorization", "Bearer "+office)
	if op, ok, err := e.admin.OperatorOf(req); err != nil || !ok || op.Role != admin.RoleOwner || !op.Allows(admin.Own) {
		t.Fatalf("%+v %v %v: the request's address passes the allowlist", op, ok, err)
	}
	req.Header.Del("Authorization")
	if _, ok, _ := e.admin.OperatorOf(req); ok {
		t.Fatal("no credential, no operator")
	}
}

// operatorAuthorizer is how agents and oauth reach the check without importing this package.
type operatorAuthorizer interface {
	AuthorizeOperator(ctx context.Context, capability, organizationID string) (string, endpoint.Result, bool)
}

func TestAuthorizeOperatorThroughTheGraph(t *testing.T) {
	e := boot(t)
	ctx := context.Background()
	e.user(t, "u1")
	if _, err := e.admin.Grants().Grant(ctx, admin.Grant{UserID: "u1", Role: admin.RoleAdmin}); err != nil {
		t.Fatal(err)
	}
	_, secret, _ := e.admin.Keys().Create(ctx, admin.Key{Name: "ci", Role: admin.RoleOwner})
	authorizer, ok := e.p.Graph().Plugin("admin").(operatorAuthorizer)
	if !ok {
		t.Fatal("the plugin does not expose AuthorizeOperator")
	}
	// The middleware resolves the operator on any route tagged admin; run a request through it.
	var userID string
	var refusal endpoint.Result
	var allowed bool
	probe := func(bearer, capability string) {
		t.Helper()
		mw := e.admin.Middleware(nil)[0]
		h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			userID, refusal, allowed = authorizer.AuthorizeOperator(r.Context(), capability, "")
		}))
		req := httptest.NewRequest(http.MethodPost, "/admin/agents/a1/revoke", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		req = req.WithContext(endpoint.WithRoute(req.Context(), &manifest.Route{Tags: []string{"admin", "agents"}}))
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	probe(e.session(t, "u1", token.Claims{}), "manage")
	if !allowed || userID != "u1" {
		t.Fatalf("a user operator: %q %v", userID, allowed)
	}
	probe(e.session(t, "u1", token.Claims{}), "own")
	if allowed || refusal.Status != http.StatusForbidden {
		t.Fatalf("an admin cannot own: %+v", refusal)
	}
	probe(secret, "own")
	if !allowed || userID != "" {
		t.Fatalf("a key operator has no user id: %q %v", userID, allowed)
	}
	probe("garbage", "read")
	if allowed || refusal.Status != http.StatusUnauthorized {
		t.Fatalf("nobody: %+v", refusal)
	}
}
