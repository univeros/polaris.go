package admin_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

func boundsFlow(t *testing.T) *flow {
	t.Helper()
	f := &flow{t: t, admin: admin.New(admin.Config{})}
	f.srv = polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), f.admin))
	f.c = contracttest.NewClient(t, f.srv.Handler(), nil)
	return f
}

func (f *flow) grant(email string, role admin.Role, scope string) string {
	f.t.Helper()
	f.login(email)
	if _, err := f.admin.Grants().Grant(context.Background(), admin.Grant{UserID: f.userID(email), Role: role, Scope: scope}); err != nil {
		f.t.Fatal(err)
	}
	return f.userID(email)
}

// makeSuperadmin links the user's membership to core's system superadmin role.
func (f *flow) makeSuperadmin(email, access string) {
	f.t.Helper()
	ctx := context.Background()
	f.createOrg("Root", access)
	membership, _ := f.srv.DB.FindOne(ctx, "auth_memberships", store.Criteria{"user_id": f.userID(email)})
	role, _ := f.srv.DB.FindOne(ctx, "auth_roles", store.Criteria{"slug": "superadmin", "organization_id": nil})
	if err := f.srv.DB.Insert(ctx, "auth_membership_roles", store.Row{"membership_id": membership.String("id"), "role_id": role.String("id")}); err != nil {
		f.t.Fatal(err)
	}
}

// Impersonation follows the reach rule of decision 69, and its token reads as the user without
// being the account holder (decision 76).
func TestImpersonationDoesNotReachUpNorActAsTheAccountHolder(t *testing.T) {
	f := boundsFlow(t)
	ownerID := f.grant("owner@example.com", admin.RoleOwner, "")
	peerID := f.grant("peer@example.com", admin.RoleAdmin, "")
	f.login("ada@example.com")
	adaID := f.userID("ada@example.com")

	adminUser := f.operator(admin.RoleAdmin, "")
	for caller, credential := range map[string]string{"an admin key": f.key(admin.RoleAdmin, "", nil), "an admin user": adminUser} {
		for target, id := range map[string]string{"an owner": ownerID, "another admin": peerID} {
			resp := f.c.Post("/admin/users/"+id+"/impersonate", nil, as(credential))
			if resp.StatusCode != http.StatusForbidden || body(t, resp)["error"] != "admin_forbidden" {
				t.Errorf("%s impersonates %s: status %d, want 403 admin_forbidden", caller, target, resp.StatusCode)
			}
		}
	}

	resp := f.c.Post("/admin/users/"+adaID+"/impersonate", nil, as(adminUser))
	wantStatus(t, resp, http.StatusCreated)
	access, _ := data(t, resp)["access_token"].(string)
	tok, err := f.srv.Graph().Tokens().Parse(access)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Claim("auth_time") != nil {
		t.Errorf("an impersonation token carries auth_time %v: it is not a recent authentication", tok.Claim("auth_time"))
	}
	if tok.ImpersonatedBy() != f.userID(operator) {
		t.Errorf("impersonated_by %q", tok.ImpersonatedBy())
	}
	wantStatus(t, f.c.Get("/auth/me", as(access)), http.StatusOK)
	writes := map[string]*http.Response{
		"enrol a factor":         f.c.Post("/auth/mfa/totp/enroll", nil, as(access)),
		"create an organization": f.c.Post("/orgs", map[string]any{"name": "Mine"}, as(access)),
		"change the password":    f.c.Post("/auth/password/change", map[string]any{"current_password": password, "new_password": "another long passphrase"}, as(access)),
		"end every session":      f.c.Post("/auth/logout-all", nil, as(access)),
	}
	for name, resp := range writes {
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("an impersonation token may not %s: status %d, want 403", name, resp.StatusCode)
		}
	}
}

// An operator grant is replaced only by an operator whose scope covers the grant already there,
// and a superadmin's only by an instance owner (decision 76).
func TestAGrantIsReplacedOnlyFromWithinTheCallersScope(t *testing.T) {
	ctx := context.Background()
	f := boundsFlow(t)
	founder := f.login("founder@example.com")
	orgA, orgB := f.createOrg("A", founder), f.createOrg("B", founder)
	instanceOwnerID := f.grant("owner@example.com", admin.RoleOwner, "")
	otherOrgID := f.grant("other@example.com", admin.RoleAdmin, orgB)
	root := f.login("root@example.com")
	f.makeSuperadmin("root@example.com", root)
	rootID := f.userID("root@example.com")
	adaID := f.userID("founder@example.com") // a plain user (registrations are rate limited)

	orgOwner := f.operator(admin.RoleOwner, orgA)
	for caller, credential := range map[string]string{"an organization owner": orgOwner, "an organization owner key": f.key(admin.RoleOwner, orgA, nil)} {
		for target, id := range map[string]string{"an instance owner": instanceOwnerID, "another organization's operator": otherOrgID, "a superadmin": rootID} {
			resp := f.c.Post("/admin/grants", map[string]any{"user_id": id, "role": "viewer", "scope": orgA}, as(credential))
			if resp.StatusCode != http.StatusForbidden || body(t, resp)["error"] != "admin_forbidden" {
				t.Errorf("%s replaces the grant of %s: status %d, want 403 admin_forbidden", caller, target, resp.StatusCode)
			}
		}
	}
	if g, ok, _ := f.admin.Grants().For(ctx, instanceOwnerID); !ok || g.Role != admin.RoleOwner || g.Scope != admin.ScopeInstance {
		t.Errorf("the instance owner's grant is now %+v", g)
	}
	if g, ok, _ := f.admin.Grants().For(ctx, otherOrgID); !ok || g.Scope != orgB {
		t.Errorf("the other organization's grant is now %+v", g)
	}
	if _, ok, _ := f.admin.Grants().For(ctx, rootID); ok {
		t.Error("the superadmin was given a grant")
	}

	// Inside its organization the owner grants and replaces as before.
	for _, role := range []string{"admin", "viewer"} {
		wantStatus(t, f.c.Post("/admin/grants", map[string]any{"user_id": adaID, "role": role, "scope": orgA}, as(orgOwner)), http.StatusCreated)
	}
	// An instance owner replaces any grant, a superadmin's included.
	instanceOwner := f.login("owner@example.com")
	for _, id := range []string{otherOrgID, rootID, adaID} {
		wantStatus(t, f.c.Post("/admin/grants", map[string]any{"user_id": id, "role": "viewer"}, as(instanceOwner)), http.StatusCreated)
	}
}

// A session an organization's identity provider opened is no operator, whatever grant or role its
// user holds (decisions 68, 76).
func TestAnOrganizationBoundSessionIsNoOperator(t *testing.T) {
	ctx := context.Background()
	f := boundsFlow(t)
	ownerID := f.grant("owner@example.com", admin.RoleOwner, "")
	root := f.login("root@example.com")
	f.makeSuperadmin("root@example.com", root)

	for name, userID := range map[string]string{"an owner": ownerID, "a superadmin": f.userID("root@example.com")} {
		bound, err := f.srv.Graph().Sessions().Mint(ctx, token.SessionPrincipal{UserID: userID, AMR: []string{token.AMRSSO}}, "", token.Claims{})
		if err != nil {
			t.Fatal(err)
		}
		if resp := f.c.Get("/admin/users", as(bound)); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("the bound session of %s reads /admin/users: status %d, want 401", name, resp.StatusCode)
		}
		if is, _ := f.admin.IsOperator(ctx, bound); is {
			t.Errorf("the bound session of %s is an operator", name)
		}
	}
	wantStatus(t, f.c.Get("/admin/users", as(f.login("owner@example.com"))), http.StatusOK)
}

// A drain's endpoint is never a literal non-public address (the delivery guard refuses the rest
// after DNS resolution).
func TestADrainEndpointIsNotALiteralInternalAddress(t *testing.T) {
	f := boundsFlow(t)
	owner := f.operator(admin.RoleOwner, "")
	org := f.createOrg("Acme", owner)
	for _, endpoint := range []string{"https://127.0.0.1/x", "https://[::1]:8443/x", "https://169.254.169.254/latest", "https://10.0.0.8/x", "https://localhost/x", "https://user@hooks.example.test/x"} {
		resp := f.c.Post("/admin/organizations/"+org+"/drains", map[string]any{"endpoint": endpoint, "secret": "a-secret-of-sixteen-chars"}, as(owner))
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s: status %d, want 422", endpoint, resp.StatusCode)
		}
	}
	wantStatus(t, f.c.Post("/admin/organizations/"+org+"/drains", map[string]any{"endpoint": "https://8.8.8.8/x", "secret": "a-secret-of-sixteen-chars"}, as(owner)), http.StatusCreated)
}

// What a plugin holds about a user is erased inside the account's erasure: when it cannot be,
// the account is not erased either (decision 76).
func TestAnErasureThatCannotEraseAPluginsRowsErasesNothing(t *testing.T) {
	ctx := context.Background()
	f := boundsFlow(t)
	adaID := f.grant("ada@example.com", admin.RoleViewer, "")
	identity := f.srv.Graph().Identity()

	if err := f.srv.DB.Exec(ctx, "ALTER TABLE "+admin.TableGrants+" RENAME TO admin_grants_away"); err != nil {
		t.Fatal(err)
	}
	if err := identity.AnonymizeUser(ctx, "", adaID); err == nil {
		t.Error("the erasure reported success although the operator grant could not be erased")
	}
	if u, _ := f.srv.Graph().Repos().Users.Get(ctx, adaID); u.Email != "ada@example.com" {
		t.Errorf("the account was anonymised (%s) without its plugin rows", u.Email)
	}

	if err := f.srv.DB.Exec(ctx, "ALTER TABLE admin_grants_away RENAME TO "+admin.TableGrants); err != nil {
		t.Fatal(err)
	}
	if err := identity.AnonymizeUser(ctx, "", adaID); err != nil {
		t.Fatal(err)
	}
	if _, held, _ := f.admin.Grants().For(ctx, adaID); held {
		t.Error("the erased user keeps an operator grant")
	}
}

// With the denylist on, a session that ended is no operator's: not on the admin routes, which an
// operator's browser may still call, nor to a bare credential. Ending a user's session there ends its
// access token, and no other one.
func TestAnEndedSessionIsNoOperatorAndAnOperatorEndsOne(t *testing.T) {
	ctx := context.Background()
	for _, denylist := range []bool{true, false} {
		f := &flow{t: t, admin: admin.New(admin.Config{})}
		f.srv = polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), f.admin),
			polaristest.WithAuth(func(a *config.Auth) { a.AccessToken.Denylist = denylist }))
		f.c = contracttest.NewClient(t, f.srv.Handler(), nil)
		sid := func(access string) string {
			tok, err := f.srv.Graph().Tokens().Parse(access)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := tok.Claim("sid").(string)
			return id
		}
		ended := http.StatusOK
		if denylist {
			ended = http.StatusUnauthorized
		}

		op := f.operator(admin.RoleOwner, "")
		second := f.login(operator)
		ended1, kept := f.login("ada@example.com"), f.login("ada@example.com")
		adaID := f.userID("ada@example.com")
		wantStatus(t, f.c.Delete("/admin/users/"+adaID+"/sessions/"+sid(ended1), as(op)), http.StatusOK)
		wantStatus(t, f.c.Get("/auth/me", as(ended1)), ended)
		wantStatus(t, f.c.Get("/auth/me", as(kept)), http.StatusOK)

		wantStatus(t, f.c.Post("/auth/logout", nil, as(second)), http.StatusOK)
		wantStatus(t, f.c.Get("/admin/users", as(second)), ended)
		wantStatus(t, f.c.Get("/admin/users", as(op)), http.StatusOK)
		for credential, want := range map[string]bool{second: !denylist, op: true} {
			if is, err := f.admin.IsOperator(ctx, credential); is != want || err != nil {
				t.Errorf("denylist %v: IsOperator %v %v, want %v", denylist, is, err, want)
			}
		}
	}
}
