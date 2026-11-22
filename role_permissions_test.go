package polaris_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/polaristest"
)

var hostPermissions = map[string]string{"invoices.read": "Read invoices", "invoices.void": "Void invoices"}

// ownerSession creates an owner, their organization and an access token switched into it.
func ownerSession(t *testing.T, srv *polaristest.Server, c *contracttest.Client, email string) (orgID, access string) {
	t.Helper()
	ctx := context.Background()
	owner, err := srv.Users().Create(ctx, polaris.NewUser{Email: email, EmailVerified: true})
	ok(t, err)
	org, err := srv.Orgs().Create(ctx, owner.ID, "Org "+email, "")
	ok(t, err)
	tokens, err := srv.Sessions().Issue(ctx, polaris.SignIn{UserID: owner.ID})
	ok(t, err)
	r := c.Post("/auth/switch-org", map[string]any{"organization_id": org.ID}, contracttest.Bearer(tokens.AccessToken))
	if r.StatusCode != http.StatusOK {
		t.Fatalf("switch-org %d", r.StatusCode)
	}
	return org.ID, contracttest.JSON(t, r)["data"].(map[string]any)["access_token"].(string)
}

func createRole(c *contracttest.Client, orgID, access, slug string, keys ...string) *http.Response {
	return c.Post("/orgs/"+orgID+"/roles", map[string]any{"name": slug, "slug": slug, "permission_keys": keys}, contracttest.Bearer(access))
}

// TestHostPermissionsReachRolesThroughRolePermissions is the flow llms.txt documents: the host
// declares its permissions and which system roles hold them; an owner then grants them to a
// custom role. A permission no role of the actor holds stays refused.
func TestHostPermissionsReachRolesThroughRolePermissions(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) {
		c.Permissions = hostPermissions
		c.RolePermissions = map[string][]string{"owner": {"invoices.read", "invoices.void"}, "admin": {"invoices.read"}}
	}))
	c := contracttest.NewClient(t, srv.Handler(), nil)
	orgID, access := ownerSession(t, srv, c, "owner@example.com")

	if r := createRole(c, orgID, access, "billing", "invoices.read"); r.StatusCode != http.StatusCreated {
		t.Fatalf("owner granting a declared host permission: %d %v", r.StatusCode, contracttest.JSON(t, r))
	}
	if !srv.Can(context.Background(), polaris.Principal{UserID: ownerID(t, srv, "owner@example.com"), OrganizationID: orgID}, "invoices.void") {
		t.Fatal("the owner holds what RolePermissions gives the owner role")
	}
	roles := contracttest.JSON(t, c.Get("/orgs/"+orgID+"/roles", contracttest.Bearer(access)))["data"].([]any)
	for _, raw := range roles {
		role := raw.(map[string]any)
		keys := role["permission_keys"].([]any)
		has := slices.Contains(keys, any("invoices.read"))
		switch role["slug"] {
		case "owner", "admin", "billing":
			if !has {
				t.Fatalf("%s lacks invoices.read: %v", role["slug"], keys)
			}
		case "member":
			if has {
				t.Fatalf("member holds invoices.read: %v", keys)
			}
		}
	}
}

func TestUndeclaredHostPermissionsStayUngrantable(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) { c.Permissions = hostPermissions }))
	c := contracttest.NewClient(t, srv.Handler(), nil)
	orgID, access := ownerSession(t, srv, c, "owner@example.com")
	r := createRole(c, orgID, access, "billing", "invoices.read")
	if body := contracttest.JSON(t, r); r.StatusCode != http.StatusForbidden || !strings.Contains(body["message"].(string), "do not hold") {
		t.Fatalf("no role holds invoices.read, so nobody may grant it: %d %v", r.StatusCode, body)
	}
}

// TestMigrateGivesExistingOrganizationsNewRolePermissions: organizations created before the host
// declared a role permission get it on the next Migrate, once; a tenant's later removal from an
// editable role is kept.
func TestMigrateGivesExistingOrganizationsNewRolePermissions(t *testing.T) {
	ctx := context.Background()
	before := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) { c.Permissions = hostPermissions }))
	c := contracttest.NewClient(t, before.Handler(), nil)
	orgID, _ := ownerSession(t, before, c, "early@example.com")

	after := polaristest.New(t, polaristest.WithDB(before.DB), polaristest.WithConfig(func(c *polaris.Config) {
		c.Permissions = hostPermissions
		c.RolePermissions = map[string][]string{"owner": {"invoices.read"}, "admin": {"invoices.read"}}
	}))
	_, err := after.Migrate(ctx)
	ok(t, err)
	ac := contracttest.NewClient(t, after.Handler(), nil)
	owner := ownerID(t, after, "early@example.com")
	if !after.Can(ctx, polaris.Principal{UserID: owner, OrganizationID: orgID}, "invoices.read") {
		t.Fatal("Migrate gives an existing organization's owner role the declared permission")
	}
	tokens, err := after.Sessions().Issue(ctx, polaris.SignIn{UserID: owner})
	ok(t, err)
	access := contracttest.JSON(t, ac.Post("/auth/switch-org", map[string]any{"organization_id": orgID}, contracttest.Bearer(tokens.AccessToken)))["data"].(map[string]any)["access_token"].(string)
	adminID := roleID(t, ac, orgID, access, "admin")
	if r := ac.Patch("/orgs/"+orgID+"/roles/"+adminID, map[string]any{"permission_keys": []string{"org.read"}}, contracttest.Bearer(access)); r.StatusCode != http.StatusOK {
		t.Fatalf("strip admin: %d", r.StatusCode)
	}
	_, err = after.Migrate(ctx)
	ok(t, err)
	for _, raw := range contracttest.JSON(t, ac.Get("/orgs/"+orgID+"/roles", contracttest.Bearer(access)))["data"].([]any) {
		if role := raw.(map[string]any); role["slug"] == "admin" && len(role["permission_keys"].([]any)) != 1 {
			t.Fatalf("Migrate must not undo a tenant's edit: %v", role["permission_keys"])
		}
	}
}

func TestRolePermissionsAreCheckedAtNew(t *testing.T) {
	for name, tc := range map[string]struct {
		grants map[string][]string
		want   string
	}{
		"unknown role":         {map[string][]string{"billing": {"invoices.read"}}, "owner, admin or member"},
		"superadmin":           {map[string][]string{"superadmin": {"invoices.read"}}, "owner, admin or member"},
		"undeclared key":       {map[string][]string{"owner": {"invoices.pay"}}, "Config.Permissions"},
		"core key":             {map[string][]string{"member": {"users.manage"}}, "core permission"},
		"core key in template": {map[string][]string{"member": {"members.invite"}}, "core permission"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := polaristest.New(t).Graph().Config()
			cfg.Permissions = hostPermissions
			cfg.RolePermissions = tc.grants
			_, err := polaris.New(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error naming %q, got %v", tc.want, err)
			}
		})
	}
}

func ownerID(t *testing.T, srv *polaristest.Server, email string) string {
	t.Helper()
	u, err := srv.Users().ByEmail(context.Background(), email)
	ok(t, err)
	return u.ID
}

func roleID(t *testing.T, c *contracttest.Client, orgID, access, slug string) string {
	t.Helper()
	for _, raw := range contracttest.JSON(t, c.Get("/orgs/"+orgID+"/roles", contracttest.Bearer(access)))["data"].([]any) {
		if role := raw.(map[string]any); role["slug"] == slug {
			return role["id"].(string)
		}
	}
	t.Fatalf("no %s role", slug)
	return ""
}
