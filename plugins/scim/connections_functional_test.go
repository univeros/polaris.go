package scim_test

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/scim"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

func TestEveryScimFixtureHasAGoTest(t *testing.T) {
	missing, err := contracttest.Uncovered(contracttest.Fixtures(t, "scim"), []string{
		classes + "ScimConnectionsTest::testAnOrganizationCreatesRotatesAndDecommissionsItsConnections",
		classes + "ScimConnectionsTest::testTheOperatorsSeeEveryOrganizationsConnections",
		classes + "ScimProvisioningTest::testADirectoryProvisionsUsersAndGroups",
	})
	if err != nil || len(missing) > 0 {
		t.Fatalf("uncovered fixtures %v (%v)", missing, err)
	}
}

func TestScimConnections(t *testing.T) {
	t.Run("testAnOrganizationCreatesRotatesAndDecommissionsItsConnections", func(t *testing.T) {
		f := newFlow(t, "ScimConnectionsTest", "testAnOrganizationCreatesRotatesAndDecommissionsItsConnections")
		ada := f.login("ada@acme.example")
		acme, owner := f.organization("Acme Rockets", ada)
		bob := f.login("bob@example.com")
		as := bearer(owner)
		connections := "/orgs/" + acme + "/scim/connections"

		problem(t, f.c.Get(connections, bearer(bob)), 403, "scim_forbidden")
		problem(t, f.c.Post(connections, map[string]any{"name": ""}, as), 422, "scim_invalid_input")
		problem(t, f.c.Post(connections, map[string]any{"name": "Okta", "deprovision": "purge"}, as), 422, "scim_invalid_input")
		problem(t, f.c.Post(connections, map[string]any{"name": "Okta", "sso_provider_id": "nope"}, as), 422, "scim_invalid_input")
		created := data(t, f.c.Post(connections, map[string]any{"name": "Okta", "deprovision": "delete"}, as))
		id, token := created["id"].(string), created["token"].(string)
		check(t, strings.HasPrefix(token, scim.TokenPrefix), "token %q", token)
		check(t, reflect.DeepEqual([]any{created["name"], created["status"], created["deprovision"], created["scim_base_url"], created["sync"]},
			[]any{"Okta", "active", "delete", base + "/scim/v2/" + id, map[string]any{"users": 0.0, "groups": 0.0, "provisioned_members": 0.0}}), "created %v", created)
		listed := items(doc(t, f.c.Get(connections, as))["data"])
		check(t, len(listed) == 1 && listed[0]["id"] == id, "listed %v", listed)
		_, hasToken := listed[0]["token"]
		check(t, !hasToken, "the list shows a token")
		read := data(t, f.c.Get(connections+"/"+id, as))
		check(t, read["scim_base_url"] == created["scim_base_url"], "read %v", read)
		problem(t, f.c.Get(connections+"/nope", as), 404, "scim_not_found")

		spc := "/scim/v2/" + id + "/ServiceProviderConfig"
		status(t, f.scim("GET", spc, nil, token), 200)
		rotated := data(t, f.c.Post(connections+"/"+id+"/rotate", nil, as))
		next := rotated["token"].(string)
		check(t, strings.HasPrefix(next, scim.TokenPrefix), "rotated %v", rotated)
		scimError(t, f.scim("GET", spc, nil, token), 401, "")
		status(t, f.scim("GET", spc, nil, next), 200)

		decommissioned := data(t, f.c.Delete(connections+"/"+id, as))
		check(t, decommissioned["status"] == "decommissioned" && decommissioned["decommissioned_at"] != nil, "decommissioned %v", decommissioned)
		scimError(t, f.scim("GET", spc, nil, next), 401, "")
		problem(t, f.c.Post(connections+"/"+id+"/rotate", nil, as), 409, "scim_conflict")
		check(t, data(t, f.c.Delete(connections+"/"+id, as))["status"] == "decommissioned", "idempotent")
		names := f.auditNames(scim.AuditConnectionCreated, scim.AuditConnectionRotated, scim.AuditConnectionDecommissioned)
		check(t, reflect.DeepEqual(names, []any{scim.AuditConnectionDecommissioned, scim.AuditConnectionRotated, scim.AuditConnectionCreated}), "audit %v", names)
	})

	t.Run("testTheOperatorsSeeEveryOrganizationsConnections", func(t *testing.T) {
		f := newFlow(t, "ScimConnectionsTest", "testTheOperatorsSeeEveryOrganizationsConnections")
		ada := f.login("ada@acme.example")
		acme, acmeOwner := f.organization("Acme Rockets", ada)
		globex, globexOwner := f.organization("Globex", ada)
		acmeConnection, _ := f.connection(acme, acmeOwner, "Okta")
		globexConnection, _ := f.connection(globex, globexOwner, "Entra")
		viewer := bearer(f.key(admin.RoleViewer, admin.ScopeInstance))
		globexViewer := bearer(f.key(admin.RoleViewer, globex))
		owner := bearer(f.key(admin.RoleOwner, admin.ScopeInstance))
		list := "/admin/scim/connections"

		problem(t, f.c.Get(list), 401, "admin_unauthorized")
		problem(t, f.c.Get(list+"?limit=0", viewer), 422, "admin_invalid_input")
		ids := column(items(doc(t, f.c.Get(list, viewer))["data"]), "id")
		check(t, reflect.DeepEqual(ids, []any{acmeConnection, globexConnection}), "listed %v", ids)
		cursor := doc(t, f.c.Get(list+"?limit=1", viewer))["next_cursor"].(string)
		ids = column(items(doc(t, f.c.Get(list+"?limit=1&cursor="+cursor, viewer))["data"]), "id")
		check(t, reflect.DeepEqual(ids, []any{globexConnection}), "second page %v", ids)
		ids = column(items(doc(t, f.c.Get(list, globexViewer))["data"]), "id")
		check(t, reflect.DeepEqual(ids, []any{globexConnection}), "scoped %v", ids)
		problem(t, f.c.Get(list+"?organization_id="+acme, globexViewer), 403, "admin_forbidden")
		problem(t, f.c.Delete(list+"/"+acmeConnection, viewer), 403, "admin_forbidden")
		problem(t, f.c.Delete(list+"/nope", owner), 404, "admin_not_found")
		check(t, data(t, f.c.Delete(list+"/"+acmeConnection, owner))["status"] == "deleted", "deleted")
		check(t, len(items(doc(t, f.c.Get("/orgs/"+acme+"/scim/connections", bearer(acmeOwner)))["data"])) == 0, "gone")
	})
}

// Stricter than upstream: core enforces the routes' org.update, so a plain member of the active
// organization cannot manage its connections (upstream only checked the active organization).
func TestAMemberWithoutOrgUpdateCannotManageConnections(t *testing.T) {
	f := &flow{t: t, admin: admin.New(admin.Config{}), trail: audit.New(audit.Config{})}
	f.srv = polaristest.New(t, polaristest.WithPlugins(f.trail, f.admin, scim.New(scim.Config{BaseURL: base})))
	f.c = contracttest.NewClient(t, f.srv.Handler(), nil)
	ctx := context.Background()
	acme, owner := f.organization("Acme", f.login("ada@acme.example"))
	connID, token := f.connection(acme, owner, "Okta")
	bobAccess := f.login("bob@acme.example")
	g := f.srv.Graph()
	bob := must(g.Repos().Users.ByEmail(ctx, "bob@acme.example"))
	role := must(g.Repos().Roles.ByOrganizationAndSlug(ctx, &acme, "member"))
	now := time.Now().UTC().Truncate(time.Second)
	id := repository.NewID()
	if err := f.srv.DB.Insert(ctx, "auth_memberships", store.Row{"id": id, "user_id": bob.ID, "organization_id": acme, "status": "active",
		"invited_by": nil, "joined_at": now, "created_at": now, "updated_at": now}); err != nil {
		t.Fatal(err)
	}
	if err := f.srv.DB.Insert(ctx, "auth_membership_roles", store.Row{"membership_id": id, "role_id": role.ID}); err != nil {
		t.Fatal(err)
	}
	switched, _ := data(t, f.c.Post("/auth/switch-org", map[string]any{"organization_id": acme}, bearer(bobAccess)))["access_token"].(string)
	resp := f.c.Get("/orgs/"+acme+"/scim/connections", bearer(switched))
	status(t, resp, 403)
	check(t, doc(t, resp)["error"] == "forbidden", "core's refusal: %v", doc(t, resp))
	problem(t, f.c.Get("/orgs/"+acme+"/scim/connections", bearer(bobAccess)), 403, "scim_forbidden")

	req := f.c.NewRequest("GET", "/scim/v2/"+connID+"/Users", nil, contracttest.Header("Authorization", "Token "+token))
	scimError(t, f.c.Do(req), 401, "")
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
