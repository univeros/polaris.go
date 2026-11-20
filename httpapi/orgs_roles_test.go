package httpapi_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
)

// Port of RoleEndpointsTest: GET/POST /orgs/{id}/roles, PATCH/DELETE /orgs/{id}/roles/{roleId}
// and the GET /permissions catalog. Custom roles carry only keys the actor holds, the cloned owner
// role and global system roles are immutable, and deleting a role detaches it from every member.
func TestRoleEndpoints(t *testing.T) {
	const founder = "founder@example.com"
	orgRun(t, "RoleEndpointsTest", map[string]func(*orgCase){
		"testListsTheClonedTemplateRolesWithTheirPermissions": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			bySlug := o.roleRolesBySlug(org, owner)
			slugs := make([]string, 0, len(bySlug))
			for slug := range bySlug {
				slugs = append(slugs, slug)
			}
			slices.Sort(slugs)
			o.equal(slugs, []string{"admin", "member", "owner"}, "role slugs")
			o.roleHasKey(bySlug["owner"], "org.delete", true)
			o.roleHasKey(bySlug["admin"], "org.delete", false)
			o.roleHasKey(bySlug["member"], "roles.read", true)
		},
		"testPermissionsCatalogIsAvailableToAnyAuthenticatedUser": func(o *orgCase) {
			session := o.login("someone@example.com")

			var keys []string
			for _, p := range orgMaps(o.json(o.c.Get("/permissions", contracttest.Bearer(session.access)))["data"]) {
				if k, ok := p["key"].(string); ok {
					keys = append(keys, k)
				}
			}
			if !slices.Contains(keys, "members.invite") || !slices.Contains(keys, "org.delete") {
				o.t.Fatalf("catalog keys: %v", keys)
			}

			o.status(o.c.Get("/permissions"), http.StatusUnauthorized)
		},
		"testOwnerCreatesACustomRoleAndItIsGrantable": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			resp := o.c.Post("/orgs/"+org+"/roles", map[string]any{
				"name":            "Support",
				"slug":            "support",
				"description":     "Read-only support staff",
				"permission_keys": []string{"org.read", "members.read"},
			}, contracttest.Bearer(owner))
			o.status(resp, http.StatusCreated)
			if id, _ := o.data(resp)["id"].(string); id == "" {
				o.t.Fatal("no role id")
			}

			o.equal(o.roleRolesBySlug(org, owner)["support"]["permission_keys"], []string{"org.read", "members.read"}, "support permissions")

			// The new role is assignable through the member-roles endpoint.
			member := repository.NewID()
			o.seedMember(org, member, "member", model.MembershipStatusActive)
			o.status(o.c.Patch("/orgs/"+org+"/members/"+member+"/roles", map[string]any{"role_slugs": []string{"support"}}, contracttest.Bearer(owner)), http.StatusOK)
		},
		"testDuplicateSlugConflicts": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			o.status(o.c.Post("/orgs/"+org+"/roles", map[string]any{
				"name":            "Member Two",
				"slug":            "member",
				"permission_keys": []string{"org.read"},
			}, contracttest.Bearer(owner)), http.StatusConflict)
		},
		"testRejectsUnknownPermissionKeysAndBadInput": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			for _, body := range []map[string]any{
				{"name": "X", "slug": "x", "permission_keys": []string{"does.not.exist"}},
				{"slug": "x", "permission_keys": []string{"org.read"}},
				{"name": "X", "slug": "Not A Slug!", "permission_keys": []string{"org.read"}},
			} {
				o.status(o.c.Post("/orgs/"+org+"/roles", body, contracttest.Bearer(owner)), http.StatusUnprocessableEntity)
			}
		},
		"testActorCannotPutPermissionsTheyDoNotHoldIntoARole": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			admin := o.seedActiveMember(org, "admin@example.com", "admin")

			// An admin holds roles.manage but not org.delete: packing it into any role is denied…
			o.status(o.c.Post("/orgs/"+org+"/roles", map[string]any{
				"name":            "Sneaky",
				"slug":            "sneaky",
				"permission_keys": []string{"org.delete"},
			}, contracttest.Bearer(admin)), http.StatusForbidden)

			// …including editing a role they already hold (the self-escalation path).
			adminRole := o.roleID(org, "admin")
			o.status(o.c.Patch("/orgs/"+org+"/roles/"+adminRole, map[string]any{"permission_keys": []string{"org.delete"}}, contracttest.Bearer(admin)), http.StatusForbidden)
		},
		"testUpdateChangesNameAndPermissions": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			roleID := o.roleCreate(org, owner, []string{"org.read"})

			resp := o.c.Patch("/orgs/"+org+"/roles/"+roleID, map[string]any{
				"name":            "Support Tier 2",
				"permission_keys": []string{"org.read", "members.read"},
			}, contracttest.Bearer(owner))
			o.status(resp, http.StatusOK)

			support := o.roleRolesBySlug(org, owner)["support"]
			o.equal(support["name"], "Support Tier 2", "name")
			o.equal(support["permission_keys"], []string{"org.read", "members.read"}, "permissions")
		},
		"testTheOwnerRoleIsImmutable": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			ownerRole := o.roleID(org, "owner")

			o.status(o.c.Patch("/orgs/"+org+"/roles/"+ownerRole, map[string]any{"name": "God"}, contracttest.Bearer(owner)), http.StatusForbidden)
			o.status(o.c.Delete("/orgs/"+org+"/roles/"+ownerRole, contracttest.Bearer(owner)), http.StatusForbidden)
		},
		"testTheClonedTemplatesAreEditableButNotDeletable": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)

			// admin/member stay tenant-editable…
			adminRole := o.roleID(org, "admin")
			o.status(o.c.Patch("/orgs/"+org+"/roles/"+adminRole, map[string]any{"name": "Manager"}, contracttest.Bearer(owner)), http.StatusOK)

			// …but deleting them would cascade-strip members and break slug-based assignment.
			o.status(o.c.Delete("/orgs/"+org+"/roles/"+adminRole, contracttest.Bearer(owner)), http.StatusForbidden)
			o.status(o.c.Delete("/orgs/"+org+"/roles/"+o.roleID(org, "member"), contracttest.Bearer(owner)), http.StatusForbidden)
		},
		"testUpdateCanStripAllPermissionsFromARole": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			roleID := o.roleCreate(org, owner, []string{"org.read"})

			o.status(o.c.Patch("/orgs/"+org+"/roles/"+roleID, map[string]any{"permission_keys": []string{}}, contracttest.Bearer(owner)), http.StatusOK)
			o.equal(o.roleRolesBySlug(org, owner)["support"]["permission_keys"], []string{}, "permissions")
		},
		"testGlobalSystemRolesAreNotReachableThroughTheOrgPath": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			superadmin := o.systemRoleID("superadmin")

			// Another scope's role is indistinguishable from an unknown one.
			o.status(o.c.Patch("/orgs/"+org+"/roles/"+superadmin, map[string]any{"name": "Pwned"}, contracttest.Bearer(owner)), http.StatusNotFound)
			o.status(o.c.Delete("/orgs/"+org+"/roles/"+superadmin, contracttest.Bearer(owner)), http.StatusNotFound)
			if _, ok := o.roleRolesBySlug(org, owner)["superadmin"]; ok {
				o.t.Fatal("superadmin listed among the organization's roles")
			}
		},
		"testDeletingARoleDetachesItFromMembers": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			roleID := o.roleCreate(org, owner, []string{"org.read", "members.read"})

			member := repository.NewID()
			o.seedMember(org, member, "support", model.MembershipStatusActive)

			o.status(o.c.Delete("/orgs/"+org+"/roles/"+roleID, contracttest.Bearer(owner)), http.StatusOK)

			if _, ok := o.roleRolesBySlug(org, owner)["support"]; ok {
				o.t.Fatal("deleted role still listed")
			}
			o.equal(o.rolesOf(org, member, owner), []string{}, "member roles")
		},
		"testPlainMemberLacksPermissionToManageRoles": func(o *orgCase) {
			org, _, _ := o.orgOwnedBy(founder)
			member := o.seedActiveMember(org, "member@example.com", "member")

			// Members hold roles.read but not roles.manage.
			o.status(o.c.Get("/orgs/"+org+"/roles", contracttest.Bearer(member)), http.StatusOK)
			o.status(o.c.Post("/orgs/"+org+"/roles", map[string]any{
				"name":            "X",
				"slug":            "x",
				"permission_keys": []string{"org.read"},
			}, contracttest.Bearer(member)), http.StatusForbidden)
			o.status(o.c.Patch("/orgs/"+org+"/roles/"+o.roleID(org, "member"), map[string]any{"name": "X"}, contracttest.Bearer(member)), http.StatusForbidden)
			o.status(o.c.Delete("/orgs/"+org+"/roles/"+o.roleID(org, "member"), contracttest.Bearer(member)), http.StatusForbidden)
		},
		"testCannotManageRolesOfAnInactiveOrg": func(o *orgCase) {
			_, acme, session := o.orgOwnedBy(founder)
			globex := o.createOrg("Globex", session.access) // owns Globex too, but is scoped to Acme

			o.status(o.c.Get("/orgs/"+globex+"/roles", contracttest.Bearer(acme)), http.StatusForbidden)
			o.status(o.c.Post("/orgs/"+globex+"/roles", map[string]any{
				"name":            "X",
				"slug":            "x",
				"permission_keys": []string{"org.read"},
			}, contracttest.Bearer(acme)), http.StatusForbidden)
		},
		"testUnknownRoleIsNotFound": func(o *orgCase) {
			org, owner, _ := o.orgOwnedBy(founder)
			unknown := repository.NewID()

			o.status(o.c.Patch("/orgs/"+org+"/roles/"+unknown, map[string]any{"name": "X"}, contracttest.Bearer(owner)), http.StatusNotFound)
			o.status(o.c.Delete("/orgs/"+org+"/roles/"+unknown, contracttest.Bearer(owner)), http.StatusNotFound)
		},
	})
}

// roleCreate creates the custom role "support" with keys and returns its id.
func (o *orgCase) roleCreate(org, token string, keys []string) string {
	o.t.Helper()
	id, _ := o.data(o.c.Post("/orgs/"+org+"/roles", map[string]any{
		"name":            "Support",
		"slug":            "support",
		"permission_keys": keys,
	}, contracttest.Bearer(token)))["id"].(string)
	return id
}

// roleRolesBySlug lists org's roles as token sees them, keyed by slug.
func (o *orgCase) roleRolesBySlug(org, token string) map[string]map[string]any {
	o.t.Helper()
	out := map[string]map[string]any{}
	for _, r := range orgMaps(o.json(o.c.Get("/orgs/"+org+"/roles", contracttest.Bearer(token)))["data"]) {
		if slug, ok := r["slug"].(string); ok {
			out[slug] = r
		}
	}
	return out
}

// roleHasKey fails the test unless role's permission keys contain key exactly when want.
func (o *orgCase) roleHasKey(role map[string]any, key string, want bool) {
	o.t.Helper()
	if slices.Contains(orgStrs(role["permission_keys"]), key) != want {
		o.t.Fatalf("role %v: has %s = %v, want %v", role["slug"], key, !want, want)
	}
}
