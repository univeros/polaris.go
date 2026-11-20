package admin_test

import (
	"context"
	"reflect"
	"slices"
	"testing"

	"github.com/univeros/polaris-go/plugins/admin"
	"github.com/univeros/polaris-go/store"
)

// rolesByEmail maps each member's email to their role slugs.
func rolesByEmail(org map[string]any) map[string]any {
	out := map[string]any{}
	members, _ := org["members"].([]any)
	for _, m := range members {
		member := m.(map[string]any)
		out[member["email"].(string)] = member["roles"]
	}
	return out
}

func TestAdminOrganizations(t *testing.T) {
	const class = "AdminOrganizationsTest"

	t.Run("testOrganizationsAreListedReadRolesSetAndDeleted", func(t *testing.T) {
		f := newFlow(t, class, "testOrganizationsAreListedReadRolesSetAndDeleted")
		ada := f.login("ada@example.com")
		adaID := f.userID("ada@example.com")
		f.login("bob@example.com")
		bobID := f.userID("bob@example.com")
		acme := f.createOrg("Acme Rockets", ada)
		globex := f.createOrg("Globex", ada)
		f.join("bob@example.com", acme, "member")
		owner := f.operator(admin.RoleOwner, "")

		want(t, reflect.DeepEqual(column(list(t, f.c.Get("/admin/organizations", as(owner))), "slug"), []any{"acme-rockets", "globex"}), "listed")
		want(t, reflect.DeepEqual(column(list(t, f.c.Get("/admin/organizations?limit=1&cursor="+acme, as(owner))), "id"), []any{globex}), "cursor")
		problem(t, f.c.Get("/admin/organizations?status=gone", as(owner)), 422, "admin_invalid_input")

		read := data(t, f.c.Get("/admin/organizations/"+acme, as(owner)))
		want(t, read["name"] == "Acme Rockets", "read %v", read)
		want(t, reflect.DeepEqual(rolesByEmail(read), map[string]any{"ada@example.com": []any{"owner"}, "bob@example.com": []any{"member"}}), "members %v", read["members"])
		problem(t, f.c.Get("/admin/organizations/nope", as(owner)), 404, "admin_not_found")

		roles := func(org, user string) string {
			return "/admin/organizations/" + org + "/members/" + user + "/roles"
		}
		problem(t, f.c.Patch(roles(acme, adaID), map[string]any{"roles": []string{"admin"}}, as(owner)), 409, "admin_conflict")
		problem(t, f.c.Patch(roles(acme, bobID), map[string]any{"roles": []string{"ceo"}}, as(owner)), 422, "admin_invalid_input")
		problem(t, f.c.Patch(roles(acme, bobID), map[string]any{"roles": []string{}}, as(owner)), 422, "admin_invalid_input")
		problem(t, f.c.Patch(roles(globex, bobID), map[string]any{"roles": []string{"admin"}}, as(owner)), 404, "admin_not_found")
		want(t, reflect.DeepEqual(data(t, f.c.Patch(roles(acme, bobID), map[string]any{"roles": []string{"owner", "admin"}}, as(owner)))["roles"], []any{"owner", "admin"}), "bob's roles")
		want(t, reflect.DeepEqual(data(t, f.c.Patch(roles(acme, adaID), map[string]any{"roles": []string{"admin"}}, as(owner)))["roles"], []any{"admin"}), "bob is an owner now, so ada can step down")
		members := rolesByEmail(data(t, f.c.Get("/admin/organizations/"+acme, as(owner))))
		bob, _ := members["bob@example.com"].([]any)
		want(t, reflect.DeepEqual(members["ada@example.com"], []any{"admin"}) && len(bob) == 2 && slices.Contains(bob, any("owner")) && slices.Contains(bob, any("admin")), "members %v", members)

		want(t, data(t, f.c.Delete("/admin/organizations/"+globex, as(owner)))["status"] == "suspended", "deleted")
		want(t, reflect.DeepEqual(column(list(t, f.c.Get("/admin/organizations?status=suspended", as(owner))), "id"), []any{globex}), "suspended listed")
		names := column(list(t, f.c.Get("/admin/audit?names=admin.organization_deleted,admin.member_roles_changed", as(owner))), "name")
		want(t, reflect.DeepEqual(names, []any{admin.AuditOrganizationDeleted, admin.AuditMemberRolesChanged, admin.AuditMemberRolesChanged}), "audited %v", names)
	})

	t.Run("testAnOrganizationScopedPrincipalSeesItsOrganizationOnly", func(t *testing.T) {
		f := newFlow(t, class, "testAnOrganizationScopedPrincipalSeesItsOrganizationOnly")
		ada := f.login("ada@example.com")
		acme := f.createOrg("Acme Rockets", ada)
		globex := f.createOrg("Globex", ada)
		scoped := f.key(admin.RoleAdmin, acme, nil)

		want(t, data(t, f.c.Get("/admin/organizations/"+acme, as(scoped)))["name"] == "Acme Rockets", "its organization")
		for _, path := range []string{"/admin/organizations/" + globex, "/admin/organizations", "/admin/users", "/admin/stats", "/admin/keys"} {
			problem(t, f.c.Get(path, as(scoped)), 403, "admin_forbidden")
		}
		trail := list(t, f.c.Get("/admin/audit", as(scoped)))
		for _, e := range trail {
			want(t, e["organization_id"] == acme, "the trail is the organization's: %v", e)
		}
		problem(t, f.c.Get("/admin/audit?organization_id="+globex, as(scoped)), 403, "admin_forbidden")

		grantee := f.operator(admin.RoleViewer, globex)
		want(t, data(t, f.c.Get("/admin/organizations/"+globex, as(grantee)))["name"] == "Globex", "a scoped grant")
		problem(t, f.c.Get("/admin/organizations/"+acme, as(grantee)), 403, "admin_forbidden")
	})

	t.Run("testDrainsAreManagedPerOrganizationByOwners", func(t *testing.T) {
		f := newFlow(t, class, "testDrainsAreManagedPerOrganizationByOwners")
		ada := f.login("ada@example.com")
		acme := f.createOrg("Acme Rockets", ada)
		owner := f.operator(admin.RoleOwner, "")
		adminKey := f.key(admin.RoleAdmin, "", nil)
		drains := "/admin/organizations/" + acme + "/drains"
		valid := map[string]any{"endpoint": "https://hooks.example.test/audit", "secret": "a-secret-of-sixteen-chars"}

		problem(t, f.c.Post(drains, valid, as(adminKey)), 403, "admin_forbidden")
		problem(t, f.c.Post(drains, map[string]any{"endpoint": "http://hooks.example.test/audit", "secret": "a-secret-of-sixteen-chars"}, as(owner)), 422, "admin_invalid_input")
		problem(t, f.c.Post(drains, map[string]any{"endpoint": "https://hooks.example.test/audit", "secret": "short"}, as(owner)), 422, "admin_invalid_input")
		problem(t, f.c.Post("/admin/organizations/nope/drains", valid, as(owner)), 404, "admin_not_found")

		drain := data(t, f.c.Post(drains, map[string]any{"endpoint": "https://hooks.example.test/audit", "secret": "a-secret-of-sixteen-chars", "filter": []string{"org.*", "admin.drain_tested"}}, as(owner)))
		_, leaked := drain["secret"]
		want(t, reflect.DeepEqual(drain["filter"], []any{"org.*", "admin.drain_tested"}) && !leaked, "drain %v", drain)
		id := drain["id"].(string)
		want(t, reflect.DeepEqual(column(list(t, f.c.Get(drains, as(adminKey))), "id"), []any{id}), "listed")

		tested := data(t, f.c.Post(drains+"/"+id+"/test", nil, as(owner)))
		want(t, tested["id"] == id && tested["last_delivery_at"] == nil, "no HTTP client, nothing delivered: %v", tested)
		recorded := list(t, f.c.Get("/admin/audit?names=admin.drain_tested", as(owner)))
		want(t, len(recorded) == 1 && recorded[0]["organization_id"] == acme && recorded[0]["data"].(map[string]any)["drain_id"] == id, "recorded %v", recorded)

		want(t, data(t, f.c.Delete(drains+"/"+id, as(owner)))["status"] == "deleted", "deleted")
		problem(t, f.c.Delete(drains+"/"+id, as(owner)), 404, "admin_not_found")
		want(t, len(list(t, f.c.Get(drains, as(owner)))) == 0, "none left")
	})
}

func TestAdminSessionsAndMFA(t *testing.T) {
	const class = "AdminSessionsAndMfaTest"

	t.Run("testSessionsAreListedAndRevokedBySupport", func(t *testing.T) {
		f := newFlow(t, class, "testSessionsAreListedAndRevokedBySupport")
		f.login("ada@example.com")
		f.login("ada@example.com")
		adaID := f.userID("ada@example.com")
		support := f.key(admin.RoleSupport, "", nil)
		viewer := f.key(admin.RoleViewer, "", nil)
		sessions := "/admin/users/" + adaID + "/sessions"

		listed := list(t, f.c.Get(sessions, as(viewer)))
		want(t, len(listed) == 2 && reflect.DeepEqual(column(listed, "current"), []any{false, false}), "sessions %v", listed)
		first := listed[0]["id"].(string)
		problem(t, f.c.Delete(sessions+"/"+first, as(viewer)), 403, "admin_forbidden")
		want(t, data(t, f.c.Delete(sessions+"/"+first, as(support)))["status"] == "revoked", "revoked")
		problem(t, f.c.Delete(sessions+"/no-such-session", as(support)), 404, "admin_not_found")
		want(t, len(list(t, f.c.Get(sessions, as(support)))) == 1, "one left")

		f.login("ada@example.com")
		all := data(t, f.c.Delete(sessions, as(support)))
		want(t, reflect.DeepEqual(all, map[string]any{"status": "revoked", "count": 3.0}), "every family counted, the revoked one included: %v", all)
		want(t, len(list(t, f.c.Get(sessions, as(support)))) == 0, "none left")
		problem(t, f.c.Get("/admin/users/nobody/sessions", as(support)), 404, "admin_not_found")
	})

	t.Run("testMfaFactorsAreListedRemovedAndReset", func(t *testing.T) {
		f := newFlow(t, class, "testMfaFactorsAreListedRemovedAndReset")
		ctx := context.Background()
		ada := f.login("ada@example.com")
		adaID := f.userID("ada@example.com")
		owner := f.operator(admin.RoleOwner, "")
		f.enrol(ada)
		mfa := "/admin/users/" + adaID + "/mfa"

		factors := list(t, f.c.Get(mfa, as(owner)))
		_, leaked := factors[0]["secret"]
		want(t, len(factors) == 1 && factors[0]["type"] == "totp" && factors[0]["confirmed_at"] != nil && !leaked, "factors %v", factors)
		problem(t, f.c.Delete(mfa+"/nope", as(owner)), 404, "admin_not_found")
		want(t, data(t, f.c.Delete(mfa+"/"+factors[0]["id"].(string), as(owner)))["status"] == "removed", "removed")
		want(t, len(list(t, f.c.Get(mfa, as(owner)))) == 0, "none left")

		f.enrol(ada)
		codes, _ := f.srv.DB.Count(ctx, "auth_recovery_codes", store.Criteria{"user_id": adaID})
		want(t, codes > 0, "recovery codes were issued")
		want(t, reflect.DeepEqual(data(t, f.c.Delete(mfa, as(owner))), map[string]any{"status": "reset", "factors": 1.0}), "reset")
		codes, _ = f.srv.DB.Count(ctx, "auth_recovery_codes", store.Criteria{"user_id": adaID})
		want(t, codes == 0, "recovery codes removed")
		want(t, len(list(t, f.c.Get(mfa, as(owner)))) == 0, "none left")
		names := column(list(t, f.c.Get("/admin/audit?names=admin.mfa_reset,admin.mfa_factor_removed", as(owner))), "name")
		want(t, reflect.DeepEqual(names, []any{admin.AuditMFAReset, admin.AuditMFAFactorRemoved}), "audited %v", names)
	})
}
