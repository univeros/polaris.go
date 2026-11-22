package admin_test

import (
	"context"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/store"
)

func TestAdminUsers(t *testing.T) {
	const class = "AdminUsersTest"

	t.Run("testAnOwnerManagesUsersAndEveryActionIsAudited", func(t *testing.T) {
		f := newFlow(t, class, "testAnOwnerManagesUsersAndEveryActionIsAudited")
		ada := f.login("ada@example.com")
		adaID := f.userID("ada@example.com")
		owner := f.operator(admin.RoleOwner, "")
		ownerID := f.userID(operator)

		all := f.c.Get("/admin/users", as(owner))
		want(t, reflect.DeepEqual(column(list(t, all), "email"), []any{"ada@example.com", operator}), "oldest first")
		want(t, body(t, all)["next_cursor"] == nil, "one page")
		first := body(t, f.c.Get("/admin/users?limit=1", as(owner)))
		want(t, first["next_cursor"] == adaID, "cursor %v", first["next_cursor"])
		second := f.c.Get("/admin/users?limit=1&cursor="+adaID, as(owner))
		want(t, reflect.DeepEqual(column(list(t, second), "email"), []any{operator}) && body(t, second)["next_cursor"] == nil, "second page")
		want(t, reflect.DeepEqual(column(list(t, f.c.Get("/admin/users?email=ada%40example.com", as(owner))), "id"), []any{adaID}), "email filter")
		problem(t, f.c.Get("/admin/users?status=banned", as(owner)), 422, "admin_invalid_input")

		read := data(t, f.c.Get("/admin/users/"+adaID, as(owner)))
		want(t, read["email"] == "ada@example.com" && read["status"] == "active" && read["email_verified"] == true && read["last_active_at"] != nil, "read %v", read)
		problem(t, f.c.Get("/admin/users/nobody", as(owner)), 404, "admin_not_found")

		want(t, data(t, f.c.Post("/admin/users/"+adaID+"/ban", nil, as(owner)))["status"] == "disabled", "ban")
		want(t, data(t, f.c.Get("/admin/users/"+adaID, as(owner)))["status"] == "disabled", "banned")
		want(t, f.c.Post("/auth/login", map[string]any{"email": "ada@example.com", "password": password}).StatusCode != 200, "a banned user cannot sign in")
		problem(t, f.c.Post("/admin/users/"+ownerID+"/ban", nil, as(owner)), 409, "admin_conflict")
		want(t, data(t, f.c.Post("/admin/users/"+adaID+"/unban", nil, as(owner)))["status"] == "active", "unban")

		weak := problem(t, f.c.Post("/admin/users/"+adaID+"/password", map[string]any{"password": "short"}, as(owner)), 422, "admin_invalid_input")
		want(t, len(weak["errors"].([]any)) > 0, "violations listed")
		want(t, data(t, f.c.Post("/admin/users/"+adaID+"/password", map[string]any{"password": "a brand new passphrase"}, as(owner)))["status"] == "password_set", "password")
		wantStatus(t, f.c.Post("/auth/login", map[string]any{"email": "ada@example.com", "password": "a brand new passphrase"}), 200)
		want(t, f.c.Post("/auth/login", map[string]any{"email": "ada@example.com", "password": password}).StatusCode != 200, "old password")

		imp := f.c.Post("/admin/users/"+adaID+"/impersonate", nil, as(owner))
		wantStatus(t, imp, 201)
		token := data(t, imp)
		want(t, token["token_type"] == "Bearer" && token["impersonated_by"] == ownerID, "impersonation %v", token)
		access := token["access_token"].(string)
		want(t, data(t, f.c.Get("/auth/me", as(access)))["email"] == "ada@example.com", "the token acts as the user")
		problem(t, f.c.Get("/admin/users", as(access)), 403, "admin_impersonation_denied")

		want(t, data(t, f.c.Delete("/admin/users/"+adaID, as(owner)))["status"] == "deleted", "delete")
		deleted := data(t, f.c.Get("/admin/users/"+adaID, as(owner)))
		want(t, strings.HasSuffix(deleted["email"].(string), "@deleted.invalid") && deleted["status"] == "disabled", "tombstone %v", deleted)
		problem(t, f.c.Delete("/admin/users/"+ownerID, as(owner)), 409, "admin_conflict")

		trail := list(t, f.c.Get("/admin/audit?subject_id="+adaID+"&names=admin.user_banned,admin.user_unbanned,admin.password_set,admin.user_impersonated,admin.user_deleted", as(owner)))
		want(t, reflect.DeepEqual(column(trail, "name"), []any{admin.AuditUserDeleted, admin.AuditUserImpersonated, admin.AuditPasswordSet, admin.AuditUserUnbanned, admin.AuditUserBanned}), "trail %v", column(trail, "name"))
		for _, e := range trail {
			want(t, e["actor_type"] == "admin" && e["actor_id"] == ownerID, "actor %v", e)
		}
		want(t, reflect.DeepEqual(trail[4]["data"], map[string]any{"actor_role": "owner", "actor_scope": "instance"}), "data %v", trail[4]["data"])
		want(t, slices.Contains(column(list(t, f.c.Get("/admin/audit?actor_id="+ownerID, as(owner))), "name"), any("user.disabled")), "the core event carries the operator as actor too")

		problem(t, f.c.Get("/admin/users"), 401, "admin_unauthorized")
		problem(t, f.c.Get("/admin/users", as(ada)), 401, "admin_unauthorized")
	})

	t.Run("testASuperadminIsAnOwnerWithoutAGrantAndCannotBeImpersonated", func(t *testing.T) {
		f := newFlow(t, class, "testASuperadminIsAnOwnerWithoutAGrantAndCannotBeImpersonated")
		ctx := context.Background()
		root := f.login("root@example.com")
		rootID := f.userID("root@example.com")
		problem(t, f.c.Get("/admin/keys", as(root)), 401, "admin_unauthorized")
		f.createOrg("Root", root)
		membership, _ := f.srv.DB.FindOne(ctx, "auth_memberships", store.Criteria{"user_id": rootID})
		role, _ := f.srv.DB.FindOne(ctx, "auth_roles", store.Criteria{"slug": "superadmin", "organization_id": nil})
		if err := f.srv.DB.Insert(ctx, "auth_membership_roles", store.Row{"membership_id": membership.String("id"), "role_id": role.String("id")}); err != nil {
			t.Fatal(err)
		}

		keys := f.c.Get("/admin/keys", as(root))
		wantStatus(t, keys, http.StatusOK)
		want(t, len(list(t, keys)) == 0, "owner-only route, no keys")

		owner := f.operator(admin.RoleOwner, "")
		problem(t, f.c.Post("/admin/users/"+rootID+"/impersonate", nil, as(owner)), 403, "admin_impersonation_denied")
	})

	t.Run("testAViewerKeyReadsAndCannotMutateAndADeletedKeyIsRefused", func(t *testing.T) {
		f := newFlow(t, class, "testAViewerKeyReadsAndCannotMutateAndADeletedKeyIsRefused")
		f.login("ada@example.com")
		adaID := f.userID("ada@example.com")
		viewer := f.key(admin.RoleViewer, "", nil)
		support := f.key(admin.RoleSupport, "", nil)

		want(t, len(list(t, f.c.Get("/admin/users", as(viewer)))) == 1, "a viewer reads")
		problem(t, f.c.Post("/admin/users/"+adaID+"/ban", nil, as(viewer)), 403, "admin_forbidden")
		problem(t, f.c.Post("/admin/users/"+adaID+"/ban", nil, as(support)), 403, "admin_forbidden")
		problem(t, f.c.Post("/admin/users/"+adaID+"/impersonate", nil, as(support)), 403, "admin_forbidden")
		problem(t, f.c.Get("/admin/keys", as(support)), 403, "admin_forbidden")

		owner := f.operator(admin.RoleOwner, "")
		keys := list(t, f.c.Get("/admin/keys", as(owner)))
		want(t, len(keys) == 2, "two keys: %v", keys)
		_, shown := keys[0]["key"]
		want(t, !shown, "the secret is never listed")
		want(t, data(t, f.c.Delete("/admin/keys/"+keys[0]["id"].(string), as(owner)))["status"] == "deleted", "delete key")
		problem(t, f.c.Get("/admin/users", as(viewer)), 401, "admin_unauthorized")
		problem(t, f.c.Get("/admin/users", as("pak_not-a-key")), 401, "admin_unauthorized")
	})
}

func TestAdminKeysGrantsAndStats(t *testing.T) {
	const class = "AdminKeysGrantsAndStatsTest"

	t.Run("testKeysAndGrantsAreOwnerOnlyAndAudited", func(t *testing.T) {
		f := newFlow(t, class, "testKeysAndGrantsAreOwnerOnlyAndAudited")
		ada := f.login("ada@example.com")
		adaID := f.userID("ada@example.com")
		owner := f.operator(admin.RoleOwner, "")

		for _, bad := range []map[string]any{
			{"name": "", "role": "support"},
			{"name": "CI", "role": "root"},
			{"name": "CI", "role": "support", "ip_allowlist": []string{"nowhere"}},
			{"name": "CI", "role": "support", "expires_at": "soon"},
			{"name": "CI", "role": "support", "scope": "no-such-org"},
		} {
			problem(t, f.c.Post("/admin/keys", bad, as(owner)), 422, "admin_invalid_input")
		}
		created := data(t, f.c.Post("/admin/keys", map[string]any{"name": "CI", "role": "support", "ip_allowlist": []string{"10.0.0.0/8"}, "expires_at": "2030-01-01T00:00:00+00:00"}, as(owner)))
		secret, _ := created["key"].(string)
		want(t, strings.HasPrefix(secret, admin.KeyPrefix) && created["name"] == "CI" && created["role"] == "support" && created["scope"] == "instance" &&
			reflect.DeepEqual(created["ip_allowlist"], []any{"10.0.0.0/8"}) && created["expires_at"] == "2030-01-01T00:00:00Z", "created %v", created)
		problem(t, f.c.Get("/admin/users", as(secret)), 401, "admin_unauthorized") // the test client has no address

		problem(t, f.c.Get("/admin/users", as(ada)), 401, "admin_unauthorized")
		problem(t, f.c.Post("/admin/grants", map[string]any{"user_id": adaID, "role": "boss"}, as(owner)), 422, "admin_invalid_input")
		problem(t, f.c.Post("/admin/grants", map[string]any{"user_id": "nobody", "role": "support"}, as(owner)), 404, "admin_not_found")
		grant := data(t, f.c.Post("/admin/grants", map[string]any{"user_id": adaID, "role": "support"}, as(owner)))
		want(t, grant["user_id"] == adaID && grant["role"] == "support" && grant["scope"] == "instance", "grant %v", grant)
		want(t, len(list(t, f.c.Get("/admin/users", as(ada)))) == 2, "ada is an operator now")
		problem(t, f.c.Post("/admin/users/"+f.userID(operator)+"/ban", nil, as(ada)), 403, "admin_forbidden")
		problem(t, f.c.Get("/admin/grants", as(ada)), 403, "admin_forbidden")

		replaced := data(t, f.c.Post("/admin/grants", map[string]any{"user_id": adaID, "role": "viewer", "expires_at": "2020-01-01T00:00:00+00:00"}, as(owner)))
		want(t, replaced["id"] == grant["id"], "one grant per user")
		problem(t, f.c.Get("/admin/users", as(ada)), 401, "admin_unauthorized") // lapsed

		want(t, len(list(t, f.c.Get("/admin/grants", as(owner)))) == 2, "the operator's own and ada's")
		want(t, data(t, f.c.Delete("/admin/grants/"+grant["id"].(string), as(owner)))["status"] == "deleted", "revoke")
		problem(t, f.c.Delete("/admin/grants/"+grant["id"].(string), as(owner)), 404, "admin_not_found")
		names := column(list(t, f.c.Get("/admin/audit?names=admin.key_created,admin.grant_created,admin.grant_deleted", as(owner))), "name")
		want(t, reflect.DeepEqual(names, []any{admin.AuditGrantDeleted, admin.AuditGrantCreated, admin.AuditGrantCreated, admin.AuditKeyCreated}), "audited %v", names)
	})

	t.Run("testAnOrganizationOwnerCreatesKeysAndGrantsForTheirOrganizationOnly", func(t *testing.T) {
		f := newFlow(t, class, "testAnOrganizationOwnerCreatesKeysAndGrantsForTheirOrganizationOnly")
		ada := f.login("ada@example.com")
		adaID := f.userID("ada@example.com")
		acme := f.createOrg("Acme Rockets", ada)
		globex := f.createOrg("Globex", ada)
		orgOwner := f.key(admin.RoleOwner, acme, nil)

		problem(t, f.c.Post("/admin/keys", map[string]any{"name": "Wide", "role": "viewer"}, as(orgOwner)), 403, "admin_forbidden")
		problem(t, f.c.Post("/admin/keys", map[string]any{"name": "Other", "role": "viewer", "scope": globex}, as(orgOwner)), 403, "admin_forbidden")
		want(t, data(t, f.c.Post("/admin/keys", map[string]any{"name": "Acme", "role": "viewer", "scope": acme}, as(orgOwner)))["scope"] == acme, "scoped key")
		problem(t, f.c.Post("/admin/grants", map[string]any{"user_id": adaID, "role": "viewer"}, as(orgOwner)), 403, "admin_forbidden")
		want(t, data(t, f.c.Post("/admin/grants", map[string]any{"user_id": adaID, "role": "viewer", "scope": acme}, as(orgOwner)))["scope"] == acme, "scoped grant")
		want(t, data(t, f.c.Get("/admin/organizations/"+acme, as(ada)))["name"] == "Acme Rockets", "ada reads her organization as a scoped viewer")
		problem(t, f.c.Get("/admin/keys", as(orgOwner)), 403, "admin_forbidden") // listing keys is instance-wide
	})

	t.Run("testStatsCountTheInstance", func(t *testing.T) {
		f := newFlow(t, class, "testStatsCountTheInstance")
		f.login("ada@example.com")
		f.login("ada@example.com")
		bob := f.login("bob@example.com")
		f.createOrg("Acme Rockets", bob)
		in := time.Now().Add(time.Hour)
		viewer := f.key(admin.RoleViewer, "", &in)

		stats := data(t, f.c.Get("/admin/stats", as(viewer)))
		want(t, reflect.DeepEqual(stats["totals"], map[string]any{"users": 2.0, "organizations": 1.0, "active_sessions": 3.0}), "totals %v", stats["totals"])
		want(t, reflect.DeepEqual(stats["sign_ups"], map[string]any{"24h": 2.0, "7d": 2.0, "30d": 2.0}), "sign-ups %v", stats["sign_ups"])
		want(t, reflect.DeepEqual(stats["sign_ins"], map[string]any{"24h": 3.0, "7d": 3.0, "30d": 3.0}), "sign-ins %v", stats["sign_ins"])
		want(t, reflect.DeepEqual(stats["active_users"], map[string]any{"24h": 2.0, "7d": 2.0, "30d": 2.0}), "active %v", stats["active_users"])
		problem(t, f.c.Get("/admin/stats"), 401, "admin_unauthorized")
	})
}
