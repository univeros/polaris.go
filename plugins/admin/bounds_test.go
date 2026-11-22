package admin_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
)

// An operator below owner manages accounts, but not the account of an operator of its own role
// or above, nor a superadmin's (decision 69): only an owner does.
func TestOnlyAnOwnerManagesAnEqualOrHigherOperatorOrASuperadmin(t *testing.T) {
	ctx := context.Background()
	f := &flow{t: t, admin: admin.New(admin.Config{})}
	f.srv = polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), f.admin))
	f.c = contracttest.NewClient(t, f.srv.Handler(), nil)

	grant := func(email string, role admin.Role) string {
		f.login(email)
		if _, err := f.admin.Grants().Grant(ctx, admin.Grant{UserID: f.userID(email), Role: role}); err != nil {
			t.Fatal(err)
		}
		return f.userID(email)
	}
	ownerID := grant("owner@example.com", admin.RoleOwner)
	peerID := grant("peer@example.com", admin.RoleAdmin)
	supportID := grant("support@example.com", admin.RoleSupport)
	root := f.login("root@example.com")
	rootID := f.userID("root@example.com")
	f.createOrg("Root", root)
	membership, _ := f.srv.DB.FindOne(ctx, "auth_memberships", store.Criteria{"user_id": rootID})
	role, _ := f.srv.DB.FindOne(ctx, "auth_roles", store.Criteria{"slug": "superadmin", "organization_id": nil})
	if err := f.srv.DB.Insert(ctx, "auth_membership_roles", store.Row{"membership_id": membership.String("id"), "role_id": role.String("id")}); err != nil {
		t.Fatal(err)
	}
	// A disabled superadmin is still a superadmin: unbanning one is managing one.
	if _, err := f.srv.DB.Update(ctx, "auth_users", store.Criteria{"id": rootID}, store.Data{"status": "disabled"}); err != nil {
		t.Fatal(err)
	}

	actions := map[string]func(id, as string) *http.Response{
		"password": func(id, as string) *http.Response {
			return f.c.Post("/admin/users/"+id+"/password", map[string]any{"password": "a brand new passphrase"}, contracttest.Bearer(as))
		},
		"ban": func(id, as string) *http.Response {
			return f.c.Post("/admin/users/"+id+"/ban", nil, contracttest.Bearer(as))
		},
		"unban": func(id, as string) *http.Response {
			return f.c.Post("/admin/users/"+id+"/unban", nil, contracttest.Bearer(as))
		},
		"remove factor": func(id, as string) *http.Response {
			return f.c.Delete("/admin/users/"+id+"/mfa/none", contracttest.Bearer(as))
		},
		"reset mfa": func(id, as string) *http.Response {
			return f.c.Delete("/admin/users/"+id+"/mfa", contracttest.Bearer(as))
		},
		"delete": func(id, as string) *http.Response { return f.c.Delete("/admin/users/"+id, contracttest.Bearer(as)) },
	}
	adminUser := f.operator(admin.RoleAdmin, "")
	for caller, credential := range map[string]string{"an admin key": f.key(admin.RoleAdmin, "", nil), "an admin user": adminUser} {
		for target, id := range map[string]string{"an owner": ownerID, "another admin": peerID, "a superadmin": rootID} {
			for name, act := range actions {
				resp := act(id, credential)
				if resp.StatusCode != http.StatusForbidden || body(t, resp)["error"] != "admin_forbidden" {
					t.Errorf("%s, %s on %s: status %d, want 403 admin_forbidden", caller, name, target, resp.StatusCode)
				}
			}
		}
		if resp := actions["reset mfa"](supportID, credential); resp.StatusCode != http.StatusOK {
			t.Errorf("%s resets the MFA of a support operator: %d", caller, resp.StatusCode)
		}
	}
	owner := f.login("owner@example.com")
	for target, id := range map[string]string{"an admin": peerID, "a superadmin": rootID} {
		if resp := actions["reset mfa"](id, owner); resp.StatusCode != http.StatusOK {
			t.Errorf("an owner manages %s: %d", target, resp.StatusCode)
		}
	}
	if resp := actions["unban"](rootID, f.key(admin.RoleOwner, "", nil)); resp.StatusCode != http.StatusOK {
		t.Errorf("an owner key unbans a superadmin: %d", resp.StatusCode)
	}
}
