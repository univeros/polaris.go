package apikeys_test

import (
	"context"
	"testing"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/apikeys"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

func freeFlow(t *testing.T) *flow {
	t.Helper()
	f := &flow{t: t, trail: audit.New(audit.Config{}), keys: apikeys.New(apikeys.Config{RotationGrace: time.Hour})}
	f.srv = polaristest.New(t, polaristest.WithPlugins(f.trail, f.keys))
	f.c = contracttest.NewClient(t, f.srv.Handler(), nil)
	return f
}

// joinAs makes userID an active member of the organization with one of its roles.
func (f *flow) joinAs(userID, orgID, slug string) {
	f.t.Helper()
	ctx, repos, now := context.Background(), f.srv.Graph().Repos(), time.Now().UTC().Truncate(time.Second)
	m := model.Membership{ID: repository.NewID(), UserID: userID, OrganizationID: orgID, Status: model.MembershipStatusActive, JoinedAt: &now, CreatedAt: now, UpdatedAt: now}
	if err := repos.Memberships.Insert(ctx, m); err != nil {
		f.t.Fatal(err)
	}
	role, err := repos.Roles.ByOrganizationAndSlug(ctx, &orgID, slug)
	if err == nil {
		err = repos.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: m.ID, RoleID: role.ID})
	}
	if err != nil {
		f.t.Fatal(err)
	}
}

// Whoever reads a rotated key's secret is who the key acts as: rotating a colleague's organization key
// is no way to act as them.
func TestARotatedKeyActsAsWhoRotatedIt(t *testing.T) {
	f := freeFlow(t)
	adaID, ada := f.login("ada@example.com")
	orgID, ada := f.organization(ada, "Acme")
	bobID, bob := f.login("bob@example.com")
	f.joinAs(bobID, orgID, authz.RoleAdmin)
	bob, _ = data(t, f.c.Post("/auth/switch-org", map[string]any{"organization_id": orgID}, contracttest.Bearer(bob)))["access_token"].(string)
	create := f.c.Post("/api-keys", map[string]any{"name": "CI", "organization_id": orgID, "permissions": []string{"org.read"}}, contracttest.Bearer(ada))
	status(t, create, 201)
	key := data(t, create)
	subject := func(secret any) any {
		me := f.c.Get("/auth/me", contracttest.Bearer(secret.(string)))
		status(t, me, 200)
		return data(t, me)["id"]
	}
	rotated := f.c.Post("/api-keys/"+key["id"].(string)+"/rotate", nil, contracttest.Bearer(bob))
	status(t, rotated, 201)
	successor := data(t, rotated)
	if subject(key["key"]) != adaID || subject(successor["key"]) != bobID {
		t.Fatalf("the key acts as %v, its successor as %v (ada %s, bob %s)", subject(key["key"]), subject(successor["key"]), adaID, bobID)
	}
	status(t, f.c.Get("/orgs/"+orgID, contracttest.Bearer(successor["key"].(string))), 200, "with the key's permissions")
}

// verify answers what the key would do now: nothing for a disabled subject, and only the permissions
// the subject still holds.
func TestVerifyAnswersWhatTheKeyWouldDo(t *testing.T) {
	f := freeFlow(t)
	ctx := context.Background()
	_, asker := f.login("asker@example.com")
	adaID, ada := f.login("ada@example.com")
	orgID, ada := f.organization(ada, "Acme")
	secret := data(t, f.c.Post("/api-keys", map[string]any{"name": "CI", "permissions": []string{"org.read"}}, contracttest.Bearer(ada)))["key"].(string)
	verify := func() map[string]any {
		return data(t, f.c.Post("/api-keys/verify", map[string]any{"key": secret}, contracttest.Bearer(asker)))
	}
	if v := verify(); v["valid"] != true || len(v["permissions"].([]any)) != 1 {
		t.Fatalf("live %v", v)
	}
	if _, err := f.srv.Graph().DB().Update(ctx, "auth_memberships", store.Criteria{"user_id": adaID}, store.Data{"status": model.MembershipStatusSuspended}); err != nil {
		t.Fatal(err)
	}
	status(t, f.c.Get("/orgs/"+orgID, contracttest.Bearer(secret)), 403)
	if v := verify(); v["valid"] != true || len(v["permissions"].([]any)) != 0 {
		t.Fatalf("a suspended member's %v", v)
	}
	if err := services.Of(f.srv.Graph()).Identity.DisableUser(ctx, "operator", adaID); err != nil {
		t.Fatal(err)
	}
	if v := verify(); v["valid"] != false || len(v) != 1 {
		t.Fatalf("a disabled account's %v", v)
	}
}

// With an MFA factor, a key is created and rotated with a recent authentication only.
func TestCreatingAndRotatingAKeyTakeAStepUp(t *testing.T) {
	f := freeFlow(t)
	ctx, g, now := context.Background(), f.srv.Graph(), time.Now().UTC().Truncate(time.Second)
	userID, fresh := f.login("ada@example.com")
	id := data(t, f.c.Post("/api-keys", map[string]any{"name": "CI"}, contracttest.Bearer(fresh)))["id"].(string)
	if err := g.Repos().MFAFactors.Insert(ctx, model.MFAFactor{ID: repository.NewID(), UserID: userID, Type: model.FactorTOTP, ConfirmedAt: &now, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	old := now.Add(-time.Hour).Unix()
	stale, err := g.Sessions().Issue(ctx, token.SessionPrincipal{UserID: userID, AMR: []string{"pwd", "otp"}, MFA: true, AuthTime: &old}, token.ClientContext{})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api-keys", "/api-keys/" + id + "/rotate"} {
		refused := f.c.Post(path, map[string]any{"name": "CI"}, contracttest.Bearer(stale.AccessToken))
		status(t, refused, 401)
		if contracttest.JSON(t, refused)["error"] != "step_up_required" {
			t.Fatalf("%s: want step_up_required", path)
		}
	}
	status(t, f.c.Post("/api-keys/"+id+"/rotate", nil, contracttest.Bearer(fresh)), 201)
}
