package scim

import (
	"testing"

	"github.com/univeros/polaris-go/model"
)

// Regression tests for the WP8 cross-tenant finding: an organization's directory (any org owner
// can create one) could take over, disable or erase any Polaris account by its email.

// tenants is org A (owner u-owner, with a directory) and org B, owned by the victim.
func tenants(t *testing.T) (*fixture, Connection, model.User, string) {
	f := newFixture(t)
	orgA := f.organization()
	victim := f.user("u-victim", "victim@victim.example")
	orgB := must(f.srv.Graph().Orgs.CreateOrganization(f.ctx, "Beta", "", victim.ID))
	return f, f.connection(orgA, DeprovisionDelete), victim, orgB.ID
}

func ops(t *testing.T, list ...any) []operation {
	t.Helper()
	parsed, err := parsePatch(map[string]any{"schemas": []any{PatchSchema}, "Operations": list})
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestADirectoryCannotClaimAnotherOrganizationsAccount(t *testing.T) {
	f, conn, victim, _ := tenants(t)
	_, err := f.p.dir.createUser(f.ctx, conn, map[string]any{"userName": victim.Email, "displayName": "Pwned"})
	refused(t, err, 409, "an existing account on a domain the organization did not verify")
	if _, err := f.srv.Graph().Repos.Memberships.ByUserAndOrganization(f.ctx, victim.ID, conn.OrganizationID); err == nil {
		t.Fatal("the victim was joined to the attacker's organization")
	}
	if u := must(f.srv.Graph().Repos.Users.Get(f.ctx, victim.ID)); u.DisplayName != nil {
		t.Fatalf("the victim's profile was overwritten: %q", *u.DisplayName)
	}
}

func TestADirectoryCannotRenameDisableOrEraseAnAccountItDoesNotOwn(t *testing.T) {
	f, conn, victim, orgB := tenants(t)
	d := f.p.dir
	d.domains = func() any { return verifiedDomains{conn.OrganizationID: "victim.example"} }
	linked := must(d.createUser(f.ctx, conn, map[string]any{"userName": victim.Email, "displayName": "Pwned"}))
	if linked.ID != victim.ID || linked.DisplayName != nil {
		t.Fatalf("a verified-domain account joins with its profile untouched: %+v", linked)
	}

	_, err := d.patchUser(f.ctx, conn, linked, ops(t, map[string]any{"op": "replace", "path": "userName", "value": "attacker@evil.example"}))
	refused(t, err, 403, "PATCH userName of an account the directory does not own")
	_, err = d.replaceUser(f.ctx, conn, linked, map[string]any{"userName": "attacker@evil.example"})
	refused(t, err, 403, "PUT userName of an account the directory does not own")
	got := must(d.patchUser(f.ctx, conn, linked, ops(t, map[string]any{"op": "replace", "value": map[string]any{"displayName": "Pwned", "active": false}})))
	if got.Email != victim.Email || got.DisplayName != nil || got.Status != model.UserStatusActive {
		t.Fatalf("the account changed: %+v", got)
	}
	g := f.srv.Graph()
	if m := must(g.Repos.Memberships.ByUserAndOrganization(f.ctx, victim.ID, conn.OrganizationID)); m.Status != model.MembershipStatusSuspended {
		t.Fatalf("active false leaves the membership %s", m.Status)
	}
	if m := must(g.Repos.Memberships.ByUserAndOrganization(f.ctx, victim.ID, orgB)); m.Status != model.MembershipStatusActive {
		t.Fatalf("the victim's own organization was touched: %s", m.Status)
	}

	if outcome := must(d.deleteUser(f.ctx, conn, got)); outcome != "deleted" {
		t.Fatal(outcome)
	}
	if u := must(g.Repos.Users.Get(f.ctx, victim.ID)); u.Email != victim.Email || u.Status != model.UserStatusActive {
		t.Fatalf("deprovision=delete erased or disabled an account the directory does not own: %+v", u)
	}
	if _, err := g.Repos.Memberships.ByUserAndOrganization(f.ctx, victim.ID, conn.OrganizationID); err == nil {
		t.Fatal("the membership stays")
	}
}

func TestAnAccountTheDirectoryCreatedIsNoLongerItsOnceItJoinsAnotherOrganization(t *testing.T) {
	f, conn, _, orgB := tenants(t)
	d := f.p.dir
	bob := must(d.createUser(f.ctx, conn, map[string]any{"userName": "bob@acme.example"}))
	bob = must(d.patchUser(f.ctx, conn, bob, ops(t, map[string]any{"op": "replace", "path": "userName", "value": "robert@acme.example"})))
	if bob.Email != "robert@acme.example" {
		t.Fatal("the directory cannot rename the account it created")
	}
	g := f.srv.Graph()
	now := bob.CreatedAt
	if err := g.Repos.Memberships.Insert(f.ctx, model.Membership{ID: "m-b", UserID: bob.ID, OrganizationID: orgB,
		Status: model.MembershipStatusActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	_, err := d.patchUser(f.ctx, conn, bob, ops(t, map[string]any{"op": "replace", "path": "userName", "value": "attacker@evil.example"}))
	refused(t, err, 403, "the account belongs to another organization too")
}

func TestADirectoryNeverLeavesAnOrganizationWithoutAnActiveOwner(t *testing.T) {
	f := newFixture(t)
	orgID := f.organization()
	conn := f.connection(orgID, DeprovisionDeactivate)
	d := f.p.dir
	d.domains = func() any { return verifiedDomains{orgID: "acme.example"} }
	g := f.srv.Graph()
	owner := must(g.Repos.Users.Get(f.ctx, "u-owner"))
	ownerRole := must(g.Repos.Roles.ByOrganizationAndSlug(f.ctx, &orgID, "owner"))

	_, err := d.patchGroup(f.ctx, conn, ownerRole, ops(t, map[string]any{"op": "replace", "path": "members", "value": []any{}}))
	refused(t, err, 409, "emptying the owner role")
	_, err = d.patchGroup(f.ctx, conn, ownerRole, ops(t, map[string]any{"op": "remove", "path": `members[value eq "u-owner"]`}))
	refused(t, err, 409, "removing the last owner")
	_, err = d.replaceGroup(f.ctx, conn, ownerRole, map[string]any{"displayName": ownerRole.Name, "members": []any{}})
	refused(t, err, 409, "PUT of the owner role without members")
	_, err = d.patchUser(f.ctx, conn, owner, ops(t, map[string]any{"op": "replace", "path": "active", "value": false}))
	refused(t, err, 409, "suspending the last active owner")
	_, err = d.deleteUser(f.ctx, conn, owner)
	refused(t, err, 409, "deprovisioning the last active owner")
	if links := must(g.Repos.MembershipRoles.ListByRole(f.ctx, ownerRole.ID)); len(links) != 1 {
		t.Fatalf("owner links %d", len(links))
	}
	if m := must(g.Repos.Memberships.ByUserAndOrganization(f.ctx, owner.ID, orgID)); m.Status != model.MembershipStatusActive {
		t.Fatalf("owner membership %s", m.Status)
	}
}
