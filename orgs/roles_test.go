package orgs

import (
	"slices"
	"testing"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

func rolesBySlug(t *testing.T, f *fixture, org string) map[string]Role {
	t.Helper()
	roles, err := f.svc.ListRoles(ctx, org)
	must(t, err)
	out := map[string]Role{}
	for _, r := range roles {
		out[r.Slug] = r
	}
	return out
}

// Port of RoleEndpointsTest::testListsTheClonedTemplateRolesWithTheirPermissions.
func TestListsTheClonedTemplateRolesWithTheirPermissions(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, _ := f.orgOwnedBy(t, "founder@example.com")
		roles := rolesBySlug(t, f, org)
		if len(roles) != 3 || roles["owner"].IsSystem || roles["owner"].Description == nil {
			t.Fatalf("roles = %+v", roles)
		}
		if !slices.Contains(roles["owner"].PermissionKeys, authz.OrgDelete) ||
			slices.Contains(roles["admin"].PermissionKeys, authz.OrgDelete) ||
			!slices.Contains(roles["member"].PermissionKeys, authz.RolesRead) {
			t.Errorf("roles = %+v", roles)
		}
		none, err := f.svc.ListRoles(ctx, "no-such-org")
		must(t, err)
		if none == nil || len(none) != 0 {
			t.Errorf("ListRoles = %#v; want empty, not nil", none)
		}
	})
}

// Port of testPermissionsCatalogIsAvailableToAnyAuthenticatedUser.
func TestPermissionsListsTheStoredCatalog(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		perms, err := f.svc.Permissions(ctx)
		must(t, err)
		keys := map[string]string{}
		for _, p := range perms {
			keys[p.Key] = p.Description
		}
		if len(perms) != len(authz.NewCatalog().Permissions()) || keys[authz.MembersInvite] == "" || keys[authz.OrgDelete] == "" {
			t.Errorf("permissions = %+v", perms)
		}
	})
}

// Port of testOwnerCreatesACustomRoleAndItIsGrantable.
func TestOwnerCreatesACustomRoleAndItIsGrantable(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		member := f.member(t, org, "member@example.com", model.MembershipStatusActive, "member")
		role, err := f.svc.CreateRole(ctx, owner, org, NewRole{
			Name: "  Support ", Slug: "support", Description: ptr("Helps customers"),
			PermissionKeys: []string{authz.MembersRead, authz.OrgRead, authz.OrgRead},
		})
		must(t, err)
		if role.Name != "Support" || role.Slug != "support" || deref(role.Description) != "Helps customers" || role.IsSystem ||
			len(role.PermissionKeys) != 2 || !slices.Contains(role.PermissionKeys, authz.OrgRead) {
			t.Errorf("role = %+v", role)
		}
		stored, err := f.r.Roles.Get(ctx, role.ID)
		must(t, err)
		if stored.OrganizationID == nil || *stored.OrganizationID != org || !stored.CreatedAt.Equal(t0) {
			t.Errorf("stored = %+v", stored)
		}
		if got := ofType[event.RoleCreated](f.events); len(got) != 1 || got[0] != (event.RoleCreated{OrganizationID: org, RoleID: role.ID, ActorUserID: owner}) {
			t.Errorf("events = %+v", got)
		}
		must(t, f.svc.ChangeMemberRoles(ctx, owner, org, member, []string{"support"}))
		if got := f.rolesOf(t, org, member); !slices.Equal(got, []string{"support"}) {
			t.Errorf("roles = %v", got)
		}
	})
}

// Port of testDuplicateSlugConflicts, testRejectsUnknownPermissionKeysAndBadInput and
// testActorCannotPutPermissionsTheyDoNotHoldIntoARole.
func TestCreateRoleRefusals(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		admin := f.member(t, org, "admin@example.com", model.MembershipStatusActive, "admin")
		create := func(actor string, r NewRole) error {
			_, err := f.svc.CreateRole(ctx, actor, org, r)
			return err
		}
		wantRefusal(t, create(owner, NewRole{Name: "Admins", Slug: "admin"}), ErrConflict, `The role slug "admin" is already taken in this organization.`)
		wantRefusal(t, create(owner, NewRole{Name: " \t", Slug: "x"}), ErrInvalid, MsgRoleName)
		for _, slug := range []string{"", "-x", "Upper", "a b", "x\n", string(make([]byte, 81))} {
			wantRefusal(t, create(owner, NewRole{Name: "X", Slug: slug}), ErrInvalid, MsgRoleSlug)
		}
		wantRefusal(t, create(owner, NewRole{Name: "X", Slug: "x", PermissionKeys: []string{"made.up"}}), ErrInvalid, "Unknown permission key: made.up")
		wantForbidden(t, create(admin, NewRole{Name: "X", Slug: "x", PermissionKeys: []string{authz.OrgDelete}}), authz.MsgEscalation)
		if f.count(t, "auth_roles", store.Criteria{"organization_id": org}) != 3 || len(ofType[event.RoleCreated](f.events)) != 0 {
			t.Error("a refused create left a row or an event")
		}
		must(t, create(admin, NewRole{Name: "X", Slug: "0-x", PermissionKeys: []string{authz.OrgUpdate}}))
	})
}

// Port of testUpdateChangesNameAndPermissions and testUpdateCanStripAllPermissionsFromARole.
func TestUpdateRole(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		role, err := f.svc.CreateRole(ctx, owner, org, NewRole{Name: "Support", Slug: "support", PermissionKeys: []string{authz.OrgRead}})
		must(t, err)
		f.clock.Advance(60e9)

		updated, err := f.svc.UpdateRole(ctx, owner, org, role.ID, RoleChanges{
			Name: ptr("Customer Support"), PermissionKeys: &[]string{authz.OrgRead, authz.MembersRead},
		})
		must(t, err)
		if updated.Name != "Customer Support" || updated.Slug != "support" || updated.Description != nil ||
			!sameSet(updated.PermissionKeys, []string{authz.OrgRead, authz.MembersRead}) {
			t.Errorf("updated = %+v", updated)
		}
		stored, err := f.r.Roles.Get(ctx, role.ID)
		must(t, err)
		if !stored.UpdatedAt.Equal(f.clock.Now()) {
			t.Errorf("updated_at = %v", stored.UpdatedAt)
		}

		untouched, err := f.svc.UpdateRole(ctx, owner, org, role.ID, RoleChanges{Description: ptr("Helps")})
		must(t, err)
		if deref(untouched.Description) != "Helps" || len(untouched.PermissionKeys) != 2 || untouched.Name != "Customer Support" {
			t.Errorf("untouched = %+v", untouched)
		}
		stripped, err := f.svc.UpdateRole(ctx, owner, org, role.ID, RoleChanges{PermissionKeys: &[]string{}})
		must(t, err)
		if len(stripped.PermissionKeys) != 0 || f.count(t, "auth_role_permissions", store.Criteria{"role_id": role.ID}) != 0 {
			t.Errorf("stripped = %+v", stripped)
		}
		if got := ofType[event.RoleUpdated](f.events); len(got) != 3 || got[0] != (event.RoleUpdated{OrganizationID: org, RoleID: role.ID, ActorUserID: owner}) {
			t.Errorf("events = %+v", got)
		}

		_, err = f.svc.UpdateRole(ctx, owner, org, role.ID, RoleChanges{Name: ptr("  ")})
		wantRefusal(t, err, ErrInvalid, MsgRoleName)
		_, err = f.svc.UpdateRole(ctx, owner, org, role.ID, RoleChanges{PermissionKeys: &[]string{"made.up"}})
		wantRefusal(t, err, ErrInvalid, "Unknown permission key: made.up")
		admin := f.member(t, org, "admin@example.com", model.MembershipStatusActive, "admin")
		_, err = f.svc.UpdateRole(ctx, admin, org, role.ID, RoleChanges{PermissionKeys: &[]string{authz.OrgDelete}})
		wantForbidden(t, err, authz.MsgEscalation)
	})
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// Port of testTheOwnerRoleIsImmutable, testTheClonedTemplatesAreEditableButNotDeletable,
// testGlobalSystemRolesAreNotReachableThroughTheOrgPath and testUnknownRoleIsNotFound.
func TestImmutableAndUnreachableRoles(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		other, _ := f.orgOwnedBy(t, "other@example.com")
		update := func(roleID string) error {
			_, err := f.svc.UpdateRole(ctx, owner, org, roleID, RoleChanges{Name: ptr("Renamed")})
			return err
		}

		ownerRole := f.roleID(t, org, "owner")
		wantForbidden(t, update(ownerRole), MsgOwnerRole)
		wantForbidden(t, f.svc.DeleteRole(ctx, owner, org, ownerRole), MsgOwnerRole)
		for _, slug := range []string{"admin", "member"} {
			must(t, update(f.roleID(t, org, slug)))
			wantForbidden(t, f.svc.DeleteRole(ctx, owner, org, f.roleID(t, org, slug)), "The "+slug+" role cannot be deleted.")
		}

		system, err := f.r.Roles.ByOrganizationAndSlug(ctx, nil, authz.RoleSuperadmin)
		must(t, err)
		for _, id := range []string{system.ID, f.roleID(t, other, "member"), "unknown"} {
			wantRefusal(t, update(id), ErrNotFound, MsgRoleNotFound)
			wantRefusal(t, f.svc.DeleteRole(ctx, owner, org, id), ErrNotFound, MsgRoleNotFound)
		}

		// A system row inside an organization is immutable too.
		sys := model.Role{ID: "sys-in-org", OrganizationID: &org, Name: "Sys", Slug: "sys", IsSystem: true, CreatedAt: t0, UpdatedAt: t0}
		must(t, f.r.Roles.Insert(ctx, sys))
		wantForbidden(t, update(sys.ID), MsgSystemRole)
	})
}

// Port of testDeletingARoleDetachesItFromMembers.
func TestDeletingARoleDetachesItFromMembers(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		role, err := f.svc.CreateRole(ctx, owner, org, NewRole{Name: "Support", Slug: "support", PermissionKeys: []string{authz.OrgRead}})
		must(t, err)
		member := f.member(t, org, "member@example.com", model.MembershipStatusActive, "member", "support")

		must(t, f.svc.DeleteRole(ctx, owner, org, role.ID))
		if got := f.rolesOf(t, org, member); !slices.Equal(got, []string{"member"}) {
			t.Errorf("roles = %v", got)
		}
		if f.count(t, "auth_role_permissions", store.Criteria{"role_id": role.ID}) != 0 {
			t.Error("grants cascade away")
		}
		if got := ofType[event.RoleDeleted](f.events); len(got) != 1 || got[0] != (event.RoleDeleted{OrganizationID: org, RoleID: role.ID, ActorUserID: owner}) {
			t.Errorf("events = %+v", got)
		}
	})
}
