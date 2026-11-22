package authz

import (
	"slices"
	"testing"

	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// The platform permissions (users.read, users.manage) reach every account of the instance, so no
// organization's role grants them, whatever its rows say (decision 76).
func TestAnOrganizationRoleNeverGrantsAPlatformPermission(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		u := member(t, r, org)
		role := orgRole(t, r, org, "support")
		for _, key := range []string{UsersManage, UsersRead, MembersRead} {
			grant(t, r, role, key)
		}
		assign(t, r, u, org, role)
		a, err := NewResolver(r).Resolve(ctx, u, org)
		must(t, err)
		if !slices.Equal(a.Scope, []string{MembersRead}) {
			t.Fatalf("an organization role resolved to %v, want only %s", a.Scope, MembersRead)
		}
	})
}

// DropPlatformGrants removes those grants from organization roles and leaves the system roles'.
func TestPlatformGrantsAreRemovedFromOrganizationRoles(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter, r *repository.Repos) {
		role := orgRole(t, r, org, "support")
		for _, key := range []string{UsersManage, UsersRead, MembersRead} {
			grant(t, r, role, key)
		}
		removed, err := DropPlatformGrants(ctx, db, nil)
		must(t, err)
		if len(removed) != 2 {
			t.Fatalf("removed %v, want the two platform grants", removed)
		}
		left, err := r.RolePermissions.ListByRole(ctx, role)
		must(t, err)
		if len(left) != 1 {
			t.Fatalf("the role keeps %d grant(s), want its organization one", len(left))
		}
		system, err := r.Roles.ByOrganizationAndSlug(ctx, nil, RoleSuperadmin)
		must(t, err)
		manage, err := r.Permissions.ByKey(ctx, UsersManage)
		must(t, err)
		if _, err := r.RolePermissions.Get(ctx, system.ID, manage.ID); err != nil {
			t.Fatalf("the system superadmin role lost %s: %v", UsersManage, err)
		}
		if again, err := DropPlatformGrants(ctx, db, nil); err != nil || len(again) != 0 {
			t.Fatalf("a second run removed %v (%v)", again, err)
		}
	})
}
