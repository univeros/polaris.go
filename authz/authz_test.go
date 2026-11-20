package authz

// Ports of PHP tests/Authorization/PermissionCatalogTest and tests/Persistence/{GateTest,
// PermissionResolverTest,PermissionCatalogSeedPersistenceTest}, run on memstore and SQLite.

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/sqlstore"
)

var (
	ctx = context.Background()
	now = time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
)

const org = "01910000-0000-7000-8000-0000000000aa"

// backends runs fn on memstore and SQLite (foreign keys on), both seeded with the core catalog.
func backends(t *testing.T, fn func(t *testing.T, db store.Adapter, r *repository.Repos)) {
	t.Helper()
	run := func(t *testing.T, db store.Adapter) {
		must(t, Seed(ctx, db, NewCatalog(), clock.NewFrozen(now)))
		fn(t, db, repository.New(db))
	}
	t.Run("memory", func(t *testing.T) { run(t, memstore.New(schema.Core()...)) })
	t.Run("sqlite", func(t *testing.T) {
		s, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "p.db")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)")
		must(t, err)
		t.Cleanup(func() { _ = s.DB().Close() })
		must(t, s.CreateSchema(ctx, schema.Core()))
		run(t, s)
	})
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func keys(ps []Permission) []string {
	out := []string{}
	for _, p := range ps {
		out = append(out, p.Key)
	}
	return out
}

func template(t *testing.T, slug string) RoleTemplate {
	for _, tpl := range NewCatalog().RoleTemplates() {
		if tpl.Slug == slug {
			return tpl
		}
	}
	t.Fatalf("no template %s", slug)
	return RoleTemplate{}
}

func TestCatalogListsTheV1Permissions(t *testing.T) {
	ps := NewCatalog().Permissions()
	want := []string{"org.read", "org.update", "org.delete", "members.read", "members.invite", "members.update",
		"members.remove", "roles.read", "roles.manage", "users.read", "users.manage", "audit.read"}
	if !slices.Equal(keys(ps), want) {
		t.Fatalf("keys %v", keys(ps))
	}
	for _, p := range ps {
		if p.Description == "" {
			t.Errorf("%s has no description", p.Key)
		}
	}
}

func TestCatalogMergesContributions(t *testing.T) {
	ps := NewCatalog(map[string]string{"billing.manage": "Manage billing", "org.read": "Overridden"},
		map[string]string{"a.b": "A"}).Permissions()
	if got := keys(ps); !slices.Equal(got[12:], []string{"billing.manage", "a.b"}) || got[0] != "org.read" {
		t.Fatalf("keys %v", got)
	}
	if ps[0].Description != "Overridden" || ps[12].Description != "Manage billing" {
		t.Fatalf("descriptions %+v", ps)
	}
}

func TestRoleTemplates(t *testing.T) {
	var slugs []string
	for _, tpl := range NewCatalog().RoleTemplates() {
		slugs = append(slugs, tpl.Slug)
	}
	if !slices.Equal(slugs, []string{"owner", "admin", "member", "superadmin"}) {
		t.Fatalf("slugs %v", slugs)
	}
	owner, admin := template(t, RoleOwner).PermissionKeys, template(t, RoleAdmin).PermissionKeys
	if !slices.Contains(owner, OrgDelete) || !slices.Contains(owner, AuditRead) || slices.Contains(owner, UsersRead) || slices.Contains(owner, UsersManage) {
		t.Errorf("owner %v", owner)
	}
	if slices.Contains(admin, OrgDelete) || !slices.Contains(admin, MembersUpdate) || !slices.Contains(admin, RolesManage) {
		t.Errorf("admin %v", admin)
	}
	if m := template(t, RoleMember).PermissionKeys; !slices.Equal(m, []string{OrgRead, MembersRead, RolesRead}) {
		t.Errorf("member %v", m)
	}
	if s := template(t, RoleSuperadmin).PermissionKeys; !slices.Equal(s, keys(NewCatalog().Permissions())) {
		t.Errorf("superadmin %v", s)
	}
}

func systemRole(t *testing.T, r *repository.Repos, slug string) model.Role {
	role, err := r.Roles.ByOrganizationAndSlug(ctx, nil, slug)
	must(t, err)
	return role
}

func TestSeedDrivesPermissionsAndRoles(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter, r *repository.Repos) {
		ps, err := r.Permissions.List(ctx)
		must(t, err)
		if len(ps) != 12 {
			t.Fatalf("permissions %d", len(ps))
		}
		if n, _ := db.Count(ctx, "auth_roles", store.Criteria{"is_system": true}); n != 4 {
			t.Fatalf("system roles %d", n)
		}
		for slug, want := range map[string]int64{"owner": 10, "admin": 9, "member": 3, "superadmin": 12} {
			role := systemRole(t, r, slug)
			if n, _ := db.Count(ctx, "auth_role_permissions", store.Criteria{"role_id": role.ID}); n != want {
				t.Errorf("%s grants %d, want %d", slug, n, want)
			}
			if role.OrganizationID != nil || !role.IsSystem || role.Description == nil {
				t.Errorf("role %+v", role)
			}
		}
	})
}

func TestReseedingIsIdempotent(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter, r *repository.Repos) {
		count := func() [3]int64 {
			var c [3]int64
			for i, tbl := range []string{"auth_permissions", "auth_roles", "auth_role_permissions"} {
				c[i], _ = db.Count(ctx, tbl, nil)
			}
			return c
		}
		before := count()
		must(t, Seed(ctx, db, NewCatalog(), clock.NewFrozen(now)))
		if after := count(); after != before {
			t.Fatalf("before %v after %v", before, after)
		}
		must(t, Seed(ctx, db, NewCatalog(map[string]string{"billing.manage": "Manage billing"}), nil))
		if _, err := r.Permissions.ByKey(ctx, "billing.manage"); err != nil {
			t.Fatal(err)
		}
	})
}

// fixture helpers (PermissionResolverTest)

func member(t *testing.T, r *repository.Repos, orgID string) string {
	m := model.Membership{ID: repository.NewID(), UserID: repository.NewID(), OrganizationID: orgID, Status: model.MembershipStatusActive, CreatedAt: now, UpdatedAt: now}
	must(t, r.Memberships.Insert(ctx, m))
	return m.UserID
}

func orgRole(t *testing.T, r *repository.Repos, orgID, slug string) string {
	o := orgID
	role := model.Role{ID: repository.NewID(), OrganizationID: &o, Name: slug, Slug: slug, CreatedAt: now, UpdatedAt: now}
	must(t, r.Roles.Insert(ctx, role))
	return role.ID
}

func grant(t *testing.T, r *repository.Repos, roleID, key string) {
	p, err := r.Permissions.ByKey(ctx, key)
	must(t, err)
	must(t, r.RolePermissions.Insert(ctx, model.RolePermission{RoleID: roleID, PermissionID: p.ID}))
}

func assign(t *testing.T, r *repository.Repos, userID, orgID, roleID string) {
	m, err := r.Memberships.ByUserAndOrganization(ctx, userID, orgID)
	must(t, err)
	must(t, r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: m.ID, RoleID: roleID}))
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

func TestResolvesARolesSlugAndPermissions(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		u := member(t, r, org)
		role := orgRole(t, r, org, "owner")
		grant(t, r, role, OrgRead)
		grant(t, r, role, MembersRead)
		assign(t, r, u, org, role)
		a, err := NewResolver(r).Resolve(ctx, u, org)
		must(t, err)
		if !slices.Equal(a.Roles, []string{"owner"}) || !sameSet(a.Scope, []string{OrgRead, MembersRead}) {
			t.Fatalf("%+v", a)
		}
	})
}

func TestResolvesTheUnionOfMultipleRoles(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		u := member(t, r, org)
		owner, mem := orgRole(t, r, org, "owner"), orgRole(t, r, org, "member")
		grant(t, r, owner, OrgRead)
		grant(t, r, owner, MembersRead)
		grant(t, r, mem, OrgRead) // overlaps: deduplicated
		grant(t, r, mem, RolesRead)
		assign(t, r, u, org, owner)
		assign(t, r, u, org, mem)
		a, err := NewResolver(r).Resolve(ctx, u, org)
		must(t, err)
		if !sameSet(a.Roles, []string{"owner", "member"}) || !sameSet(a.Scope, []string{OrgRead, MembersRead, RolesRead}) {
			t.Fatalf("%+v", a)
		}
	})
}

func TestResolvesEmptyForNonMemberOrNoActiveOrg(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		u := member(t, r, org)
		role := orgRole(t, r, org, "owner")
		grant(t, r, role, OrgRead)
		assign(t, r, u, org, role)
		res := NewResolver(r)
		for _, c := range []struct{ user, org string }{{repository.NewID(), org}, {u, ""}} {
			a, err := res.Resolve(ctx, c.user, c.org)
			must(t, err)
			if a.Roles == nil || a.Scope == nil || len(a.Roles)+len(a.Scope) != 0 {
				t.Errorf("%+v: %#v", c, a)
			}
		}
	})
}

func TestSuperadminResolvesToEveryPermission(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		u := member(t, r, org)
		assign(t, r, u, org, systemRole(t, r, RoleSuperadmin).ID)
		a, err := NewResolver(r).Resolve(ctx, u, "")
		must(t, err)
		if !slices.Equal(a.Roles, []string{"superadmin"}) || len(a.Scope) != 12 || !slices.Contains(a.Scope, UsersManage) || !a.IsSuperadmin() {
			t.Fatalf("%+v", a)
		}
	})
}

func TestDisabledUserSuspendedMemberAndInactiveOrgResolveEmpty(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		res := NewResolver(r)
		setup := func(orgID string) string {
			u := member(t, r, orgID)
			role := orgRole(t, r, orgID, "owner-"+repository.NewID())
			grant(t, r, role, OrgRead)
			assign(t, r, u, orgID, role)
			return u
		}
		empty := func(u, orgID string) {
			t.Helper()
			a, err := res.Resolve(ctx, u, orgID)
			must(t, err)
			if len(a.Roles)+len(a.Scope) != 0 {
				t.Errorf("%+v", a)
			}
		}
		// disabled user, even a superadmin
		u := setup(org)
		must(t, r.Users.Insert(ctx, model.User{ID: u, Email: "d@example.com", Status: model.UserStatusDisabled, CreatedAt: now, UpdatedAt: now}))
		assign(t, r, u, org, systemRole(t, r, RoleSuperadmin).ID)
		empty(u, org)

		// suspended membership
		u = setup(org)
		m, err := r.Memberships.ByUserAndOrganization(ctx, u, org)
		must(t, err)
		after := m
		after.Status = model.MembershipStatusSuspended
		must(t, r.Memberships.Update(ctx, m, after))
		empty(u, org)

		// suspended organization; an active one with the same setup grants
		suspended := model.Organization{ID: repository.NewID(), Name: "S", Slug: "s", Status: model.OrganizationStatusSuspended, CreatedBy: u, CreatedAt: now, UpdatedAt: now}
		must(t, r.Organizations.Insert(ctx, suspended))
		empty(setup(suspended.ID), suspended.ID)
		active := model.Organization{ID: repository.NewID(), Name: "A", Slug: "a", CreatedBy: u, CreatedAt: now, UpdatedAt: now}
		must(t, r.Organizations.Insert(ctx, active))
		if a, _ := res.Resolve(ctx, setup(active.ID), active.ID); !a.Allows(OrgRead) {
			t.Errorf("active org: %+v", a)
		}
	})
}

// memberWith creates a member of org holding exactly key through one role named "limited".
func memberWith(t *testing.T, r *repository.Repos, key string) Caller {
	u := member(t, r, org)
	role := orgRole(t, r, org, "limited")
	grant(t, r, role, key)
	assign(t, r, u, org, role)
	return Caller{UserID: u, OrganizationID: org}
}

func TestGateAuthorize(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		g := NewGate(NewResolver(r))
		c := memberWith(t, r, MembersRead)
		must(t, g.Authorize(ctx, c, MembersRead))
		if ok, err := g.Allows(ctx, c, MembersInvite); ok || err != nil {
			t.Fatalf("allows invite: %v %v", ok, err)
		}
		err := g.Authorize(ctx, c, MembersInvite)
		var fe *ForbiddenError
		if !errors.Is(err, ErrForbidden) || !errors.As(err, &fe) || fe.Message != MsgForbidden || err.Error() != MsgForbidden {
			t.Fatalf("err %v", err)
		}
	})
}

func TestADelegatedCallerHoldsTheIntersection(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		g := NewGate(NewResolver(r))
		owner := memberWith(t, r, MembersRead)
		delegated := owner
		delegated.Delegated, delegated.DelegatedPermissions = true, []string{MembersRead, MembersInvite}
		nothing := owner
		nothing.Delegated, nothing.DelegatedPermissions = true, []string{MembersInvite}
		empty := owner
		empty.Delegated = true

		a, err := g.Authority(ctx, delegated)
		must(t, err)
		if !slices.Equal(a.Scope, []string{MembersRead}) || !slices.Equal(a.Roles, []string{"limited"}) {
			t.Fatalf("%+v", a)
		}
		check := func(c Caller, perm string, want bool) {
			t.Helper()
			if ok, err := g.Allows(ctx, c, perm); ok != want || err != nil {
				t.Errorf("allows %s = %v (%v), want %v", perm, ok, err, want)
			}
		}
		check(delegated, MembersRead, true)
		check(delegated, MembersInvite, false) // delegated but not held
		check(nothing, MembersRead, false)     // held but not delegated
		check(empty, MembersRead, false)
		if a, _ := g.Authority(ctx, nothing); len(a.Scope) != 0 {
			t.Errorf("nothing %+v", a)
		}
	})
}

func TestDelegationDropsTheSuperadminOverride(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		u := member(t, r, org)
		assign(t, r, u, org, systemRole(t, r, RoleSuperadmin).ID)
		a, err := NewGate(NewResolver(r)).Authority(ctx, Caller{UserID: u, Delegated: true, DelegatedPermissions: []string{UsersRead}})
		must(t, err)
		if len(a.Roles) != 0 || !slices.Equal(a.Scope, []string{UsersRead}) || a.IsSuperadmin() {
			t.Fatalf("%+v", a)
		}
	})
}

func TestEscalationGuard(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		g := NewEscalationGuard(r)
		owner, admin := systemRole(t, r, RoleOwner).ID, systemRole(t, r, RoleAdmin).ID
		adminAuthority := Authority{Roles: []string{RoleAdmin}, Scope: template(t, RoleAdmin).PermissionKeys}

		must(t, g.CheckRoles(ctx, adminAuthority, []string{admin}))
		if err := g.CheckRoles(ctx, adminAuthority, []string{admin, owner}); !errors.Is(err, ErrForbidden) || err.Error() != MsgEscalation {
			t.Errorf("owner grant: %v", err)
		}
		super := Authority{Roles: []string{RoleSuperadmin}, Scope: []string{}}
		must(t, g.CheckRoles(ctx, super, []string{owner}))

		must(t, g.CheckPermissions(adminAuthority, []string{MembersRead}))
		must(t, g.CheckPermissions(super, []string{OrgDelete}))
		if err := g.CheckPermissions(adminAuthority, []string{OrgDelete}); !errors.Is(err, ErrForbidden) {
			t.Errorf("org.delete: %v", err)
		}
	})
}

func TestPrincipals(t *testing.T) {
	backends(t, func(t *testing.T, _ store.Adapter, r *repository.Repos) {
		c := memberWith(t, r, MembersRead)
		must(t, r.Users.Insert(ctx, model.User{ID: c.UserID, Email: "p@example.com", EmailVerifiedAt: &now, CreatedAt: now, UpdatedAt: now}))
		res := NewResolver(r)

		p, err := NewPrincipals(r, res, false).Resolve(ctx, c.UserID, org)
		must(t, err)
		if p.UserID != c.UserID || p.OrganizationID != org || !p.EmailVerified || !slices.Equal(p.Roles, []string{"limited"}) || p.Scope != nil || p.MFA || p.AMR != nil {
			t.Fatalf("%+v", p)
		}
		p, err = NewPrincipals(r, res, true).Resolve(ctx, c.UserID, org)
		must(t, err)
		if !slices.Equal(p.Scope, []string{MembersRead}) {
			t.Fatalf("embedded scope %+v", p)
		}
		p, err = NewPrincipals(r, res, true).Resolve(ctx, repository.NewID(), "")
		must(t, err)
		if p.EmailVerified || len(p.Roles) != 0 {
			t.Fatalf("stranger %+v", p)
		}
	})
}
