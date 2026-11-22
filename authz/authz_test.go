package authz

// The catalog, the authority value and the forbidden error: the vocabulary plugins and hosts read.

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

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

func TestWithRoleGrantsExtendsTheSystemTemplatesAndRefusesTheRest(t *testing.T) {
	base := NewCatalog(map[string]string{"billing.manage": "Manage billing"})
	c, err := base.WithRoleGrants(map[string][]string{RoleAdmin: {"billing.manage", "billing.manage"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tpl := range c.RoleTemplates() {
		if got := slices.Contains(tpl.PermissionKeys, "billing.manage"); got != (tpl.Slug == RoleAdmin) {
			t.Errorf("%s grants billing.manage: %v", tpl.Slug, got)
		}
	}
	for name, grants := range map[string]map[string][]string{
		"not a system role":  {RoleSuperadmin: {"billing.manage"}},
		"core permission":    {RoleMember: {OrgDelete}},
		"not in the catalog": {RoleOwner: {"nope.nope"}},
	} {
		if _, err := base.WithRoleGrants(grants); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestAuthorityAllowsEveryPermissionAsked(t *testing.T) {
	a := Authority{Roles: []string{RoleAdmin}, Scope: []string{OrgRead, MembersRead}}
	if !a.Allows() || !a.Allows(OrgRead, MembersRead) || a.Allows(OrgRead, OrgDelete) || a.IsSuperadmin() {
		t.Fatalf("authority %+v", a)
	}
	if !(Authority{Roles: []string{RoleSuperadmin}}).IsSuperadmin() {
		t.Fatal("superadmin not recognised")
	}
}

func TestForbiddenMatchesErrForbiddenAndCarriesItsMessage(t *testing.T) {
	err := Forbidden(MsgEscalation)
	var fe *ForbiddenError
	if !errors.Is(err, ErrForbidden) || !errors.As(err, &fe) || err.Error() != MsgEscalation {
		t.Fatalf("err = %#v", err)
	}
}
