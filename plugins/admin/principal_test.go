package admin_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/plugins/admin"
)

// The role matrix: deny by default, each role including the ones below it.
func TestEachRoleAllowsExactlyItsCapabilities(t *testing.T) {
	all := []admin.Capability{admin.Read, admin.Support, admin.Manage, admin.Impersonate, admin.Own}
	matrix := map[admin.Role][]admin.Capability{
		admin.RoleViewer:  {admin.Read},
		admin.RoleSupport: {admin.Read, admin.Support},
		admin.RoleAdmin:   {admin.Read, admin.Support, admin.Manage, admin.Impersonate},
		admin.RoleOwner:   all,
		"root":            nil,
	}
	for role, allowed := range matrix {
		for _, c := range all {
			has := false
			for _, a := range allowed {
				has = has || a == c
			}
			if role.Allows(c) != has {
				t.Errorf("%s / %s: %v", role, c, !has)
			}
		}
	}
	if admin.RoleOwner.Allows("nothing") {
		t.Error("an unknown capability is denied")
	}
}

func TestRolesParseFromInputOnly(t *testing.T) {
	if r, ok := admin.ParseRole("support"); !ok || r != admin.RoleSupport {
		t.Error("support")
	}
	if _, ok := admin.ParseRole("root"); ok {
		t.Error("root")
	}
}

func TestAnInstancePrincipalCoversEveryOrganizationAndAScopedOneItsOwn(t *testing.T) {
	instance := admin.Principal{ID: "k1", Type: admin.TypeAPIKey, Role: admin.RoleViewer, Scope: admin.ScopeInstance}
	scoped := admin.Principal{ID: "u1", Type: admin.TypeUser, Role: admin.RoleAdmin, Scope: "org-a"}
	for _, c := range []struct {
		p    admin.Principal
		org  string
		want bool
	}{
		{instance, "", true}, {instance, "org-a", true},
		{scoped, "", false}, {scoped, "org-a", true}, {scoped, "org-b", false},
	} {
		if c.p.Covers(c.org) != c.want {
			t.Errorf("%+v covers %q: %v", c.p, c.org, !c.want)
		}
	}
	if !scoped.Allows(admin.Manage) || scoped.Allows(admin.Own) {
		t.Error("allows follows the role")
	}
}

func TestAuthorizeWithoutAnOperatorIsUnauthorized(t *testing.T) {
	if _, ok := admin.Operator(context.Background()); ok {
		t.Fatal("no operator outside an admin route")
	}
	if _, res, ok := admin.Authorize(context.Background(), admin.Read, ""); ok || res.Status != http.StatusUnauthorized {
		t.Fatalf("%v %+v", ok, res)
	}
	if res := admin.Invalid("bad", "one", "two"); res.Status != 422 || res.Body.(map[string]any)["errors"] == nil {
		t.Fatalf("%+v", res)
	}
	if res := admin.Invalid("bad"); res.Body.(map[string]any)["errors"] != nil {
		t.Fatal("no errors member without errors")
	}
}

func TestAllowlist(t *testing.T) {
	allows := []struct {
		list []string
		ip   string
		want bool
	}{
		{nil, "", true},
		{nil, "203.0.113.7", true},
		{[]string{"203.0.113.7"}, "", false},
		{[]string{"203.0.113.7"}, "not an address", false},
		{[]string{"203.0.113.7"}, "203.0.113.7", true},
		{[]string{"203.0.113.7"}, "203.0.113.8", false},
		{[]string{"10.0.0.0/8"}, "10.200.1.1", true},
		{[]string{"10.0.0.0/8"}, "11.0.0.1", false},
		{[]string{"192.168.4.0/22"}, "192.168.7.255", true},
		{[]string{"192.168.4.0/22"}, "192.168.8.0", false},
		{[]string{"2001:db8::/32"}, "2001:db8:1::5", true},
		{[]string{"2001:db8::/32"}, "2001:db9::1", false},
		{[]string{"10.0.0.0/8"}, "::ffff:10.0.0.1", false}, // families do not mix
		{[]string{"0.0.0.0/0"}, "8.8.8.8", true},
		{[]string{"nowhere", "fe80::1"}, "fe80::1%eth0", false},
	}
	for _, c := range allows {
		if got := admin.AllowlistAllows(c.list, c.ip); got != c.want {
			t.Errorf("%v allows %q: %v", c.list, c.ip, got)
		}
	}
	valid := map[string]bool{
		"203.0.113.7": true, "10.0.0.0/8": true, "2001:db8::/32": true,
		"10.0.0.0/33": false, "example.test": false, "10.0.0.0/abc": false, "fe80::1%eth0": false, "": false,
	}
	for entry, want := range valid {
		if admin.ValidAllowlistEntry(entry) != want {
			t.Errorf("%q valid: %v", entry, !want)
		}
	}
}
