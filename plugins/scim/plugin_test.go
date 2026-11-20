package scim

import (
	"context"
	"github.com/univeros/polaris.go/internal/services"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
)

const location = "https://app.example/auth/scim/v2/c1"

type fixture struct {
	t   *testing.T
	ctx context.Context
	srv *polaristest.Server
	p   *Plugin
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	p := New(Config{BaseURL: "https://app.example/auth/"})
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}), p))
	return &fixture{t: t, ctx: context.Background(), srv: srv, p: p}
}

// refused asserts err is a SCIM error with status.
func refused(t *testing.T, err error, status int, what string) {
	t.Helper()
	e, ok := asError(err)
	if !ok || e.Status != status {
		t.Fatalf("%s: %v, want a %d", what, err, status)
	}
}

// must unwraps a call in a test; a failure panics, which fails the test with its stack.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// user inserts an account directly, as upstream's unit of work does.
func (f *fixture) user(id, email string) model.User {
	f.t.Helper()
	now := time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	u := model.User{ID: id, Email: email, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := f.srv.Graph().Repos().Users.Insert(f.ctx, u); err != nil {
		f.t.Fatal(err)
	}
	return u
}

// organization is Acme, owned by owner@acme.example.
func (f *fixture) organization() string {
	f.t.Helper()
	owner := f.user("u-owner", "owner@acme.example")
	org := must(services.Of(f.srv.Graph()).Orgs.CreateOrganization(f.ctx, "Acme", "", owner.ID))
	return org.ID
}

func (f *fixture) connection(orgID, deprovision string) Connection {
	f.t.Helper()
	conn, _, err := f.p.Connections().Create(f.ctx, orgID, "Okta", deprovision, "", "")
	if err != nil {
		f.t.Fatal(err)
	}
	return conn
}

func TestPlugin(t *testing.T) {
	t.Run("testEverythingIsWiredAndConnectionsAuthenticateByToken", func(t *testing.T) {
		f := newFixture(t)
		g := f.srv.Graph()
		for _, table := range []string{TableConnections, TableResources, TableProvenance} {
			if !slices.ContainsFunc(g.Schema(), func(m schema.Model) bool { return m.Table == table }) {
				t.Fatalf("no table %s", table)
			}
		}
		var routes []string
		served := f.p.endpoints()
		for _, rt := range g.Manifest().Routes() {
			if rt.Plugin != ID {
				continue
			}
			routes = append(routes, rt.Name)
			if served[rt.Name] == nil {
				t.Fatalf("%s is not served", rt.Name)
			}
			switch {
			case strings.HasPrefix(rt.Path, "/scim/"):
				if rt.Auth != manifest.AuthPublic {
					t.Fatalf("%s: auth %s", rt.Name, rt.Auth)
				}
			case strings.HasPrefix(rt.Path, "/orgs/"):
				if rt.Auth != manifest.AuthBearer || !reflect.DeepEqual(rt.RequiresPermissions, []string{"org.update"}) {
					t.Fatalf("%s: %s %v", rt.Name, rt.Auth, rt.RequiresPermissions)
				}
			}
		}
		if len(routes) != 22 || len(served) != 22 {
			t.Fatalf("%d routes, %d served", len(routes), len(served))
		}
		for name := range auditNames {
			if !audit.Of(g).Catalog().Has(name) {
				t.Fatalf("%s is not in the audit catalog", name)
			}
		}
		if Of(g) != f.p {
			t.Fatal("Of")
		}

		conns := f.p.Connections()
		conn, token, err := conns.Create(f.ctx, "org-1", "Okta", DeprovisionDelete, "", "u1")
		if err != nil || !strings.HasPrefix(token, TokenPrefix) || conn.TokenHash == token || conn.TokenHash == "" {
			t.Fatalf("created %v %q %v", conn, token, err)
		}
		if conn.Name != "Okta" || conn.Status != StatusActive || conn.Deprovision != DeprovisionDelete {
			t.Fatalf("connection %v", conn)
		}
		if _, has := conn.Map()["token_hash"]; has {
			t.Fatal("the map shows the hash")
		}
		authenticated := func(token string) string {
			c, ok, err := conns.Authenticate(f.ctx, token)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				return ""
			}
			return c.ID
		}
		if authenticated(token) != conn.ID || authenticated("pst_nope") != "" || authenticated("not a token") != "" || authenticated("") != "" {
			t.Fatal("authenticate")
		}
		conn, rotated := must2(t)(conns.Rotate(f.ctx, conn))
		if authenticated(token) != "" || authenticated(rotated) != conn.ID {
			t.Fatal("the previous token still works, or the new one does not")
		}
		must2(t)(conns.Create(f.ctx, "org-2", "Entra", "anything", "", ""))
		if mine := must(conns.ForOrganization(f.ctx, "org-1")); len(mine) != 1 {
			t.Fatalf("org-1 has %d", len(mine))
		}
		first, next, err := conns.List(f.ctx, "", "", 1)
		if err != nil || len(first) != 1 || next == "" {
			t.Fatalf("page %v %q %v", first, next, err)
		}
		if second, last, _ := conns.List(f.ctx, "", next, 0); len(second) != 1 || last != "" || second[0].Deprovision != DeprovisionDeactivate {
			t.Fatalf("second page %v %q", second, last)
		}
		conn = must(conns.Decommission(f.ctx, conn))
		if authenticated(rotated) != "" {
			t.Fatal("a decommissioned connection authenticates")
		}
		if found, ok, _ := conns.Find(f.ctx, conn.ID); !ok || found.Status != StatusDecommissioned || found.DecommissionedAt == nil {
			t.Fatalf("found %v", found)
		}
		if deleted, _ := conns.Delete(f.ctx, conn.ID); !deleted {
			t.Fatal("not deleted")
		}
		if deleted, _ := conns.Delete(f.ctx, conn.ID); deleted {
			t.Fatal("deleted twice")
		}
	})

	t.Run("testUsersAreMembersProvisionedPatchedAndDeprovisioned", func(t *testing.T) {
		f := newFixture(t)
		g := f.srv.Graph()
		orgID := f.organization()
		conn := f.connection(orgID, DeprovisionDeactivate)
		d := f.p.dir
		d.domains = func() any { return verifiedDomains{orgID: "acme.example"} }
		res := d.resources
		activeIn := func(c Connection, u model.User) bool { return must(d.active(f.ctx, c, u)) }
		patch := func(user model.User, ops ...any) (model.User, error) {
			parsed, err := parsePatch(map[string]any{"schemas": []any{PatchSchema}, "Operations": ops})
			if err != nil {
				t.Fatal(err)
			}
			return d.patchUser(f.ctx, conn, user, parsed)
		}
		externalID := func(id string) string { return must(res.externalID(f.ctx, conn, KindUser, id)) }

		ada := must(d.createUser(f.ctx, conn, map[string]any{"userName": "Ada@Acme.example", "displayName": "Ada Lovelace", "externalId": "ext-ada",
			"emails": []any{map[string]any{"value": "ada@acme.example", "primary": true}}}))
		if ada.Email != "ada@acme.example" || *ada.DisplayName != "Ada Lovelace" || ada.PasswordHash != nil || ada.EmailVerifiedAt == nil {
			t.Fatalf("ada %+v", ada)
		}
		m := must(g.Repos().Memberships.ByUserAndOrganization(f.ctx, ada.ID, orgID))
		if m.Status != model.MembershipStatusActive || len(must(g.Repos().MembershipRoles.ListByMembership(f.ctx, m.ID))) != 1 {
			t.Fatalf("membership %+v", m)
		}
		if !must(res.createdMembership(f.ctx, conn, ada.ID)) {
			t.Fatal("no provenance")
		}
		joined := 0
		for _, e := range f.srv.Events.All() {
			if _, ok := e.(event.MemberJoined); ok {
				joined++
			}
		}
		if joined != 1 {
			t.Fatalf("%d MemberJoined", joined)
		}
		r := must(d.userResource(f.ctx, conn, ada, location))
		if r["userName"] != "ada@acme.example" || r["externalId"] != "ext-ada" || r["active"] != true ||
			r["meta"].(map[string]any)["location"] != location+"/Users/"+ada.ID || r["groups"].([]map[string]any)[0]["display"] != "Member" {
			t.Fatalf("resource %v", r)
		}

		_, err := d.createUser(f.ctx, conn, map[string]any{"userName": "owner@acme.example"})
		refused(t, err, 409, "the owner is a member already")
		f.user("u-grace", "grace@acme.example")
		grace := must(d.createUser(f.ctx, conn, map[string]any{"userName": "grace@acme.example", "name": map[string]any{"givenName": "Grace", "familyName": "Hopper"}}))
		if grace.ID != "u-grace" || grace.DisplayName != nil || !must(res.createdMembership(f.ctx, conn, grace.ID)) {
			t.Fatalf("an existing account on a verified domain joins, its profile untouched: %+v", grace)
		}
		if err := res.forgetMembership(f.ctx, conn, grace.ID); err != nil {
			t.Fatal(err)
		}
		_, err = d.createUser(f.ctx, conn, map[string]any{"userName": "ada@acme.example"})
		refused(t, err, 409, "ada again")
		_, err = d.createUser(f.ctx, conn, map[string]any{"userName": "not-an-email"})
		refused(t, err, 400, "not an email")
		_, err = d.findUser(f.ctx, conn, "nope")
		refused(t, err, 404, "nope")

		f1, _ := parseFilter(`userName eq "ADA@acme.example"`)
		pg := must(d.listUsers(f.ctx, conn, f1, 1, 10, location))
		if pg.total != 1 || pg.resources[0]["userName"] != "ada@acme.example" {
			t.Fatalf("filtered %v", pg)
		}
		f2, _ := parseFilter(`externalId eq "ext-ada"`)
		if must(d.listUsers(f.ctx, conn, f2, 1, 10, location)).total != 1 {
			t.Fatal("by externalId")
		}
		if all := must(d.listUsers(f.ctx, conn, nil, 3, 1, location)); all.total != 3 || len(all.resources) != 1 {
			t.Fatalf("startIndex 3 of 3: %v", all)
		}
		if beyond := must(d.listUsers(f.ctx, conn, nil, 9, 5, location)); beyond.total != 3 || len(beyond.resources) != 0 {
			t.Fatalf("beyond: %v", beyond)
		}

		patched := must(patch(ada, map[string]any{"op": "replace", "path": "active", "value": false}))
		if patched.Status != model.UserStatusActive || activeIn(conn, patched) {
			t.Fatalf("active false suspends the membership, never the account: %s", patched.Status)
		}
		patched = must(patch(patched, map[string]any{"op": "replace", "value": map[string]any{"active": "True",
			"name": map[string]any{"givenName": "Ada", "familyName": "King"}, "externalId": "ext-2"}}))
		if !activeIn(conn, patched) || *patched.DisplayName != "Ada King" || externalID(ada.ID) != "ext-2" {
			t.Fatalf("patched %+v %s", patched, externalID(ada.ID))
		}
		patched = must(patch(patched, map[string]any{"op": "replace", "path": "userName", "value": "ada.king@acme.example"},
			map[string]any{"op": "remove", "path": "externalId"}, map[string]any{"op": "replace", "path": "displayName", "value": " "}))
		if patched.Email != "ada.king@acme.example" || externalID(ada.ID) != "" || patched.DisplayName != nil {
			t.Fatalf("renamed %+v", patched)
		}
		_, err = patch(patched, map[string]any{"op": "replace", "path": "userName", "value": "grace@acme.example"})
		refused(t, err, 409, "another account's email")
		_, err = patch(patched, map[string]any{"op": "replace", "path": "userName", "value": "nope"})
		refused(t, err, 400, "not an email")
		replaced := must(d.replaceUser(f.ctx, conn, patched, map[string]any{"userName": "ada@acme.example", "displayName": "Ada", "active": false, "externalId": "ext-3"}))
		if replaced.Email != "ada@acme.example" || *replaced.DisplayName != "Ada" || activeIn(conn, replaced) || externalID(ada.ID) != "ext-3" {
			t.Fatalf("replaced %+v", replaced)
		}

		if outcome := must(d.deleteUser(f.ctx, conn, replaced)); outcome != "deactivated" {
			t.Fatal(outcome)
		}
		if _, err := g.Repos().Memberships.ByUserAndOrganization(f.ctx, ada.ID, orgID); err == nil {
			t.Fatal("the membership the connection created stays")
		}
		if must(g.Repos().Users.Get(f.ctx, ada.ID)).Status != model.UserStatusDisabled {
			t.Fatal("not disabled")
		}
		if must(d.deleteUser(f.ctx, conn, grace)) != "deactivated" {
			t.Fatal("grace")
		}
		if _, err := g.Repos().Memberships.ByUserAndOrganization(f.ctx, grace.ID, orgID); err == nil {
			t.Fatal("deprovisioning an account the directory does not own leaves its membership")
		}
		if must(g.Repos().Users.Get(f.ctx, grace.ID)).Status != model.UserStatusActive {
			t.Fatal("deprovisioning disabled an account the directory does not own")
		}
		purge := f.connection(orgID, DeprovisionDelete)
		bob := must(d.createUser(f.ctx, purge, map[string]any{"userName": "bob@acme.example", "active": false}))
		if bob.Status != model.UserStatusActive || activeIn(purge, bob) {
			t.Fatal("active false does not suspend the membership")
		}
		if must(d.deleteUser(f.ctx, purge, bob)) != "deleted" || must(g.Repos().Users.Get(f.ctx, bob.ID)).Email == "bob@acme.example" {
			t.Fatal("not anonymised")
		}
	})

	t.Run("testGroupsAreRolesWithMembers", func(t *testing.T) {
		f := newFixture(t)
		orgID := f.organization()
		conn := f.connection(orgID, DeprovisionDeactivate)
		d := f.p.dir
		patch := func(role model.Role, ops ...any) (model.Role, error) {
			parsed, err := parsePatch(map[string]any{"schemas": []any{PatchSchema}, "Operations": ops})
			if err != nil {
				t.Fatal(err)
			}
			return d.patchGroup(f.ctx, conn, role, parsed)
		}
		members := func(role model.Role) []any {
			r := must(d.groupResource(f.ctx, conn, role, location))
			var ids []any
			for _, m := range r["members"].([]map[string]any) {
				ids = append(ids, m["value"])
			}
			return ids
		}
		ada := must(d.createUser(f.ctx, conn, map[string]any{"userName": "ada@acme.example"}))
		bob := must(d.createUser(f.ctx, conn, map[string]any{"userName": "bob@acme.example"}))
		sorted := func(ids ...string) []any {
			slices.Sort(ids)
			out := make([]any, len(ids))
			for i, id := range ids {
				out[i] = id
			}
			return out
		}

		eng := must(d.createGroup(f.ctx, conn, map[string]any{"displayName": "Engineering Team", "externalId": "g-1", "members": []any{map[string]any{"value": ada.ID}}}))
		if eng.Name != "Engineering Team" || eng.Slug != "engineering-team" || *eng.OrganizationID != orgID {
			t.Fatalf("role %+v", eng)
		}
		r := must(d.groupResource(f.ctx, conn, eng, location))
		if r["externalId"] != "g-1" || !reflect.DeepEqual(members(eng), []any{ada.ID}) {
			t.Fatalf("group %v", r)
		}
		groups := must(d.userResource(f.ctx, conn, ada, location))["groups"].([]map[string]any)
		if !slices.ContainsFunc(groups, func(m map[string]any) bool { return m["display"] == "Engineering Team" }) {
			t.Fatalf("ada's groups %v", groups)
		}
		_, err := d.createGroup(f.ctx, conn, map[string]any{"displayName": "Engineering Team"})
		refused(t, err, 409, "same name")
		_, err = d.createGroup(f.ctx, conn, map[string]any{"displayName": ""})
		refused(t, err, 400, "no name")
		_, err = d.createGroup(f.ctx, conn, map[string]any{"displayName": "Ops", "members": []any{map[string]any{"value": "nobody"}}})
		refused(t, err, 400, "not a member")
		if _, err := d.repos.Roles.ByOrganizationAndSlug(f.ctx, &orgID, "ops"); err == nil {
			t.Fatal("a refused group was created")
		}
		_, err = d.createGroup(f.ctx, conn, map[string]any{"displayName": "Ops", "members": "nope"})
		refused(t, err, 400, "members not a list")

		fl, _ := parseFilter(`displayName co "engineering"`)
		listed := must(d.listGroups(f.ctx, conn, fl, 1, 10, location))
		if listed.total != 1 || listed.resources[0]["id"] != eng.ID {
			t.Fatalf("listed %v", listed)
		}
		if must(d.listGroups(f.ctx, conn, nil, 1, 10, location)).total < 4 {
			t.Fatal("the system roles too")
		}

		patched := must(patch(eng, map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": bob.ID}}},
			map[string]any{"op": "replace", "path": "displayName", "value": "Engineering"}, map[string]any{"op": "replace", "path": "externalId", "value": " g-2 "}))
		if patched.Name != "Engineering" || !reflect.DeepEqual(members(patched), sorted(ada.ID, bob.ID)) {
			t.Fatalf("patched %+v %v", patched, members(patched))
		}
		patched = must(patch(patched, map[string]any{"op": "remove", "path": `members[value eq "` + ada.ID + `"]`}))
		if !reflect.DeepEqual(members(patched), []any{bob.ID}) {
			t.Fatalf("removed %v", members(patched))
		}
		patched = must(patch(patched, map[string]any{"op": "replace", "value": map[string]any{"members": []any{ada.ID}}}))
		if !reflect.DeepEqual(members(patched), []any{ada.ID}) {
			t.Fatalf("path-less replace %v", members(patched))
		}
		patched = must(patch(patched, map[string]any{"op": "remove", "path": "members", "value": []any{map[string]any{"value": ada.ID}}}))
		if len(members(patched)) != 0 {
			t.Fatalf("removed all %v", members(patched))
		}
		replaced := must(d.replaceGroup(f.ctx, conn, patched, map[string]any{"displayName": "Engineering", "members": []any{map[string]any{"value": ada.ID}}}))
		if !reflect.DeepEqual(members(replaced), []any{ada.ID}) {
			t.Fatalf("replaced %v", members(replaced))
		}
		_, err = patch(replaced, map[string]any{"op": "add", "path": `members[value eq "x"]`, "value": []any{}})
		refused(t, err, 400, "filtered add")
		_, err = patch(replaced, map[string]any{"op": "remove", "path": "members"})
		refused(t, err, 400, "members without a list")

		member := must(d.repos.Roles.ByOrganizationAndSlug(f.ctx, &orgID, "member"))
		_, err = d.replaceGroup(f.ctx, conn, member, map[string]any{"displayName": "Renamed"})
		refused(t, err, 403, "a built-in role keeps its name")
		refused(t, d.deleteGroup(f.ctx, conn, member), 403, "a built-in role stays")
		must(d.replaceGroup(f.ctx, conn, member, map[string]any{"displayName": member.Name, "members": []any{map[string]any{"value": bob.ID}}}))
		if !reflect.DeepEqual(members(member), []any{bob.ID}) {
			t.Fatalf("a built-in role takes members: %v", members(member))
		}
		if err := d.deleteGroup(f.ctx, conn, replaced); err != nil {
			t.Fatal(err)
		}
		_, err = d.findGroup(f.ctx, conn, replaced.ID)
		refused(t, err, 404, "deleted")
		if n, _ := f.srv.DB.Count(f.ctx, TableResources, store.Criteria{"kind": KindGroup}); n != 0 {
			t.Fatalf("%d group external ids left", n)
		}
	})
}

func must2(t *testing.T) func(Connection, string, error) (Connection, string) {
	return func(c Connection, s string, err error) (Connection, string) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return c, s
	}
}

// verifiedDomains is the sso plugin's VerifiedDomains: organization id to its one verified domain.
type verifiedDomains map[string]string

func (v verifiedDomains) DomainVerified(_ context.Context, organizationID, domain string) (bool, error) {
	return v[organizationID] == domain, nil
}
