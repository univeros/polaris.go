package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
)

// Helpers of the ports of upstream's organization, membership, invitation, role, user-admin and
// org-switch functional tests. Each PHP test class repeats its own private helpers; the requests
// they issue are the same, so they are shared here.

const (
	orgPHP      = `Polaris\Tests\Functional\`
	orgPassword = "Sup3r-Secret-Passw0rd"
)

// orgCase is one ported test: a booted server and a client replaying the test's fixture.
type orgCase struct {
	t   *testing.T
	srv *polaristest.Server
	c   *contracttest.Client
	ctx context.Context
}

// orgRun runs each test of a PHP class as a subtest with its own server and fixture.
func orgRun(t *testing.T, phpClass string, tests map[string]func(*orgCase)) {
	t.Helper()
	dir := contracttest.UpstreamFixtures(t, "core")
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			srv := polaristest.New(t)
			fx := contracttest.For(t, dir, orgPHP+phpClass, name)
			test(&orgCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), fx), ctx: context.Background()})
		})
	}
}

// orgSession is the token pair of a login.
type orgSession struct{ access, refresh string }

// login registers and verifies email on first use (a repeated registration answers 202 without
// an event, so the last token is verified again, harmlessly), then logs in.
func (o *orgCase) login(email string) orgSession {
	o.t.Helper()
	if o.c.Post("/auth/register", map[string]any{"email": email, "password": orgPassword}).StatusCode < 300 {
		registered := orgEventsOf[event.UserRegistered](o.srv)
		if len(registered) > 0 {
			o.c.Post("/auth/email/verify", map[string]any{"token": registered[len(registered)-1].VerificationToken})
		}
	}
	data := orgMap(o.json(o.c.Post("/auth/login", map[string]any{"email": email, "password": orgPassword}))["data"])
	access, _ := data["access_token"].(string)
	refresh, _ := data["refresh_token"].(string)
	return orgSession{access: access, refresh: refresh}
}

// createOrg creates an organization named name and returns its id ("" on failure).
func (o *orgCase) createOrg(name, access string) string {
	o.t.Helper()
	id, _ := orgMap(o.json(o.c.Post("/orgs", map[string]any{"name": name}, contracttest.Bearer(access)))["data"])["id"].(string)
	return id
}

// switchOrg re-scopes the session of access to org and returns the new access token.
func (o *orgCase) switchOrg(access, org string) string {
	o.t.Helper()
	tok, _ := orgMap(o.json(o.c.Post("/auth/switch-org", map[string]any{"organization_id": org}, contracttest.Bearer(access)))["data"])["access_token"].(string)
	return tok
}

// orgOwnedBy logs email in, creates "Acme" and returns it with a token scoped to it, plus the
// unscoped login session.
func (o *orgCase) orgOwnedBy(email string) (org, scoped string, session orgSession) {
	o.t.Helper()
	session = o.login(email)
	org = o.createOrg("Acme", session.access)
	return org, o.switchOrg(session.access, org), session
}

// seedMember links userID to org with roleSlug directly in the database, as upstream's tests do.
func (o *orgCase) seedMember(org, userID, roleSlug, status string) {
	o.t.Helper()
	at := time.Date(2026, 6, 10, 10, 0, 0, 0, time.UTC)
	m := model.Membership{ID: repository.NewID(), UserID: userID, OrganizationID: org, Status: status, CreatedAt: at, UpdatedAt: at}
	repos := o.srv.Graph().Repos()
	o.must(repos.Memberships.Insert(o.ctx, m))
	o.must(repos.MembershipRoles.Insert(o.ctx, model.MembershipRole{MembershipID: m.ID, RoleID: o.roleID(org, roleSlug)}))
}

// seedActiveMember logs email in, seeds them as an active roleSlug member and returns a token
// scoped to org.
func (o *orgCase) seedActiveMember(org, email, roleSlug string) string {
	o.t.Helper()
	session := o.login(email)
	o.seedMember(org, o.userID(email), roleSlug, model.MembershipStatusActive)
	return o.switchOrg(session.access, org)
}

// grantSuperadmin links the first membership of userID to the global superadmin role.
func (o *orgCase) grantSuperadmin(userID string) {
	o.t.Helper()
	o.must(o.srv.Graph().Repos().MembershipRoles.Insert(o.ctx, model.MembershipRole{
		MembershipID: o.idFrom("auth_memberships", store.Criteria{"user_id": userID}),
		RoleID:       o.systemRoleID(authz.RoleSuperadmin),
	}))
}

func (o *orgCase) userID(email string) string {
	return o.idFrom("auth_users", store.Criteria{"email": email})
}

func (o *orgCase) roleID(org, slug string) string {
	return o.idFrom("auth_roles", store.Criteria{"organization_id": org, "slug": slug})
}

func (o *orgCase) systemRoleID(slug string) string {
	return o.idFrom("auth_roles", store.Criteria{"organization_id": nil, "slug": slug})
}

// idFrom is the id of the first row of table matching c; the test fails without one.
func (o *orgCase) idFrom(table string, c store.Criteria) string {
	o.t.Helper()
	rows, err := o.srv.DB.FindMany(o.ctx, table, c, store.Query{})
	o.must(err)
	for _, row := range rows {
		if id := row.String("id"); id != "" {
			return id
		}
	}
	o.t.Fatalf("no row in %s for %v", table, c)
	return ""
}

func (o *orgCase) count(table string, c store.Criteria) int64 {
	o.t.Helper()
	n, err := o.srv.DB.Count(o.ctx, table, c)
	o.must(err)
	return n
}

// lastInviteToken is the plaintext token of the last member.invited event ("" without one).
func (o *orgCase) lastInviteToken() string {
	invited := orgEventsOf[event.MemberInvited](o.srv)
	if len(invited) == 0 {
		return ""
	}
	return invited[len(invited)-1].InviteToken
}

// members lists org's members as token sees them.
func (o *orgCase) members(org, token string) []map[string]any {
	o.t.Helper()
	return orgMaps(o.json(o.c.Get("/orgs/"+org+"/members", contracttest.Bearer(token)))["data"])
}

// member is userID's entry in org's member list (nil when absent).
func (o *orgCase) member(org, userID, token string) map[string]any {
	o.t.Helper()
	for _, m := range o.members(org, token) {
		if m["user_id"] == userID {
			return m
		}
	}
	return nil
}

// rolesOf is userID's role slugs in org, sorted, as token sees them.
func (o *orgCase) rolesOf(org, userID, token string) []string {
	o.t.Helper()
	roles := orgStrs(o.member(org, userID, token)["roles"])
	slices.Sort(roles)
	return roles
}

func (o *orgCase) json(resp *http.Response) map[string]any {
	o.t.Helper()
	return contracttest.JSON(o.t, resp)
}

func (o *orgCase) must(err error) {
	o.t.Helper()
	if err != nil {
		o.t.Fatal(err)
	}
}

// status fails the test unless resp answered want.
func (o *orgCase) status(resp *http.Response, want int) {
	o.t.Helper()
	if resp.StatusCode != want {
		o.t.Fatalf("%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want)
	}
}

// equal fails the test unless got equals want (compared through their JSON encodings).
func (o *orgCase) equal(got, want any, what string) {
	o.t.Helper()
	g, _ := json.Marshal(got)
	w, _ := json.Marshal(want)
	if string(g) != string(w) {
		o.t.Fatalf("%s: got %s, want %s", what, g, w)
	}
}

func (o *orgCase) errorCode(resp *http.Response) any { return o.json(resp)["error"] }

func (o *orgCase) data(resp *http.Response) map[string]any { return orgMap(o.json(resp)["data"]) }

// orgEventsOf returns the recorded events of type T, in order.
func orgEventsOf[T event.Event](srv *polaristest.Server) []T {
	var out []T
	for _, e := range srv.Events.All() {
		if v, ok := e.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

// orgClaims decodes a JWT's payload without verifying it.
func orgClaims(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	return claims
}

func orgMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func orgMaps(v any) []map[string]any {
	items, _ := v.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func orgStrs(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
