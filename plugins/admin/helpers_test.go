package admin_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

const (
	password = "correct horse battery staple"
	operator = "operator@example.com"
)

// flow is upstream's AdminTestCase: a server with the audit and admin plugins, replaying the
// recorded fixture of one PHP test.
type flow struct {
	t     *testing.T
	srv   *polaristest.Server
	c     *contracttest.Client
	admin *admin.Plugin
}

func newFlow(t *testing.T, class, method string) *flow {
	t.Helper()
	f := &flow{t: t, admin: admin.New(admin.Config{})}
	f.srv = polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), f.admin))
	fixture := contracttest.For(t, contracttest.UpstreamFixtures(t, "admin"), `Polaris\Admin\Tests\Functional\`+class, method)
	f.c = contracttest.NewClient(t, f.srv.Handler(), fixture)
	return f
}

func as(token string) contracttest.Option { return contracttest.Bearer(token) }

func body(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	return contracttest.JSON(t, resp)
}

func data(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := body(t, resp)["data"].(map[string]any)
	return d
}

func list(t *testing.T, resp *http.Response) []map[string]any {
	t.Helper()
	items, _ := body(t, resp)["data"].([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		m, _ := item.(map[string]any)
		out = append(out, m)
	}
	return out
}

func column(items []map[string]any, key string) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		out = append(out, item[key])
	}
	return out
}

func want(t *testing.T, cond bool, format string, args ...any) {
	t.Helper()
	if !cond {
		t.Fatalf(format, args...)
	}
}

func wantStatus(t *testing.T, resp *http.Response, status int) {
	t.Helper()
	want(t, resp.StatusCode == status, "%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL, resp.StatusCode, status)
}

// problem asserts an admin (or audit) problem document; its body.
func problem(t *testing.T, resp *http.Response, status int, code string) map[string]any {
	t.Helper()
	wantStatus(t, resp, status)
	b := body(t, resp)
	typ := strings.Replace(code, "_", "/", 1)
	want(t, resp.Header.Get("Content-Type") == "application/problem+json" && b["error"] == code &&
		b["type"] == "https://polaris.univeros.io/problems/"+typ, "problem %v, want %s", b, code)
	return b
}

// login registers (once), verifies and logs email in: its access token.
func (f *flow) login(email string) string {
	f.t.Helper()
	if f.c.Post("/auth/register", map[string]any{"email": email, "password": password}).StatusCode < 300 {
		var reg event.UserRegistered
		for _, e := range f.srv.Events.All() {
			if r, ok := e.(event.UserRegistered); ok {
				reg = r
			}
		}
		f.c.Post("/auth/email/verify", map[string]any{"token": reg.VerificationToken})
	}
	access, _ := data(f.t, f.c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return access
}

// operator logs the operator in with a grant of role on scope ("" for the instance).
func (f *flow) operator(role admin.Role, scope string) string {
	f.t.Helper()
	access := f.login(operator)
	if _, err := f.admin.Grants().Grant(context.Background(), admin.Grant{UserID: f.userID(operator), Role: role, Scope: scope}); err != nil {
		f.t.Fatal(err)
	}
	return access
}

// key creates an operator API key: its secret.
func (f *flow) key(role admin.Role, scope string, expiresAt *time.Time) string {
	f.t.Helper()
	_, secret, err := f.admin.Keys().Create(context.Background(), admin.Key{Name: "test", Role: role, Scope: scope, ExpiresAt: expiresAt, CreatedBy: "test"})
	if err != nil {
		f.t.Fatal(err)
	}
	return secret
}

func (f *flow) userID(email string) string {
	f.t.Helper()
	u, err := f.srv.Graph().Repos().Users.ByEmail(context.Background(), email)
	if err != nil {
		f.t.Fatalf("no user %s: %v", email, err)
	}
	return u.ID
}

func (f *flow) createOrg(name, access string) string {
	f.t.Helper()
	id, _ := data(f.t, f.c.Post("/orgs", map[string]any{"name": name}, as(access)))["id"].(string)
	return id
}

// join makes the user an active member of the organization with the role slug, without the
// invitation round trip.
func (f *flow) join(email, orgID, slug string) {
	f.t.Helper()
	ctx := context.Background()
	role, err := f.srv.Graph().Repos().Roles.ByOrganizationAndSlug(ctx, &orgID, slug)
	if err != nil {
		f.t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	id := repository.NewID()
	db := f.srv.DB
	if err := db.Insert(ctx, "auth_memberships", store.Row{
		"id": id, "user_id": f.userID(email), "organization_id": orgID, "status": "active", "invited_by": nil,
		"joined_at": now, "created_at": now, "updated_at": now,
	}); err != nil {
		f.t.Fatal(err)
	}
	if err := db.Insert(ctx, "auth_membership_roles", store.Row{"membership_id": id, "role_id": role.ID}); err != nil {
		f.t.Fatal(err)
	}
}

// enrol enrols and confirms a TOTP factor for the token's user.
func (f *flow) enrol(access string) {
	f.t.Helper()
	enrolled := data(f.t, f.c.Post("/auth/mfa/totp/enroll", nil, as(access)))
	secret, _ := enrolled["secret"].(string)
	code, err := totp.GenerateCodeCustom(secret, f.srv.Graph().Clock().Now(), totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		f.t.Fatal(err)
	}
	wantStatus(f.t, f.c.Post("/auth/mfa/totp/confirm", map[string]any{"factor_id": enrolled["factor_id"], "code": code}, as(access)), 200)
}
