package scim_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/scim"
	"github.com/univeros/polaris.go/polaristest"
)

const (
	password = "correct horse battery staple"
	base     = "https://app.example/auth"
	classes  = `Polaris\Scim\Tests\Functional\`
)

// flow is upstream's ScimTestCase: audit, admin and scim under the pipeline, replaying the
// recorded fixture of one PHP test.
type flow struct {
	t     *testing.T
	srv   *polaristest.Server
	c     *contracttest.Client
	admin *admin.Plugin
	trail *audit.Plugin
}

func newFlow(t *testing.T, class, method string) *flow {
	t.Helper()
	f := &flow{t: t, admin: admin.New(admin.Config{}), trail: audit.New(audit.Config{})}
	f.srv = polaristest.New(t, polaristest.WithPlugins(f.trail, f.admin, scim.New(scim.Config{BaseURL: base})))
	f.c = contracttest.NewClient(t, f.srv.Handler(), contracttest.For(t, contracttest.UpstreamFixtures(t, "scim"), classes+class, method))
	return f
}

func bearer(token string) contracttest.Option { return contracttest.Bearer(token) }

func doc(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	return contracttest.JSON(t, resp)
}

func data(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := doc(t, resp)["data"].(map[string]any)
	return d
}

func items(v any) []map[string]any {
	list, _ := v.([]any)
	out := make([]map[string]any, 0, len(list))
	for _, item := range list {
		m, _ := item.(map[string]any)
		out = append(out, m)
	}
	return out
}

func column(list []map[string]any, key string) []any {
	out := make([]any, 0, len(list))
	for _, m := range list {
		out = append(out, m[key])
	}
	return out
}

func check(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func status(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	check(t, resp.StatusCode == want, "%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL, resp.StatusCode, want)
}

// problem asserts a problem document whose type matches its error code.
func problem(t *testing.T, resp *http.Response, want int, code string) {
	t.Helper()
	status(t, resp, want)
	b := doc(t, resp)
	check(t, resp.Header.Get("Content-Type") == "application/problem+json" && b["error"] == code &&
		b["type"] == "https://polaris.univeros.io/problems/"+strings.Replace(code, "_", "/", 1), "problem %v, want %s", b, code)
}

// scimError asserts a SCIM error document.
func scimError(t *testing.T, resp *http.Response, want int, scimType string) {
	t.Helper()
	status(t, resp, want)
	b := doc(t, resp)
	typ, _ := b["scimType"].(string)
	schemas, _ := b["schemas"].([]any)
	check(t, resp.Header.Get("Content-Type") == scim.ContentType && b["status"] == strconv.Itoa(want) && typ == scimType &&
		len(schemas) == 1 && schemas[0] == scim.ErrorSchema, "scim error %v, want %d %q", b, want, scimType)
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

// organization creates an organization: its id and the access token switched to it.
func (f *flow) organization(name, access string) (string, string) {
	f.t.Helper()
	id, _ := data(f.t, f.c.Post("/orgs", map[string]any{"name": name}, bearer(access)))["id"].(string)
	switched, _ := data(f.t, f.c.Post("/auth/switch-org", map[string]any{"organization_id": id}, bearer(access)))["access_token"].(string)
	return id, switched
}

// connection creates a connection: its id and token.
func (f *flow) connection(orgID, access, name string) (string, string) {
	f.t.Helper()
	d := data(f.t, f.c.Post("/orgs/"+orgID+"/scim/connections", map[string]any{"name": name, "deprovision": "deactivate"}, bearer(access)))
	id, _ := d["id"].(string)
	token, _ := d["token"].(string)
	return id, token
}

// scim sends a request as a directory does: a SCIM JSON body, the connection token as bearer.
func (f *flow) scim(method, path string, body any, token string) *http.Response {
	f.t.Helper()
	var raw []byte
	var opts []contracttest.Option
	if body != nil {
		raw, _ = json.Marshal(body)
		opts = append(opts, contracttest.Header("Content-Type", scim.ContentType))
	}
	if token != "" {
		opts = append(opts, bearer(token))
	}
	return f.c.Do(f.c.NewRequest(method, path, raw, opts...))
}

func (f *flow) key(role admin.Role, scope string) string {
	f.t.Helper()
	_, secret, err := f.admin.Keys().Create(context.Background(), admin.Key{Name: "test", Role: role, Scope: scope, CreatedBy: "test"})
	if err != nil {
		f.t.Fatal(err)
	}
	return secret
}

// auditNames are the recorded names among names, newest first.
func (f *flow) auditNames(names ...string) []any {
	f.t.Helper()
	pg, err := f.trail.Store().Read(context.Background(), audit.Query{Names: names})
	if err != nil {
		f.t.Fatal(err)
	}
	out := make([]any, len(pg.Events))
	for i, e := range pg.Events {
		out[i] = e.Name
	}
	return out
}

// q is a filter query as PHP's rawurlencode writes it.
func q(filter string) string {
	return "?filter=" + strings.ReplaceAll(url.QueryEscape(filter), "+", "%20")
}
