package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// TestTenantFlow walks the README: an organization with custom roles, the protected project
// routes for the owner, an invited viewer and an organization API key, and a SCIM-provisioned user.
func TestTenantFlow(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_ISSUER"} {
		t.Setenv(name, "")
	}
	if err := devEnv("http://localhost"); err != nil {
		t.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.DB().Close() })
	mails := &inbox{}
	h, p, err := newServer(ctx, db, mails)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c := client{t: t, base: srv.URL}

	ada := c.signIn(p, "ada@acme.test")
	org := c.do("POST", "/orgs", ada, map[string]any{"name": "Acme"}, http.StatusCreated)["data"].(map[string]any)["id"].(string)
	ada = c.switchOrg(ada, org)
	c.do("POST", "/orgs/"+org+"/roles", ada, map[string]any{"name": "Viewer", "slug": "viewer", "permission_keys": []string{"org.read", "projects.read"}}, http.StatusCreated)
	c.do("POST", "/api/projects", ada, map[string]any{"name": "Website relaunch"}, http.StatusCreated)

	// An invited viewer reads but does not write.
	c.do("POST", "/orgs/"+org+"/invites", ada, map[string]any{"email": "bob@acme.test", "role_slugs": []string{"viewer"}}, http.StatusCreated)
	bob := c.signIn(p, "bob@acme.test")
	c.do("POST", "/auth/invites/accept", bob, map[string]any{"token": mails.token(t, "bob@acme.test")}, http.StatusOK)
	bob = c.switchOrg(bob, org)
	if got := c.do("GET", "/api/projects", bob, nil, http.StatusOK)["projects"].([]any); len(got) != 1 {
		t.Errorf("bob sees %v", got)
	}
	c.do("POST", "/api/projects", bob, map[string]any{"name": "Nope"}, http.StatusForbidden)

	// An organization API key carries only projects.read.
	key := c.do("POST", "/api-keys", ada, map[string]any{"name": "CI", "organization_id": org, "permissions": []string{"projects.read"}}, http.StatusCreated)["data"].(map[string]any)["key"].(string)
	if got := c.do("GET", "/api/projects", key, nil, http.StatusOK)["caller"]; got != "api_key" {
		t.Errorf("caller = %v", got)
	}
	c.do("POST", "/api/projects", key, map[string]any{"name": "Nope"}, http.StatusForbidden)

	// A SCIM directory provisions a member.
	conn := c.do("POST", "/orgs/"+org+"/scim/connections", ada, map[string]any{"name": "Okta"}, http.StatusCreated)["data"].(map[string]any)
	c.do("POST", "/scim/v2/"+conn["id"].(string)+"/Users", conn["token"].(string),
		map[string]any{"userName": "carol@acme.test", "emails": []map[string]any{{"value": "carol@acme.test", "primary": true}}}, http.StatusCreated)
	members, _ := json.Marshal(c.do("GET", "/orgs/"+org+"/members", ada, nil, http.StatusOK))
	if !strings.Contains(string(members), "carol@acme.test") {
		t.Errorf("members: %s", members)
	}
}

type client struct {
	t    *testing.T
	base string
}

// do sends a JSON request and checks the status; it answers the decoded body.
func (c client) do(method, path, bearer string, body any, want int) map[string]any {
	c.t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(method, c.base+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if resp.StatusCode != want {
		c.t.Fatalf("%s %s: %d, want %d: %v", method, path, resp.StatusCode, want, out)
	}
	return out
}

// signIn creates a verified account in process and signs it in over HTTP.
func (c client) signIn(p *polaris.Polaris, email string) string {
	c.t.Helper()
	const password = "correct horse battery staple"
	if _, err := p.Users().Create(context.Background(), polaris.NewUser{Email: email, Password: password, EmailVerified: true}); err != nil {
		c.t.Fatal(err)
	}
	return c.do("POST", "/auth/login", "", map[string]any{"email": email, "password": password}, http.StatusOK)["data"].(map[string]any)["access_token"].(string)
}

func (c client) switchOrg(bearer, org string) string {
	c.t.Helper()
	return c.do("POST", "/auth/switch-org", bearer, map[string]any{"organization_id": org}, http.StatusOK)["data"].(map[string]any)["access_token"].(string)
}

// inbox is a notify.Mailer that keeps the invitation tokens.
type inbox struct {
	mu     sync.Mutex
	tokens map[string]string
}

func (m *inbox) Send(_ context.Context, to, template string, data map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if template == notify.TemplateOrgInvite {
		if m.tokens == nil {
			m.tokens = map[string]string{}
		}
		m.tokens[to], _ = data["token"].(string)
	}
	return nil
}

func (m *inbox) token(t *testing.T, to string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokens[to] == "" {
		t.Fatalf("no invitation mailed to %s", to)
	}
	return m.tokens[to]
}
