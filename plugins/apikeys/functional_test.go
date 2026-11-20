package apikeys_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/plugins/apikeys"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/store"
)

const (
	flowClass = `Polaris\ApiKeys\Tests\Functional\ApiKeysFlowTest`
	password  = "correct horse battery staple"
)

type flow struct {
	t     *testing.T
	srv   *polaristest.Server
	c     *contracttest.Client
	trail *audit.Plugin
	keys  *apikeys.Plugin
}

func newFlow(t *testing.T, method string) *flow {
	t.Helper()
	f := &flow{t: t, trail: audit.New(audit.Config{}), keys: apikeys.New(apikeys.Config{RotationGrace: time.Hour})}
	f.srv = polaristest.New(t, polaristest.WithPlugins(f.trail, f.keys))
	f.c = contracttest.NewClient(t, f.srv.Handler(), contracttest.For(t, contracttest.UpstreamFixtures(t, "api-keys"), flowClass, method))
	return f
}

func data(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	return d
}

func list(t *testing.T, resp *http.Response) []any {
	t.Helper()
	l, _ := contracttest.JSON(t, resp)["data"].([]any)
	return l
}

func status(t *testing.T, resp *http.Response, want int, msg ...string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d %v", resp.Request.Method, resp.Request.URL, resp.StatusCode, want, msg)
	}
}

// problem asserts an api-keys problem document.
func problem(t *testing.T, resp *http.Response, want int, code string) {
	t.Helper()
	status(t, resp, want, code)
	body := contracttest.JSON(t, resp)
	if resp.Header.Get("Content-Type") != "application/problem+json" || body["error"] != code ||
		body["type"] != "https://polaris.univeros.io/problems/api-keys/"+strings.TrimPrefix(code, "api_keys_") {
		t.Fatalf("problem %v", body)
	}
}

// login registers, verifies and logs email in: its user id and access token.
func (f *flow) login(email string) (string, string) {
	f.t.Helper()
	f.c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var reg event.UserRegistered
	for _, e := range f.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			reg = r
		}
	}
	f.c.Post("/auth/email/verify", map[string]any{"token": reg.VerificationToken})
	access, _ := data(f.t, f.c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return reg.UserID, access
}

// organization creates an organization and switches to it: its id and the switched token.
func (f *flow) organization(access, name string) (string, string) {
	f.t.Helper()
	created := f.c.Post("/orgs", map[string]any{"name": name}, contracttest.Bearer(access))
	status(f.t, created, 201)
	id, _ := data(f.t, created)["id"].(string)
	switched := f.c.Post("/auth/switch-org", map[string]any{"organization_id": id}, contracttest.Bearer(access))
	status(f.t, switched, 200)
	token, _ := data(f.t, switched)["access_token"].(string)
	return id, token
}

func TestApiKeysFlow(t *testing.T) {
	t.Run("testAKeyActsAsItsOwnerWithTheDelegatedPermissionsOnEveryRoute", func(t *testing.T) {
		f := newFlow(t, "testAKeyActsAsItsOwnerWithTheDelegatedPermissionsOnEveryRoute")
		userID, session := f.login("ada@example.com")
		orgID, session := f.organization(session, "Acme")
		as := contracttest.Bearer(session)

		created := f.c.Post("/api-keys", map[string]any{"name": "CI deploy", "permissions": []string{"org.read"}, "metadata": map[string]any{"pipeline": "main"}}, as)
		status(t, created, 201)
		key := data(t, created)
		secret, id := key["key"].(string), key["id"].(string)
		if !strings.HasPrefix(secret, "pk_live_") || key["organization_id"] != orgID || key["owner_type"] != apikeys.OwnerUser {
			t.Fatalf("created %v", key)
		}
		listed := list(t, f.c.Get("/api-keys", as))
		if len(listed) != 1 || listed[0].(map[string]any)["key"] != nil || listed[0].(map[string]any)["hint"] != secret[len(secret)-4:] {
			t.Fatalf("listed %v", listed)
		}
		if _, has := data(t, f.c.Get("/api-keys/"+id, as))["key"]; has {
			t.Fatal("the read shows the secret")
		}

		withKey := contracttest.Bearer(secret)
		me := f.c.Get("/auth/me", withKey)
		status(t, me, 200)
		if data(t, me)["id"] != userID {
			t.Fatal("the key does not act as its owner")
		}
		status(t, f.c.Get("/audit/me", contracttest.Header("x-api-key", secret)), 200)
		status(t, f.c.Get("/orgs/"+orgID, withKey), 200)
		status(t, f.c.Get("/orgs/"+orgID+"/members", withKey), 403, "held by the owner, not delegated")
		problem(t, f.c.Post("/auth/mfa/recovery-codes/regenerate", nil, withKey), 403, "api_keys_not_allowed")

		problem(t, f.c.Post("/api-keys", map[string]any{"name": "x", "permissions": []string{"users.manage"}}, as), 403, "api_keys_permission_not_held")
		problem(t, f.c.Post("/api-keys", map[string]any{"name": "x", "permissions": []string{"nothing.here"}}, as), 422, "api_keys_invalid_input")
		minted := f.c.Post("/api-keys", map[string]any{"name": "from a key", "permissions": []string{"org.read"}}, withKey)
		status(t, minted, 403)
		if contracttest.JSON(t, minted)["error"] != "forbidden" {
			t.Fatal("a key minted a key")
		}
		status(t, f.c.Post("/orgs", map[string]any{"name": "From a key"}, withKey), 403)
		status(t, f.c.Post("/auth/mfa/totp/enroll", nil, withKey), 403)

		verified := data(t, f.c.Post("/api-keys/verify", map[string]any{"key": secret}, as))
		if verified["valid"] != true || verified["id"] != id || verified["subject"] != userID {
			t.Fatalf("verified %v", verified)
		}
		if data(t, f.c.Post("/api-keys/verify", map[string]any{"key": "pk_live_nothing"}, as))["valid"] != false {
			t.Fatal("an unknown key verified")
		}

		updated := data(t, f.c.Patch("/api-keys/"+id, map[string]any{"name": "CI deploy (renamed)", "permissions": []string{"org.read", "members.read"}, "rate_limit": map[string]any{"window": 60, "max": 2}}, as))
		if perms := updated["permissions"].([]any); len(perms) != 2 {
			t.Fatalf("updated %v", updated)
		}
		status(t, f.c.Get("/orgs/"+orgID+"/members", withKey), 200, "members.read delegated now")

		second := f.c.Get("/auth/me", withKey)
		status(t, second, 200)
		if second.Header.Get("X-RateLimit-Remaining") != "0" || second.Header.Get("X-RateLimit-Limit") != "2" {
			t.Fatalf("headers %v", second.Header)
		}
		third := f.c.Get("/auth/me", withKey)
		status(t, third, 429)
		if third.Header.Get("X-RateLimit-Remaining") != "0" || third.Header.Get("Retry-After") == "" {
			t.Fatalf("429 headers %v", third.Header)
		}

		f.c.Patch("/api-keys/"+id, map[string]any{"rate_limit": nil}, as)
		rotated := f.c.Post("/api-keys/"+id+"/rotate", nil, as)
		status(t, rotated, 201)
		successor := data(t, rotated)
		next := successor["key"].(string)
		if next == secret || successor["rotated_from"] != id {
			t.Fatalf("successor %v", successor)
		}
		status(t, f.c.Get("/auth/me", withKey), 200, "the old key answers during the grace")
		status(t, f.c.Get("/auth/me", contracttest.Bearer(next)), 200)
		if data(t, f.c.Get("/api-keys/"+id, as))["status"] != apikeys.StatusRotated {
			t.Fatal("not rotated")
		}
		problem(t, f.c.Post("/api-keys/"+id+"/rotate", nil, as), 403, "api_keys_forbidden")

		if data(t, f.c.Delete("/api-keys/"+id, as))["status"] != "revoked" {
			t.Fatal("not revoked")
		}
		status(t, f.c.Get("/auth/me", withKey), 401)
		status(t, f.c.Get("/auth/me", contracttest.Bearer(next)), 200)
		status(t, f.c.Get("/api-keys/"+id, as), 404)
		if len(list(t, f.c.Get("/api-keys", as))) != 1 {
			t.Fatal("the revoked key is listed")
		}

		page, err := f.trail.Store().Read(context.Background(), audit.Query{Names: []string{apikeys.AuditCreated, apikeys.AuditUpdated, apikeys.AuditRotated, apikeys.AuditRevoked}})
		if err != nil {
			t.Fatal(err)
		}
		counts := map[string]int{}
		for _, e := range page.Events {
			counts[e.Name]++
		}
		if counts[apikeys.AuditCreated] != 1 || counts[apikeys.AuditUpdated] != 2 || counts[apikeys.AuditRotated] != 1 || counts[apikeys.AuditRevoked] != 1 {
			t.Fatalf("audited %v", counts)
		}
		n := 0
		for _, e := range f.srv.Events.All() {
			if _, ok := e.(apikeys.Event); ok {
				n++
			}
		}
		if n != 5 {
			t.Fatalf("%d key events", n)
		}
	})

	t.Run("testAnOrganizationsKeyIsManagedByItsAdminsAndActsAsItsCreator", func(t *testing.T) {
		f := newFlow(t, "testAnOrganizationsKeyIsManagedByItsAdminsAndActsAsItsCreator")
		adaID, ada := f.login("ada@example.com")
		orgID, ada := f.organization(ada, "Acme")
		_, bob := f.login("bob@example.com")
		asAda, asBob := contracttest.Bearer(ada), contracttest.Bearer(bob)

		problem(t, f.c.Post("/api-keys", map[string]any{"name": "Acme bot", "organization_id": orgID}, asBob), 403, "api_keys_forbidden")
		created := f.c.Post("/api-keys", map[string]any{"name": "Acme bot", "organization_id": orgID, "permissions": []string{"members.read"}, "environment": "test"}, asAda)
		status(t, created, 201)
		key := data(t, created)
		secret, id := key["key"].(string), key["id"].(string)
		if !strings.HasPrefix(secret, "pk_test_") || key["owner_type"] != apikeys.OwnerOrganization || key["owner_id"] != orgID || key["created_by"] != adaID {
			t.Fatalf("created %v", key)
		}

		if len(list(t, f.c.Get("/api-keys", asAda))) != 0 || len(list(t, f.c.Get("/api-keys?organization_id="+orgID, asAda))) != 1 {
			t.Fatal("the key lists under the organization only")
		}
		problem(t, f.c.Get("/api-keys?organization_id="+orgID, asBob), 403, "api_keys_forbidden")
		withKey := contracttest.Bearer(secret)
		status(t, f.c.Get("/orgs/"+orgID+"/members", withKey), 200)
		status(t, f.c.Get("/orgs/"+orgID, withKey), 403, "org.read was not delegated")
		if data(t, f.c.Get("/auth/me", withKey))["id"] != adaID {
			t.Fatal("the key does not act as its creator")
		}

		status(t, f.c.Get("/api-keys/"+id, asBob), 404)
		status(t, f.c.Delete("/api-keys/"+id, asBob), 404)
		status(t, f.c.Delete("/api-keys/"+id, asAda), 200)
		status(t, f.c.Get("/auth/me", withKey), 401)
	})

	t.Run("testAnExpiredKeyAndATooLargeBudgetAreRefused", func(t *testing.T) {
		f := newFlow(t, "testAnExpiredKeyAndATooLargeBudgetAreRefused")
		_, session := f.login("ada@example.com")
		as := contracttest.Bearer(session)
		problem(t, f.c.Post("/api-keys", map[string]any{"name": "old", "expires_at": "2020-01-01T00:00:00+00:00"}, as), 422, "api_keys_invalid_input")
		problem(t, f.c.Post("/api-keys", map[string]any{"name": "old", "rate_limit": map[string]any{"window": 0, "max": 1}}, as), 422, "api_keys_invalid_input")
		problem(t, f.c.Post("/api-keys", map[string]any{"name": "", "permissions": []string{}}, as), 422, "api_keys_invalid_input")
		created := data(t, f.c.Post("/api-keys", map[string]any{"name": "short-lived", "expires_at": "2099-01-01T00:00:00+00:00"}, as))
		if created["expires_at"] != "2099-01-01T00:00:00+00:00" {
			t.Fatalf("created %v", created)
		}
		secret, id := created["key"].(string), created["id"].(string)
		status(t, f.c.Get("/auth/me", contracttest.Bearer(secret)), 200)
		ctx := context.Background()
		if _, err := f.srv.DB.Update(ctx, apikeys.TableKeys, store.Criteria{"id": id}, store.Data{"expires_at": time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)}); err != nil {
			t.Fatal(err)
		}
		status(t, f.c.Get("/auth/me", contracttest.Bearer(secret)), 401)
		if _, ok, _ := f.keys.Keys().Authenticate(ctx, secret); ok {
			t.Fatal("an expired key authenticated")
		}
		if data(t, f.c.Get("/api-keys/"+id, as))["status"] != apikeys.StatusExpired {
			t.Fatal("not expired")
		}
	})
}

func TestEveryFixtureIsCovered(t *testing.T) {
	var covered []string
	for _, m := range []string{"testAKeyActsAsItsOwnerWithTheDelegatedPermissionsOnEveryRoute", "testAnOrganizationsKeyIsManagedByItsAdminsAndActsAsItsCreator", "testAnExpiredKeyAndATooLargeBudgetAreRefused"} {
		covered = append(covered, flowClass+"::"+m)
	}
	left, err := contracttest.Uncovered(contracttest.UpstreamFixtures(t, "api-keys"), covered)
	if err != nil || len(left) > 0 {
		t.Fatalf("uncovered %v (%v)", left, err)
	}
}
