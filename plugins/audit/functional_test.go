package audit_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
)

const (
	routesClass = `Polaris\Audit\Tests\Functional\AuditRoutesTest`
	email       = "ada@example.com"
	password    = "correct horse battery staple"
)

type flow struct {
	t   *testing.T
	srv *polaristest.Server
	c   *contracttest.Client
}

func newFlow(t *testing.T, method string) *flow {
	t.Helper()
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{})))
	fx := contracttest.For(t, contracttest.UpstreamFixtures(t, "audit"), routesClass, method)
	return &flow{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), fx)}
}

func (f *flow) registerVerifyLogin() string {
	f.t.Helper()
	f.c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var token string
	for _, e := range f.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			token = r.VerificationToken
		}
	}
	f.c.Post("/auth/email/verify", map[string]any{"token": token})
	return dataString(f.t, f.c.Post("/auth/login", map[string]any{"email": email, "password": password}), "access_token")
}

func dataString(t *testing.T, resp *http.Response, key string) string {
	t.Helper()
	data, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	s, _ := data[key].(string)
	return s
}

func names(t *testing.T, resp *http.Response) []string {
	t.Helper()
	var out []string
	list, _ := contracttest.JSON(t, resp)["data"].([]any)
	for _, item := range list {
		out = append(out, item.(map[string]any)["name"].(string))
	}
	return out
}

func status(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL, resp.StatusCode, want)
	}
}

func TestAuditRoutes(t *testing.T) {
	t.Run("testTheCallersTrailListsTheAuthFlowNewestFirstWithFiltersAndPages", func(t *testing.T) {
		f := newFlow(t, "testTheCallersTrailListsTheAuthFlowNewestFirstWithFiltersAndPages")
		access := f.registerVerifyLogin()

		me := f.c.Get("/audit/me", contracttest.Bearer(access))
		if got := names(t, me); !slices.Equal(got, []string{audit.SessionSignedIn, audit.UserEmailVerified, audit.UserSignedUp}) {
			t.Fatalf("trail %v", got)
		}
		body := contracttest.JSON(t, me)
		data := body["data"].([]any)
		if body["next_cursor"] != nil || data[0].(map[string]any)["session_id"] == nil || data[0].(map[string]any)["actor_type"] != "user" {
			t.Fatalf("body %v", body)
		}
		if got := data[2].(map[string]any)["data"].(map[string]any); len(got) != 1 || got["email"] != email {
			t.Fatalf("no verification token in the data: %v", got)
		}
		if got := names(t, f.c.Get("/audit/me?names="+audit.UserSignedUp, contracttest.Bearer(access))); !slices.Equal(got, []string{audit.UserSignedUp}) {
			t.Fatalf("filtered %v", got)
		}
		first := contracttest.JSON(t, f.c.Get("/audit/me?limit=2", contracttest.Bearer(access)))
		cursor, _ := first["next_cursor"].(string)
		if items := first["data"].([]any); len(items) != 2 || items[1].(map[string]any)["id"] != cursor {
			t.Fatalf("first page %v", first)
		}
		second := f.c.Get("/audit/me?limit=2&cursor="+cursor, contracttest.Bearer(access))
		if got := names(t, second); !slices.Equal(got, []string{audit.UserSignedUp}) || contracttest.JSON(t, second)["next_cursor"] != nil {
			t.Fatalf("second page %v", got)
		}
		invalid := f.c.Get("/audit/me?from=yesterday-ish-nonsense", contracttest.Bearer(access))
		status(t, invalid, 422)
		if invalid.Header.Get("Content-Type") != "application/problem+json" || contracttest.JSON(t, invalid)["error"] != "audit_invalid_query" {
			t.Fatal("invalid query problem")
		}
		status(t, f.c.Get("/audit/me"), 401)
	})

	t.Run("testTheCatalogIsListedForASession", func(t *testing.T) {
		f := newFlow(t, "testTheCatalogIsListedForASession")
		access := f.registerVerifyLogin()
		if got := names(t, f.c.Get("/audit/types", contracttest.Bearer(access))); !slices.Contains(got, audit.SessionSignedIn) {
			t.Fatalf("types %v", got)
		}
		status(t, f.c.Get("/audit/types"), 401)
	})

	t.Run("testAnOrganizationsTrailNeedsTheActiveOrganizationAndAuditRead", func(t *testing.T) {
		f := newFlow(t, "testAnOrganizationsTrailNeedsTheActiveOrganizationAndAuditRead")
		access := f.registerVerifyLogin()
		org := dataString(t, f.c.Post("/orgs", map[string]any{"name": "Acme Rockets"}, contracttest.Bearer(access)), "id")
		other := dataString(t, f.c.Post("/orgs", map[string]any{"name": "Globex"}, contracttest.Bearer(access)), "id")
		scoped := dataString(t, f.c.Post("/auth/switch-org", map[string]any{"organization_id": org}, contracttest.Bearer(access)), "access_token")

		trail := f.c.Get("/audit/organization/"+org, contracttest.Bearer(scoped))
		if got := names(t, trail); !slices.Equal(got, []string{audit.SessionOrganizationSwitched, audit.OrgCreated}) {
			t.Fatalf("trail %v", got)
		}
		forbidden := f.c.Get("/audit/organization/"+other, contracttest.Bearer(scoped))
		status(t, forbidden, 403)
		if contracttest.JSON(t, forbidden)["error"] != "audit_forbidden" {
			t.Fatal("audit_forbidden expected")
		}
		status(t, f.c.Get("/audit/organization/"+org, contracttest.Bearer(access)), 403)
		status(t, f.c.Get("/audit/organization/"+org), 401)
	})
}

func TestEveryFixtureIsCovered(t *testing.T) {
	var covered []string
	for _, m := range []string{"testTheCallersTrailListsTheAuthFlowNewestFirstWithFiltersAndPages", "testTheCatalogIsListedForASession", "testAnOrganizationsTrailNeedsTheActiveOrganizationAndAuditRead"} {
		covered = append(covered, routesClass+"::"+m)
	}
	left, err := contracttest.Uncovered(contracttest.UpstreamFixtures(t, "audit"), covered)
	if err != nil || len(left) > 0 {
		t.Fatalf("uncovered %v (%v)", left, err)
	}
}
