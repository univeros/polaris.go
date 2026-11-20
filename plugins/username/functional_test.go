package username_test

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/plugins/username"
	"github.com/univeros/polaris-go/polaristest"
)

const (
	flowClass = `Polaris\Username\Tests\Functional\UsernameFlowTest`
	password  = "correct horse battery staple"
)

func data(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	return d
}

// login registers, verifies and logs email in: its access token.
func login(t *testing.T, srv *polaristest.Server, c *contracttest.Client, email string) string {
	t.Helper()
	c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var reg event.UserRegistered
	for _, e := range srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			reg = r
		}
	}
	c.Post("/auth/email/verify", map[string]any{"token": reg.VerificationToken})
	access, _ := data(t, c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return access
}

func TestUsernameFlow(t *testing.T) {
	const method = "testAUsernameIsUniqueWithoutRegardToCaseAndSignsInThroughThePasswordPath"
	t.Run(method, func(t *testing.T) {
		srv := polaristest.New(t, polaristest.WithPlugins(username.New(username.Config{})))
		c := contracttest.NewClient(t, srv.Handler(), contracttest.For(t, contracttest.UpstreamFixtures(t, "username"), flowClass, method))
		ada := login(t, srv, c, "ada@example.com")
		grace := login(t, srv, c, "grace@example.com")

		if resp := c.Patch("/username", map[string]any{"username": "ada.l"}, contracttest.Bearer("")); resp.StatusCode != 401 {
			t.Fatalf("no bearer: %d", resp.StatusCode)
		}
		invalid := contracttest.JSON(t, c.Patch("/username", map[string]any{"username": "admin"}, contracttest.Bearer(ada)))
		if invalid["error"] != "username_invalid" || !reflect.DeepEqual(invalid["errors"], []any{"The username is reserved."}) {
			t.Fatalf("reserved: %v", invalid)
		}
		if got := data(t, c.Patch("/username", map[string]any{"username": "Ada.L"}, contracttest.Bearer(ada))); got["username"] != "ada.l" || got["display_username"] != "Ada.L" {
			t.Fatalf("set: %v", got)
		}
		taken := c.Patch("/username", map[string]any{"username": "ADA.l"}, contracttest.Bearer(grace))
		if taken.StatusCode != 409 || contracttest.JSON(t, taken)["error"] != "username_taken" {
			t.Fatal("taken without regard to case")
		}

		for _, id := range []string{"ada.L", "ADA@example.com"} {
			session := data(t, c.Post("/username/sign-in", map[string]any{"username": id, "password": password}))
			if u, _ := session["user"].(map[string]any); u["email"] != "ada@example.com" {
				t.Fatalf("%s: %v", id, session)
			}
		}
		unknown := c.Post("/username/sign-in", map[string]any{"username": "nobody", "password": password})
		wrong := c.Post("/username/sign-in", map[string]any{"username": "ada.l", "password": "not the password"})
		if unknown.StatusCode != 401 || wrong.StatusCode != 401 || !reflect.DeepEqual(contracttest.JSON(t, unknown), contracttest.JSON(t, wrong)) {
			t.Fatal("an unknown username and a wrong password must answer the same 401")
		}
		if resp := c.Post("/username/sign-in", map[string]any{"username": "ada.l"}); resp.StatusCode != 422 {
			t.Fatalf("no password: %d", resp.StatusCode)
		}
	})
}

func TestEveryFixtureIsCovered(t *testing.T) {
	covered := []string{flowClass + "::testAUsernameIsUniqueWithoutRegardToCaseAndSignsInThroughThePasswordPath"}
	left, err := contracttest.Uncovered(contracttest.UpstreamFixtures(t, "username"), covered)
	if err != nil || len(left) > 0 {
		t.Fatalf("uncovered %v (%v)", left, err)
	}
}
