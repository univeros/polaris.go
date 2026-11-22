package httpapi_test

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/polaristest"
)

// A field of another JSON type than its spec declares is a 422 naming the field: nothing is
// coerced (a number is not read as a string, true is not "1", "0" is not false).
func TestAFieldOfTheWrongTypeIsA422NamingIt(t *testing.T) {
	srv := polaristest.New(t)
	c := contracttest.NewClient(t, srv.Handler(), nil)
	refused := func(resp *http.Response, want ...string) {
		t.Helper()
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Fatalf("%s %s: status %d, want 422", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode)
		}
		got, _ := contracttest.JSON(t, resp)["errors"].([]any)
		wantAny := make([]any, len(want))
		for i, w := range want {
			wantAny[i] = w
		}
		if !reflect.DeepEqual(got, wantAny) {
			t.Errorf("errors = %v, want %v", got, want)
		}
	}

	refused(c.Post("/auth/login", map[string]any{"email": authEmail, "password": 12345678}), "password must be a string.")
	refused(c.Post("/auth/login", map[string]any{"email": true, "password": true}), "email must be a string.", "password must be a string.")
	refused(c.Post("/auth/token/refresh", map[string]any{"refresh_token": []any{"x"}}), "refresh_token must be a string.")

	c.Post("/auth/register", map[string]any{"email": authEmail, "password": authPassword})
	regs := authEventsOf[event.UserRegistered](srv)
	c.Post("/auth/email/verify", map[string]any{"token": regs[len(regs)-1].VerificationToken})
	access, _ := authPair(t, c.Post("/auth/login", map[string]any{"email": authEmail, "password": authPassword}))
	bearer := contracttest.Bearer(access)

	refused(c.Patch("/auth/mfa/factors/some-factor", map[string]any{"default": "1"}, bearer), "default must be true or false.")
	refused(c.Patch("/auth/mfa/factors/some-factor", map[string]any{"default": 0}, bearer), "default must be true or false.")
	refused(c.Post("/auth/mfa/totp/confirm", map[string]any{"factor_id": "f", "code": 123456}, bearer), "code must be a string.")
	refused(c.Post("/orgs", map[string]any{"name": 7}, bearer), "name must be a string.")
	refused(c.Post("/orgs", map[string]any{"name": "Acme", "slug": "acme\n"}, bearer),
		"The slug must be URL-safe (lowercase letters, digits and hyphens) and at most 160 characters.")

	// null is absent, as before: the endpoint's own rules answer.
	if resp := c.Patch("/auth/mfa/factors/some-factor", map[string]any{"default": nil}, bearer); resp.StatusCode != http.StatusNotFound {
		t.Errorf("default null: status %d, want 404 (no such factor)", resp.StatusCode)
	}
}
