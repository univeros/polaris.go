package httpapi_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/polaristest"
)

const (
	authEmail       = "ada@example.com"
	authPassword    = "correct horse battery staple"
	authNewPassword = "an entirely different passphrase"
	authPHPNS       = `Polaris\Tests\Functional\`
)

// authCase boots a server and a client replaying the fixture of the PHP test class::method.
type authCase struct {
	t   *testing.T
	srv *polaristest.Server
	c   *contracttest.Client
}

func authNew(t *testing.T, class, method string, opts ...polaristest.Option) *authCase {
	t.Helper()
	srv := polaristest.New(t, opts...)
	fx := contracttest.For(t, contracttest.UpstreamFixtures(t, "core"), authPHPNS+class, method)
	return &authCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), fx)}
}

// authEventsOf returns the dispatched events of type T, in order.
func authEventsOf[T event.Event](srv *polaristest.Server) []T {
	var out []T
	for _, e := range srv.Events.All() {
		if v, ok := e.(T); ok {
			out = append(out, v)
		}
	}
	return out
}

func authStatusIs(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL.Path, resp.StatusCode, want)
	}
}

// register registers email and verifies it with the token of the last user.registered event.
func (a *authCase) register(email, password string) {
	a.t.Helper()
	a.c.Post("/auth/register", map[string]any{"email": email, "password": password})
	regs := authEventsOf[event.UserRegistered](a.srv)
	if len(regs) == 0 {
		a.t.Fatal("no user.registered event")
	}
	a.c.Post("/auth/email/verify", map[string]any{"token": regs[len(regs)-1].VerificationToken})
}

// login logs email in and returns the access and refresh tokens ("" when absent).
func (a *authCase) login(email, password string) (access, refresh string) {
	a.t.Helper()
	return authPair(a.t, a.c.Post("/auth/login", map[string]any{"email": email, "password": password}))
}

func authPair(t testing.TB, resp *http.Response) (access, refresh string) {
	t.Helper()
	data, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	access, _ = data["access_token"].(string)
	refresh, _ = data["refresh_token"].(string)
	return access, refresh
}

func (a *authCase) user(email string) model.User {
	a.t.Helper()
	u, err := a.srv.Graph().Repos().Users.ByEmail(context.Background(), email)
	if err != nil {
		a.t.Fatalf("user %s: %v", email, err)
	}
	return u
}

// updateUser applies edit to the stored user, as the PHP tests persist through the unit of work.
func (a *authCase) updateUser(email string, edit func(u *model.User)) {
	a.t.Helper()
	before := a.user(email)
	after := before
	edit(&after)
	if err := a.srv.Graph().Repos().Users.Update(context.Background(), before, after); err != nil {
		a.t.Fatalf("update user: %v", err)
	}
}

func (a *authCase) sidOf(access string) string {
	a.t.Helper()
	tok, err := a.srv.Graph().Tokens().Parse(access)
	if err != nil {
		a.t.Fatalf("parse access token: %v", err)
	}
	sid, _ := tok.Claim("sid").(string)
	return sid
}
