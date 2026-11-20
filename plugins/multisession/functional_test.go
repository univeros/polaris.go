package multisession_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/multisession"
	"github.com/univeros/polaris.go/polaristest"
)

const (
	flowClass = `Polaris\MultiSession\Tests\Functional\MultiSessionFlowTest`
	password  = "correct horse battery staple"
)

func data(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	return d
}

func list(t *testing.T, resp *http.Response) []map[string]any {
	t.Helper()
	l, _ := contracttest.JSON(t, resp)["data"].([]any)
	out := make([]map[string]any, 0, len(l))
	for _, v := range l {
		out = append(out, v.(map[string]any))
	}
	return out
}

func emails(sessions []map[string]any) []string {
	out := []string{}
	for _, s := range sessions {
		out = append(out, s["user"].(map[string]any)["email"].(string))
	}
	return out
}

func status(t *testing.T, resp *http.Response, want int, msg string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s: %s %s: status %d, want %d", msg, resp.Request.Method, resp.Request.URL, resp.StatusCode, want)
	}
}

// register registers and verifies email.
func register(c *contracttest.Client, srv *polaristest.Server, email string) {
	c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var reg event.UserRegistered
	for _, e := range srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			reg = r
		}
	}
	c.Post("/auth/email/verify", map[string]any{"token": reg.VerificationToken})
}

func TestMultiSessionFlow(t *testing.T) {
	t.Run("testTwoAccountsOnOneDeviceSwitchAndSignOutOneAtATime", func(t *testing.T) {
		srv := polaristest.New(t, polaristest.WithPlugins(multisession.New(multisession.Config{DisableCookie: true})))
		c := contracttest.NewClient(t, srv.Handler(), contracttest.For(t, contracttest.UpstreamFixtures(t, "multi-session"), flowClass, "testTwoAccountsOnOneDeviceSwitchAndSignOutOneAtATime"))
		register(c, srv, "ada@example.com")
		register(c, srv, "grace@example.com")

		adaResp := c.Post("/auth/login", map[string]any{"email": "ada@example.com", "password": password})
		dev := adaResp.Header.Get(multisession.Header)
		if dev == "" {
			t.Fatal("a sign-in mints the device")
		}
		if m := data(t, c.Get("/multi-session/last-method", contracttest.Header(multisession.Header, dev)))["last_method"]; m != "pwd" {
			t.Fatalf("last method %v", m)
		}
		graceResp := c.Post("/auth/login", map[string]any{"email": "grace@example.com", "password": password}, contracttest.Header(multisession.Header, dev))
		if graceResp.Header.Get(multisession.Header) == dev {
			t.Fatal("joining the device gives it a new id")
		}
		dev = graceResp.Header.Get(multisession.Header)
		ada, grace := data(t, adaResp), data(t, graceResp)
		asGrace := contracttest.Bearer(grace["access_token"].(string))
		onDevice := contracttest.Header(multisession.Header, dev)

		status(t, c.Get("/multi-session/list", asGrace), 403, "no device")
		sessions := list(t, c.Get("/multi-session/list", asGrace, onDevice))
		if got := strings.Join(emails(sessions), ","); got != "grace@example.com,ada@example.com" {
			t.Fatalf("listed %s", got)
		}
		adaSession := sessions[1]["session_id"].(string)

		switched := data(t, c.Post("/multi-session/switch", map[string]any{"session_id": adaSession}, asGrace, onDevice))
		if switched["user"].(map[string]any)["email"] != "ada@example.com" {
			t.Fatalf("switched %v", switched)
		}
		status(t, c.Post("/auth/token/refresh", map[string]any{"refresh_token": ada["refresh_token"]}), 401, "ada's old session ended")
		status(t, c.Post("/multi-session/switch", map[string]any{"session_id": adaSession}, asGrace, onDevice), 404, "the old session is gone")

		asAda := contracttest.Bearer(switched["access_token"].(string))
		if n := len(list(t, c.Get("/multi-session/list", asAda, onDevice))); n != 2 {
			t.Fatalf("%d sessions", n)
		}
		tok, err := srv.Graph().Tokens().Parse(grace["access_token"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if s := data(t, c.Delete("/multi-session/"+tok.Claim("sid").(string), asAda, onDevice))["status"]; s != "revoked" {
			t.Fatalf("revoke %v", s)
		}
		status(t, c.Post("/auth/token/refresh", map[string]any{"refresh_token": grace["refresh_token"]}), 401, "grace is signed out")
		if got := emails(list(t, c.Get("/multi-session/list", asAda, onDevice))); len(got) != 1 || got[0] != "ada@example.com" {
			t.Fatalf("ada stays: %v", got)
		}
	})
}

// Port of CookieModeTest::testSignInsAreRecordedAgainstTheDeviceAndTheSwitchSetsTheCookie: the
// device middleware runs inside cookie delivery, so it sees the body-mode response.
func TestCookieMode(t *testing.T) {
	t.Run("testSignInsAreRecordedAgainstTheDeviceAndTheSwitchSetsTheCookie", func(t *testing.T) {
		srv := polaristest.New(t, polaristest.WithPlugins(multisession.New(multisession.Config{})),
			polaristest.WithAuth(func(a *config.Auth) { a.Flows.TokenDelivery = config.DeliveryCookie }))
		c := contracttest.NewClient(t, srv.Handler(), nil)
		register(c, srv, "ada@example.com")
		register(c, srv, "grace@example.com")
		send := func(method, path string, body any, opts ...contracttest.Option) *http.Response {
			return c.JSONRequest(method, "https://localhost"+path, body, append(opts, contracttest.Header("X-Polaris-CSRF", "1"))...)
		}
		cookies := func(resp *http.Response) map[string]string {
			out := map[string]string{}
			for _, ck := range resp.Cookies() {
				out[ck.Name] = ck.Value
			}
			return out
		}

		adaResp := send("POST", "/auth/login", map[string]any{"email": "ada@example.com", "password": password})
		status(t, adaResp, 200, "ada signs in")
		if _, has := data(t, adaResp)["refresh_token"]; has {
			t.Fatal("refresh token in the body")
		}
		dev := cookies(adaResp)[multisession.Cookie]
		if dev == "" || cookies(adaResp)["__Secure-polaris_refresh"] == "" {
			t.Fatalf("cookies %v", adaResp.Header.Values("Set-Cookie"))
		}
		if !strings.Contains(strings.Join(adaResp.Header.Values("Set-Cookie"), "\n"), multisession.Cookie+"="+dev+"; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax; Secure") {
			t.Fatalf("device cookie %v", adaResp.Header.Values("Set-Cookie"))
		}

		graceResp := send("POST", "/auth/login", map[string]any{"email": "grace@example.com", "password": password}, contracttest.Cookie(multisession.Cookie, dev))
		status(t, graceResp, 200, "grace signs in")
		dev = cookies(graceResp)[multisession.Cookie]
		asGrace := contracttest.Bearer(data(t, graceResp)["access_token"].(string))

		sessions := list(t, c.Get("https://localhost/multi-session/list", contracttest.Cookie(multisession.Cookie, dev), asGrace))
		if got := strings.Join(emails(sessions), ","); got != "grace@example.com,ada@example.com" {
			t.Fatalf("listed %s", got)
		}
		switched := send("POST", "/multi-session/switch", map[string]any{"session_id": sessions[1]["session_id"]}, contracttest.Cookie(multisession.Cookie, dev), asGrace)
		status(t, switched, 200, "switch")
		if data(t, switched)["user"].(map[string]any)["email"] != "ada@example.com" {
			t.Fatal("switched to ada")
		}
		if _, has := data(t, switched)["refresh_token"]; has || cookies(switched)["__Secure-polaris_refresh"] == "" {
			t.Fatal("the switch hands the refresh token to the cookie")
		}
	})
}

func TestEveryFixtureHasAGoTest(t *testing.T) {
	left, err := contracttest.Uncovered(contracttest.UpstreamFixtures(t, "multi-session"),
		[]string{flowClass + "::testTwoAccountsOnOneDeviceSwitchAndSignOutOneAtATime"})
	if err != nil || len(left) > 0 {
		t.Fatalf("uncovered %v (%v)", left, err)
	}
}
