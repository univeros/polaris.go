package multisession

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/token"
)

// Port of packages/multi-session/tests/PluginTest.php.

const pw = "correct horse battery staple"

type harness struct {
	t   *testing.T
	srv *polaristest.Server
	p   *Plugin
	c   *contracttest.Client
}

func boot(t *testing.T, cfg Config) *harness {
	t.Helper()
	p := New(cfg)
	srv := polaristest.New(t, polaristest.WithPlugins(p))
	return &harness{t: t, srv: srv, p: p, c: contracttest.NewClient(t, srv.Handler(), nil)}
}

func (h *harness) user(email string) model.User {
	h.t.Helper()
	g := h.srv.Graph()
	hash, err := g.Hasher().Hash(pw)
	if err != nil {
		h.t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	u := model.User{ID: repository.NewID(), Email: email, PasswordHash: &hash, EmailVerifiedAt: &now, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := g.Repos().Users.Insert(context.Background(), u); err != nil {
		h.t.Fatal(err)
	}
	return u
}

type req struct {
	body          any
	token, device string
	cookie        string
}

func (h *harness) send(method, path string, r req) *http.Response {
	opts := []contracttest.Option{contracttest.RemoteAddr("203.0.113.7:1234")}
	if r.token != "" {
		opts = append(opts, contracttest.Bearer(r.token))
	}
	if r.device != "" {
		opts = append(opts, contracttest.Header(Header, r.device))
	}
	if r.cookie != "" {
		opts = append(opts, contracttest.Cookie(Cookie, r.cookie))
	}
	if r.body == nil {
		return h.c.Do(h.c.NewRequest(method, "https://app.example"+path, nil, opts...))
	}
	return h.c.JSONRequest(method, "https://app.example"+path, r.body, opts...)
}

func (h *harness) login(email string, r req) *http.Response {
	r.body = map[string]any{"email": email, "password": pw}
	return h.send(http.MethodPost, "/auth/login", r)
}

func (h *harness) data(resp *http.Response) map[string]any {
	d, _ := contracttest.JSON(h.t, resp)["data"].(map[string]any)
	return d
}

func (h *harness) claims(access string) map[string]any {
	h.t.Helper()
	tok, err := h.srv.Graph().Tokens().Parse(access)
	if err != nil {
		h.t.Fatal(err)
	}
	return tok.Claims()
}

func (h *harness) emails(resp *http.Response) []string {
	l, _ := contracttest.JSON(h.t, resp)["data"].([]any)
	out := []string{}
	for _, s := range l {
		out = append(out, s.(map[string]any)["user"].(map[string]any)["email"].(string))
	}
	return out
}

func want(t *testing.T, resp *http.Response, code int, msg string) {
	t.Helper()
	if resp.StatusCode != code {
		t.Fatalf("%s: status %d, want %d", msg, resp.StatusCode, code)
	}
}

func TestPlugin(t *testing.T) {
	t.Run("testEverythingIsWiredThroughTheGraph", func(t *testing.T) {
		h := boot(t, Config{})
		g := h.srv.Graph()
		if !slices.ContainsFunc(g.Schema(), func(m schema.Model) bool { return m.Table == TableDevices }) {
			t.Fatal("table missing")
		}
		var routes []string
		for _, rt := range g.Manifest().Routes() {
			if strings.HasPrefix(rt.Name, "polaris."+ID+".") {
				routes = append(routes, rt.Method+" "+rt.Path+" "+string(rt.Auth))
			}
		}
		slices.Sort(routes)
		if strings.Join(routes, "|") != "DELETE /multi-session/{sessionId} bearer|GET /multi-session/last-method public|GET /multi-session/list bearer|POST /multi-session/switch bearer" {
			t.Fatalf("routes %v", routes)
		}
		if g.Plugin(ID) != h.p || len(h.p.Middleware(g)) != 1 {
			t.Fatal("plugin not wired")
		}
	})

	t.Run("testTwoAccountsOnOneDeviceSwitchWithoutSigningInAndRevokeOneAtATime", func(t *testing.T) {
		h := boot(t, Config{})
		ada := h.user("ada@example.com")
		h.user("grace@example.com")

		if m := h.data(h.send(http.MethodGet, "/multi-session/last-method", req{}))["last_method"]; m != nil {
			t.Fatalf("unknown device: %v", m)
		}
		first := h.login("ada@example.com", req{})
		dev := first.Header.Get(Header)
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(dev) {
			t.Fatalf("device %q", dev)
		}
		if !strings.Contains(first.Header.Get("Set-Cookie"), Cookie+"="+dev+"; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax") {
			t.Fatalf("cookie %q", first.Header.Get("Set-Cookie"))
		}
		adaSession := h.data(first)
		if m := h.data(h.send(http.MethodGet, "/multi-session/last-method", req{device: dev}))["last_method"]; m != "pwd" {
			t.Fatalf("last method %v", m)
		}

		forgedID := strings.Repeat("a", 64)
		forged := h.login("grace@example.com", req{device: forgedID})
		if forged.Header.Get(Header) == forgedID {
			t.Fatal("an id the server did not mint is accepted")
		}
		second := h.login("grace@example.com", req{device: dev})
		joined := second.Header.Get(Header)
		if joined == dev {
			t.Fatal("a sign-in that joins a device keeps its id")
		}
		grace := h.data(second)
		graceAccess := grace["access_token"].(string)
		want(t, h.send(http.MethodGet, "/multi-session/list", req{token: graceAccess, device: dev}), 403, "the old id names nothing")
		dev = joined
		refreshed := h.send(http.MethodPost, "/auth/token/refresh", req{body: map[string]any{"refresh_token": grace["refresh_token"]}, device: dev})
		if refreshed.Header.Get(Header) != dev {
			t.Fatal("a refresh keeps the id")
		}

		listed := h.send(http.MethodGet, "/multi-session/list", req{token: graceAccess, device: dev})
		if got := h.emails(listed); strings.Join(got, ",") != "grace@example.com,ada@example.com" {
			t.Fatalf("listed %v", got)
		}
		l := contracttest.JSON(t, listed)["data"].([]any)
		if l[0].(map[string]any)["current"] != true || l[1].(map[string]any)["current"] != false {
			t.Fatalf("current %v", l)
		}
		want(t, h.send(http.MethodGet, "/multi-session/list", req{token: graceAccess}), 403, "no device")
		want(t, h.send(http.MethodGet, "/multi-session/list", req{token: h.data(forged)["access_token"].(string), device: dev}), 403, "a session of another device")
		want(t, h.send(http.MethodGet, "/multi-session/list", req{token: graceAccess, cookie: dev}), 200, "the cookie works as the header")

		adaSid := h.claims(adaSession["access_token"].(string))["sid"].(string)
		want(t, h.send(http.MethodPost, "/multi-session/switch", req{body: map[string]any{"session_id": "nope"}, token: graceAccess, device: dev}), 404, "unknown session")
		want(t, h.send(http.MethodPost, "/multi-session/switch", req{body: map[string]any{}, token: graceAccess, device: dev}), 422, "no session_id")
		switched := h.send(http.MethodPost, "/multi-session/switch", req{body: map[string]any{"session_id": adaSid}, token: graceAccess, device: dev})
		envelope := h.data(switched)
		if switched.StatusCode != 200 || envelope["user"].(map[string]any)["id"] != ada.ID {
			t.Fatalf("switch %d %v", switched.StatusCode, envelope)
		}
		claims := h.claims(envelope["access_token"].(string))
		if amr := claims["amr"].([]any); len(amr) != 1 || amr[0] != "pwd" || claims["sid"] == adaSid {
			t.Fatalf("claims %v", claims)
		}
		want(t, h.send(http.MethodPost, "/auth/token/refresh", req{body: map[string]any{"refresh_token": adaSession["refresh_token"]}}), 401, "the old session ended")
		want(t, h.send(http.MethodGet, "/auth/me", req{token: graceAccess}), 200, "the caller's own session stays")
		if _, err := h.srv.Graph().Repos().RefreshTokens.ActiveInFamily(context.Background(), h.claims(graceAccess)["sid"].(string)); err != nil {
			t.Fatal("the caller's session ended", err)
		}
		if m := h.data(h.send(http.MethodGet, "/multi-session/last-method", req{device: dev}))["last_method"]; m != "pwd" {
			t.Fatal("a switch is a sign-in")
		}

		want(t, h.send(http.MethodDelete, "/multi-session/"+claims["sid"].(string), req{token: graceAccess, device: dev}), 200, "revoke")
		want(t, h.send(http.MethodPost, "/auth/token/refresh", req{body: map[string]any{"refresh_token": envelope["refresh_token"]}}), 401, "ada is signed out")
		if got := h.emails(h.send(http.MethodGet, "/multi-session/list", req{token: graceAccess, device: dev})); strings.Join(got, ",") != "grace@example.com" {
			t.Fatalf("grace stays: %v", got)
		}
		want(t, h.send(http.MethodDelete, "/multi-session/"+claims["sid"].(string), req{token: graceAccess, device: dev}), 404, "once")
	})

	t.Run("testASwitchKeepsMfaAuthTimeAndTheOrganizationOfTheSession", func(t *testing.T) {
		h := boot(t, Config{})
		ctx := context.Background()
		g := h.srv.Graph()
		ada, grace := h.user("ada@example.com"), h.user("grace@example.com")
		org, err := g.Orgs().CreateOrganization(ctx, "Acme", "", ada.ID)
		if err != nil {
			t.Fatal(err)
		}
		authTime := int64(1760000000)
		adaTokens, err := g.Sessions().Issue(ctx, token.SessionPrincipal{UserID: ada.ID, OrganizationID: org.ID, EmailVerified: true, MFA: true, AMR: []string{"pwd", "otp"}, AuthTime: &authTime}, token.ClientContext{})
		if err != nil {
			t.Fatal(err)
		}
		graceTokens, err := g.Sessions().Issue(ctx, token.SessionPrincipal{UserID: grace.ID, AMR: []string{"magic_link"}}, token.ClientContext{})
		if err != nil {
			t.Fatal(err)
		}
		d := h.p.devices
		dev, err := d.record(ctx, mint(), ada.ID, adaTokens.SessionID, []string{"pwd", "otp"})
		if err != nil {
			t.Fatal(err)
		}
		if dev, err = d.record(ctx, dev, grace.ID, graceTokens.SessionID, []string{"magic_link"}); err != nil {
			t.Fatal(err)
		}
		if known, _ := d.known(ctx, dev); !known {
			t.Fatal("device unknown")
		}
		if m, _ := d.lastMethod(ctx, dev); m == nil || *m != "magic_link" {
			t.Fatalf("last method %v", m)
		}
		issued, _, err := d.switchTo(ctx, dev, graceTokens.SessionID, adaTokens.SessionID, token.ClientContext{})
		if err != nil {
			t.Fatal(err)
		}
		claims := h.claims(issued.AccessToken)
		if amr := claims["amr"].([]any); len(amr) != 2 || amr[1] != "otp" || claims["mfa"] != true || claims["auth_time"] != authTime || claims["org"] != org.ID {
			t.Fatalf("claims %v", claims)
		}

		disabled := ada
		disabled.Status = model.UserStatusDisabled
		if err := g.Repos().Users.Update(ctx, ada, disabled); err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.switchTo(ctx, dev, graceTokens.SessionID, claims["sid"].(string), token.ClientContext{}); !errors.Is(err, errSessionNotFound) {
			t.Fatalf("a disabled account is switched to: %v", err)
		}
	})

	t.Run("testAPlantedDeviceIdDoesNotLetItsOwnerIntoTheNextSignIn", func(t *testing.T) {
		h := boot(t, Config{})
		h.user("mallory@example.com")
		h.user("ada@example.com")

		mallory := h.login("mallory@example.com", req{})
		planted := mallory.Header.Get(Header)
		ada := h.login("ada@example.com", req{cookie: planted})
		dev := ada.Header.Get(Header)
		if dev == planted || !strings.Contains(ada.Header.Get("Set-Cookie"), Cookie+"="+dev) {
			t.Fatal("the browser does not get a new id")
		}
		want(t, h.send(http.MethodGet, "/multi-session/list", req{token: h.data(mallory)["access_token"].(string), device: planted}), 403, "the planted id names nothing any more")
		if got := h.emails(h.send(http.MethodGet, "/multi-session/list", req{token: h.data(ada)["access_token"].(string), device: dev})); strings.Join(got, ",") != "ada@example.com,mallory@example.com" {
			t.Fatalf("listed %v", got)
		}
	})

	t.Run("testWithoutTheCookieOnlyTheHeaderCarriesTheDevice", func(t *testing.T) {
		h := boot(t, Config{DisableCookie: true})
		h.user("ada@example.com")
		resp := h.login("ada@example.com", req{})
		if resp.Header.Get(Header) == "" || resp.Header.Get("Set-Cookie") != "" {
			t.Fatalf("headers %v", resp.Header)
		}
		wrong := h.send(http.MethodPost, "/auth/login", req{body: map[string]any{"email": "ada@example.com", "password": "wrong"}})
		if wrong.Header.Get(Header) != "" {
			t.Fatal("no token pair, no device")
		}
	})
}

// Go-only: two concurrent switches into one session cannot both open a session from it.
func TestConcurrentSwitchesMintOnce(t *testing.T) {
	h := boot(t, Config{})
	ctx := context.Background()
	g := h.srv.Graph()
	ada, grace := h.user("ada@example.com"), h.user("grace@example.com")
	adaTokens, _ := g.Sessions().Issue(ctx, token.SessionPrincipal{UserID: ada.ID, AMR: []string{"pwd"}}, token.ClientContext{})
	graceTokens, _ := g.Sessions().Issue(ctx, token.SessionPrincipal{UserID: grace.ID, AMR: []string{"pwd"}}, token.ClientContext{})
	d := h.p.devices
	dev, _ := d.record(ctx, mint(), ada.ID, adaTokens.SessionID, nil)
	dev, _ = d.record(ctx, dev, grace.ID, graceTokens.SessionID, nil)

	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := d.switchTo(ctx, dev, graceTokens.SessionID, adaTokens.SessionID, token.ClientContext{}); err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d switches won", won)
	}
}
