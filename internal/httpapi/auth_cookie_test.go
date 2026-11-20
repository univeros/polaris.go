package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/pipeline"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
)

// authCookieCase is CookieModeTest's harness (CookieRequests): cookie token delivery on, requests
// over https://localhost. Upstream recorded no fixture for it, so responses are only asserted.
type authCookieCase struct {
	t   *testing.T
	srv *polaristest.Server
	c   *contracttest.Client
}

const authCookieEmail = "cookie@example.com"

func authCookieNew(t *testing.T) *authCookieCase {
	srv := polaristest.New(t, polaristest.WithAuth(func(c *config.Auth) { c.Flows.TokenDelivery = config.DeliveryCookie }))
	return &authCookieCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil)}
}

// authCookieReq describes one CookieRequests::send call. A nil headers sends the CSRF header a
// cookie-mode client sends; an empty map sends none.
type authCookieReq struct {
	body    map[string]any
	cookies map[string]string
	headers map[string]string
	scheme  string
	access  string
}

func (a *authCookieCase) send(path string, r authCookieReq) *http.Response {
	a.t.Helper()
	if r.body == nil {
		r.body = map[string]any{}
	}
	if r.scheme == "" {
		r.scheme = "https"
	}
	if r.headers == nil {
		r.headers = map[string]string{pipeline.CSRFHeader: "1"}
	}
	raw, err := json.Marshal(r.body)
	if err != nil {
		a.t.Fatal(err)
	}
	req := a.c.NewRequest(http.MethodPost, r.scheme+"://localhost"+path, raw)
	req.Header.Set("Content-Type", "application/json")
	for name, value := range r.cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	for name, value := range r.headers {
		req.Header.Set(name, value)
	}
	if r.access != "" {
		req.Header.Set("Authorization", "Bearer "+r.access)
	}
	return a.c.Do(req)
}

func (a *authCookieCase) register() {
	a.t.Helper()
	a.c.Post("/auth/register", map[string]any{"email": authCookieEmail, "password": authPassword})
	regs := authEventsOf[event.UserRegistered](a.srv)
	a.c.Post("/auth/email/verify", map[string]any{"token": regs[len(regs)-1].VerificationToken})
}

func (a *authCookieCase) login() *http.Response {
	return a.send("/auth/login", authCookieReq{body: map[string]any{"email": authCookieEmail, "password": authPassword}})
}

func (a *authCookieCase) registerAndLogin() *http.Response {
	a.register()
	return a.login()
}

func (a *authCookieCase) sessions() int64 {
	a.t.Helper()
	n, err := a.srv.Graph().Repos().RefreshTokens.Count(context.Background(), store.Criteria{})
	if err != nil {
		a.t.Fatal(err)
	}
	return n
}

func authRefreshCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == pipeline.RefreshCookie {
			return c
		}
	}
	return nil
}

// authCookieSet asserts the refresh cookie of cookie-mode spec §2.4 was set and returns its value.
func authCookieSet(t *testing.T, resp *http.Response) string {
	t.Helper()
	c := authRefreshCookie(resp)
	if c == nil || c.Value == "" {
		t.Fatalf("%s: the refresh cookie is not set", resp.Request.URL.Path)
	}
	if c.Path != "/auth/token/refresh" || c.MaxAge < 2592000-5 || c.MaxAge > 2592000+5 ||
		!c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Domain != "" {
		t.Fatalf("refresh cookie attributes: %q", c.Raw)
	}
	return c.Value
}

func authCookieCleared(t *testing.T, resp *http.Response) {
	t.Helper()
	c := authRefreshCookie(resp)
	if c == nil || c.MaxAge >= 0 || (c.Value != "" && c.Value != "deleted") {
		t.Fatalf("%s: the refresh cookie is not cleared: %v", resp.Request.URL.Path, c)
	}
}

func authNoCookie(t *testing.T, resp *http.Response) {
	t.Helper()
	if c := authRefreshCookie(resp); c != nil {
		t.Fatalf("%s: unexpected refresh cookie %q", resp.Request.URL.Path, c.Raw)
	}
}

func authNoRefreshInBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if strings.Contains(string(contracttest.Decode[json.RawMessage](t, resp)), `"refresh_token"`) {
		t.Fatal("refresh_token in the body")
	}
}

func authTOTP(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	code, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestCookieMode(t *testing.T) {
	refreshWith := func(a *authCookieCase, cookie string) *http.Response {
		return a.send("/auth/token/refresh", authCookieReq{cookies: map[string]string{pipeline.RefreshCookie: cookie}})
	}

	t.Run("testLoginMovesTheRefreshTokenToTheCookie", func(t *testing.T) {
		a := authCookieNew(t)
		a.register()
		resp := a.login()
		authStatusIs(t, resp, http.StatusOK)
		data := contracttest.JSON(t, resp)["data"].(map[string]any)
		if _, ok := data["refresh_token"]; ok || data["access_token"] == "" || data["token_type"] != "Bearer" || data["expires_in"] == nil {
			t.Fatalf("login body: %v", data)
		}
		authCookieSet(t, resp)
		authStatusIs(t, a.c.Get("/auth/me", contracttest.Bearer(data["access_token"].(string))), http.StatusOK)
	})

	t.Run("testTheMfaTicketSetsNoCookieAndTheVerifySetsIt", func(t *testing.T) {
		a := authCookieNew(t)
		access, _ := authPair(t, a.registerAndLogin())
		enrollResp := a.c.Post("/auth/mfa/totp/enroll", nil, contracttest.Bearer(access))
		if enrollResp.StatusCode == http.StatusNotImplemented {
			t.Skip("the MFA routes are not ported yet")
		}
		enroll := contracttest.JSON(t, enrollResp)["data"].(map[string]any)
		secret := enroll["secret"].(string)
		a.c.Post("/auth/mfa/totp/confirm", map[string]any{"factor_id": enroll["factor_id"], "code": authTOTP(t, secret, time.Now())}, contracttest.Bearer(access))
		ticket := a.login()
		authStatusIs(t, ticket, http.StatusOK)
		challenge := contracttest.JSON(t, ticket)["data"].(map[string]any)
		if challenge["mfa_required"] != true {
			t.Fatalf("login: %v", challenge)
		}
		authNoCookie(t, ticket)
		factor := challenge["factors"].([]any)[0].(map[string]any)
		verified := a.send("/auth/mfa/verify", authCookieReq{
			body:   map[string]any{"factor_id": factor["id"], "code": authTOTP(t, secret, time.Now().Add(30*time.Second))},
			access: challenge["mfa_token"].(string),
		})
		authStatusIs(t, verified, http.StatusOK)
		authNoRefreshInBody(t, verified)
		authCookieSet(t, verified)
	})

	t.Run("testRefreshWithTheCookieRotatesIt", func(t *testing.T) {
		a := authCookieNew(t)
		first := authCookieSet(t, a.registerAndLogin())
		refreshed := refreshWith(a, first)
		authStatusIs(t, refreshed, http.StatusOK)
		authNoRefreshInBody(t, refreshed)
		if access, _ := authPair(t, refreshed); access == "" {
			t.Fatal("no access token")
		}
		second := authCookieSet(t, refreshed)
		if second == first {
			t.Fatal("cookie not rotated")
		}
		authStatusIs(t, refreshWith(a, second), http.StatusOK)
	})

	failingGuards := map[string]map[string]string{
		"no header":                       {},
		"a foreign Origin":                {pipeline.CSRFHeader: "1", "Origin": "https://evil.example"},
		"Origin: null":                    {pipeline.CSRFHeader: "1", "Origin": "null"},
		"a cross-site fetch":              {pipeline.CSRFHeader: "1", "Sec-Fetch-Site": "cross-site"},
		"the header with the wrong value": {pipeline.CSRFHeader: "true"},
	}
	for name, headers := range failingGuards {
		t.Run("testARefreshThatFailsTheGuardIsRefusedAndConsumesNothing/"+name, func(t *testing.T) {
			a := authCookieNew(t)
			cookie := authCookieSet(t, a.registerAndLogin())
			refused := a.send("/auth/token/refresh", authCookieReq{cookies: map[string]string{pipeline.RefreshCookie: cookie}, headers: headers})
			authStatusIs(t, refused, http.StatusForbidden)
			if body := contracttest.JSON(t, refused); len(body) != 2 || body["error"] != "csrf_failed" || body["message"] != "The request did not pass the CSRF check." {
				t.Fatalf("body: %v", body)
			}
			authNoCookie(t, refused)
			authStatusIs(t, refreshWith(a, cookie), http.StatusOK)
		})
	}

	t.Run("testTheOwnOriginAndASameOriginFetchPassTheGuard", func(t *testing.T) {
		a := authCookieNew(t)
		cookie := authCookieSet(t, a.registerAndLogin())
		origin := a.send("/auth/token/refresh", authCookieReq{cookies: map[string]string{pipeline.RefreshCookie: cookie}, headers: map[string]string{pipeline.CSRFHeader: "1", "Origin": "https://localhost"}})
		authStatusIs(t, origin, http.StatusOK)
		fetch := a.send("/auth/token/refresh", authCookieReq{cookies: map[string]string{pipeline.RefreshCookie: authCookieSet(t, origin)}, headers: map[string]string{pipeline.CSRFHeader: "1", "Sec-Fetch-Site": "same-origin"}})
		authStatusIs(t, fetch, http.StatusOK)
	})

	t.Run("testLoginCsrfIsRefusedBeforeASessionExists", func(t *testing.T) {
		a := authCookieNew(t)
		a.register()
		before := a.sessions()
		refused := a.send("/auth/login", authCookieReq{
			body:    map[string]any{"email": authCookieEmail, "password": authPassword},
			headers: map[string]string{"Origin": "https://evil.example", "Content-Type": "application/x-www-form-urlencoded"},
		})
		authStatusIs(t, refused, http.StatusForbidden)
		if e := contracttest.JSON(t, refused)["error"]; e != "csrf_failed" {
			t.Fatalf("error: %v", e)
		}
		authNoCookie(t, refused)
		if after := a.sessions(); after != before {
			t.Fatalf("a session was created: %d -> %d", before, after)
		}
	})

	t.Run("testARefreshTokenPlantedThroughTheBodyOrTheQueryIsRefusedWithoutTheGuard", func(t *testing.T) {
		a := authCookieNew(t)
		token := authCookieSet(t, a.registerAndLogin())
		evil := map[string]string{"Origin": "https://evil.example"}
		form := a.send("/auth/token/refresh", authCookieReq{body: map[string]any{"refresh_token": token}, headers: evil})
		query := a.send("/auth/token/refresh?refresh_token="+token, authCookieReq{headers: evil})
		authStatusIs(t, form, http.StatusForbidden)
		authStatusIs(t, query, http.StatusForbidden)
		authStatusIs(t, refreshWith(a, token), http.StatusOK)
	})

	t.Run("testABodyTokenStillRefreshesAndItsSuccessorGoesToTheCookie", func(t *testing.T) {
		a := authCookieNew(t)
		token := authCookieSet(t, a.registerAndLogin())
		refreshed := a.send("/auth/token/refresh", authCookieReq{body: map[string]any{"refresh_token": token}})
		authStatusIs(t, refreshed, http.StatusOK)
		authNoRefreshInBody(t, refreshed)
		if authCookieSet(t, refreshed) == token {
			t.Fatal("cookie not rotated")
		}
	})

	t.Run("testAnInvalidBodyTokenLeavesAValidCookieAlone", func(t *testing.T) {
		a := authCookieNew(t)
		cookie := authCookieSet(t, a.registerAndLogin())
		failed := a.send("/auth/token/refresh", authCookieReq{body: map[string]any{"refresh_token": "not-a-token"}, cookies: map[string]string{pipeline.RefreshCookie: cookie}})
		authStatusIs(t, failed, http.StatusUnauthorized)
		authNoCookie(t, failed)
		authStatusIs(t, refreshWith(a, cookie), http.StatusOK)
	})

	t.Run("testReplayingARotatedCookieRevokesTheFamilyAndClearsIt", func(t *testing.T) {
		a := authCookieNew(t)
		first := authCookieSet(t, a.registerAndLogin())
		second := authCookieSet(t, refreshWith(a, first))
		replay := refreshWith(a, first)
		authStatusIs(t, replay, http.StatusUnauthorized)
		authCookieCleared(t, replay)
		authStatusIs(t, refreshWith(a, second), http.StatusUnauthorized)
	})

	t.Run("testLogoutAndLogoutAllClearTheCookie", func(t *testing.T) {
		a := authCookieNew(t)
		access, _ := authPair(t, a.registerAndLogin())
		logout := a.send("/auth/logout", authCookieReq{access: access})
		authStatusIs(t, logout, http.StatusOK)
		authCookieCleared(t, logout)
		again, _ := authPair(t, a.login())
		all := a.send("/auth/logout-all", authCookieReq{access: again})
		authStatusIs(t, all, http.StatusOK)
		authCookieCleared(t, all)
	})

	t.Run("testAFailedLogoutLeavesTheCookie", func(t *testing.T) {
		a := authCookieNew(t)
		refused := a.send("/auth/logout", authCookieReq{access: "not-a-jwt"})
		authStatusIs(t, refused, http.StatusUnauthorized)
		authNoCookie(t, refused)
	})

	plaintext := map[string]struct {
		path string
		body map[string]any
	}{
		"login":   {"/auth/login", map[string]any{"email": authCookieEmail, "password": authPassword}},
		"refresh": {"/auth/token/refresh", map[string]any{"refresh_token": "x"}},
	}
	for name, p := range plaintext {
		t.Run("testPlaintextIsRefusedBeforeTheHandler/"+name, func(t *testing.T) {
			a := authCookieNew(t)
			a.register()
			before := a.sessions()
			refused := a.send(p.path, authCookieReq{body: p.body, scheme: "http"})
			authStatusIs(t, refused, http.StatusForbidden)
			if body := contracttest.JSON(t, refused); len(body) != 2 || body["error"] != "insecure_transport" || body["message"] != "Sessions are only issued over HTTPS." {
				t.Fatalf("body: %v", body)
			}
			authNoCookie(t, refused)
			if after := a.sessions(); after != before {
				t.Fatalf("a session was created: %d -> %d", before, after)
			}
		})
	}

	t.Run("testRoutesWithoutTheSessionKeyAreUntouched", func(t *testing.T) {
		a := authCookieNew(t)
		resp := a.c.Post("/auth/register", map[string]any{"email": "plain@example.com", "password": authPassword})
		authStatusIs(t, resp, http.StatusAccepted)
		authNoCookie(t, resp)
	})
}
