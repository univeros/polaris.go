package httpapi_test

import (
	"net/http"
	"slices"
	"testing"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/polaristest"
)

const authJWKSPath = "/auth/.well-known/jwks.json"

func TestJwksEndpoint(t *testing.T) {
	const class = "JwksEndpointTest"

	t.Run("testServesTheJwkSetOverHttp", func(t *testing.T) {
		a := authNew(t, class, "testServesTheJwkSetOverHttp")
		resp := a.c.Get(authJWKSPath)
		authStatusIs(t, resp, http.StatusOK)
		keys, _ := contracttest.JSON(t, resp)["keys"].([]any)
		if len(keys) == 0 || keys[0].(map[string]any)["kty"] != "RSA" {
			t.Fatalf("keys: %v", keys)
		}
	})

	t.Run("testRotationOverlapPublishesBothKeys", func(t *testing.T) {
		// Upstream reboots with AUTH_JWT_PREVIOUS_PUBLIC_KEY (the same test key) and
		// AUTH_JWT_PREVIOUS_KID; polaristest has no secrets option, so the server is built here.
		db := polaristest.New(t).DB
		private, public := contracttest.TestRSAKeyPEM()
		auth := config.Defaults()
		auth.Issuer = contracttest.Issuer
		p, err := polaris.New(polaris.Config{
			Secrets: config.Secrets{
				AppKey: contracttest.AppKey, JWTPrivateKey: private, JWTPublicKey: public,
				JWTPreviousPublicKey: public, JWTPreviousKeyID: contracttest.PreviousKID,
			},
			Auth: auth,
			DB:   db,
		})
		if err != nil {
			t.Fatal(err)
		}
		fx := contracttest.For(t, contracttest.UpstreamFixtures(t, "core"), authPHPNS+class, "testRotationOverlapPublishesBothKeys")
		keys, _ := contracttest.JSON(t, contracttest.NewClient(t, p.Handler(), fx).Get(authJWKSPath))["keys"].([]any)
		var kids []string
		for _, k := range keys {
			kids = append(kids, k.(map[string]any)["kid"].(string))
		}
		if len(kids) != 2 || !slices.Contains(kids, contracttest.PreviousKID) {
			t.Fatalf("kids: %v", kids)
		}
	})

	t.Run("testUnknownRouteIsNotFound", func(t *testing.T) {
		a := authNew(t, class, "testUnknownRouteIsNotFound")
		authStatusIs(t, a.c.Get("/auth/does-not-exist"), http.StatusNotFound)
	})
}

func TestAuthMiddleware(t *testing.T) {
	const class = "AuthMiddlewareTest"
	run := func(name string, f func(t *testing.T, a *authCase)) {
		t.Run(name, func(t *testing.T) { f(t, authNew(t, class, name)) })
	}
	gated := func(t *testing.T, resp *http.Response) {
		t.Helper()
		authStatusIs(t, resp, http.StatusUnauthorized)
		if h := resp.Header.Get("WWW-Authenticate"); h != "Bearer" {
			t.Fatalf("%s %s: WWW-Authenticate %q", resp.Request.Method, resp.Request.URL.Path, h)
		}
	}

	run("testAPublicPathSkipsAuthentication", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Get(authJWKSPath), http.StatusOK)
	})

	run("testAProtectedPathWithoutATokenIsRejectedByTheMiddleware", func(t *testing.T, a *authCase) {
		resp := a.c.Get("/auth/me")
		gated(t, resp)
		if e := contracttest.JSON(t, resp)["error"]; e != "unauthorized" {
			t.Fatalf("error: %v", e)
		}
	})

	run("testAProtectedPathWithAnInvalidBearerIsUnauthorized", func(t *testing.T, a *authCase) {
		authStatusIs(t, a.c.Get("/auth/me", contracttest.Bearer("not-a-real-jwt")), http.StatusUnauthorized)
	})

	run("testEveryProtectedRouteIsRejectedByTheMiddlewareWithoutAToken", func(t *testing.T, a *authCase) {
		gated(t, a.c.Get("/auth/me"))
		gated(t, a.c.Get("/auth/sessions"))
		gated(t, a.c.Post("/auth/logout", nil))
		gated(t, a.c.Post("/auth/logout-all", nil))
		gated(t, a.c.Post("/auth/password/change", nil))
		gated(t, a.c.Delete("/auth/sessions/abc"))
	})

	run("testAProtectedPathWithAValidBearerReachesTheDomain", func(t *testing.T, a *authCase) {
		a.register(authEmail, authPassword)
		access, _ := a.login(authEmail, authPassword)
		resp := a.c.Get("/auth/me", contracttest.Bearer(access))
		authStatusIs(t, resp, http.StatusOK)
		if e := contracttest.JSON(t, resp)["data"].(map[string]any)["email"]; e != authEmail {
			t.Fatalf("email: %v", e)
		}
	})

	run("testLoginIsRateLimited", func(t *testing.T, a *authCase) {
		wrong := map[string]any{"email": authEmail, "password": "wrong"}
		for i := range 10 {
			if resp := a.c.Post("/auth/login", wrong); resp.StatusCode == http.StatusTooManyRequests {
				t.Fatalf("request %d should be within budget", i)
			}
		}
		blocked := a.c.Post("/auth/login", wrong)
		authStatusIs(t, blocked, http.StatusTooManyRequests)
		if blocked.Header.Get("X-RateLimit-Limit") != "10" || blocked.Header.Get("Retry-After") == "" {
			t.Fatalf("rate-limit headers: %v", blocked.Header)
		}
	})
}

func TestDenylistEndpoints(t *testing.T) {
	const class = "DenylistEndpointsTest"
	const email, password = "victim@example.com", "Sup3r-Secret-Passw0rd"

	t.Run("testLogoutEverywhereKillsTheLiveAccessTokenInstantly", func(t *testing.T) {
		a := authNew(t, class, "testLogoutEverywhereKillsTheLiveAccessTokenInstantly",
			polaristest.WithAuth(func(c *config.Auth) { c.AccessToken.Denylist = true }))
		a.register(email, password)
		access, _ := a.login(email, password)
		authStatusIs(t, a.c.Get("/auth/me", contracttest.Bearer(access)), http.StatusOK)
		authStatusIs(t, a.c.Post("/auth/logout-all", nil, contracttest.Bearer(access)), http.StatusOK)
		resp := a.c.Get("/auth/me", contracttest.Bearer(access))
		authStatusIs(t, resp, http.StatusUnauthorized)
		if e := contracttest.JSON(t, resp)["error"]; e != "session_ended" {
			t.Fatalf("error: %v", e)
		}
	})

	t.Run("testWithoutTheFlagTheStatelessDefaultIsUnchanged", func(t *testing.T) {
		a := authNew(t, class, "testWithoutTheFlagTheStatelessDefaultIsUnchanged")
		a.register(email, password)
		access, _ := a.login(email, password)
		authStatusIs(t, a.c.Post("/auth/logout-all", nil, contracttest.Bearer(access)), http.StatusOK)
		authStatusIs(t, a.c.Get("/auth/me", contracttest.Bearer(access)), http.StatusOK)
	})
}
