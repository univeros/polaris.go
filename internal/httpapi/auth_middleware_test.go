package httpapi_test

import (
	"net/http"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/token"
)

const authJWKSPath = "/auth/.well-known/jwks.json"

func TestJwksEndpoint(t *testing.T) {
	const class = "JwksEndpointTest"

	t.Run("testServesTheJwkSetOverHttp", func(t *testing.T) {
		a := authNew(t, class, "testServesTheJwkSetOverHttp")
		resp := a.c.Get(authJWKSPath)
		authStatusIs(t, resp, http.StatusOK)
		keys, _ := contracttest.JSON(t, resp)["keys"].([]any)
		// The key under its kid and under its legacy kid (decision 73).
		if len(keys) != 2 || keys[0].(map[string]any)["kty"] != "RSA" {
			t.Fatalf("keys: %v", keys)
		}
	})

	t.Run("testRotationOverlapPublishesBothKeys", func(t *testing.T) {
		// The recorded test reboots with AUTH_JWT_PREVIOUS_PUBLIC_KEY (the same test key) and
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
		fx := contracttest.For(t, contracttest.Fixtures(t, "core"), coreSuite+class, "testRotationOverlapPublishesBothKeys")
		keys, _ := contracttest.JSON(t, contracttest.NewClient(t, p.Handler(), fx).Get(authJWKSPath))["keys"].([]any)
		var kids []string
		for _, k := range keys {
			kids = append(kids, k.(map[string]any)["kid"].(string))
		}
		// The current key, the retiring one, then the current key under its legacy kid (decision
		// 73); the retiring key's explicit kid has no alias.
		if len(kids) != 3 || kids[1] != contracttest.PreviousKID {
			t.Fatalf("kids: %v", kids)
		}
	})

	t.Run("testUnknownRouteIsNotFound", func(t *testing.T) {
		a := authNew(t, class, "testUnknownRouteIsNotFound")
		authStatusIs(t, a.c.Get("/auth/does-not-exist"), http.StatusNotFound)
	})
}

// Decision 73: the default kid is the RFC 7638 thumbprint of the key. A release before it named
// the key by the SHA-256 of its PEM text; the JWKS publishes the key under both kids (same key
// material) and the server accepts tokens naming the old one, so nothing issued or cached before
// the upgrade stops verifying. New tokens carry the thumbprint. An explicit kid has no alias.
func TestTheLegacyDefaultKidKeepsVerifying(t *testing.T) {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = contracttest.Issuer
	boot := func(kid string) (*polaris.Polaris, config.Secrets) {
		secrets := config.Secrets{AppKey: contracttest.AppKey, JWTPrivateKey: private, JWTPublicKey: public, JWTKeyID: kid}
		p, err := polaris.New(polaris.Config{Secrets: secrets, Auth: auth, DB: polaristest.New(t).DB})
		if err != nil {
			t.Fatal(err)
		}
		return p, secrets
	}

	p, secrets := boot("")
	want, _ := token.Thumbprint(token.RS256, public)
	if secrets.KeyID() != want || secrets.LegacyKeyID() == "" {
		t.Fatalf("kid %q, legacy %q", secrets.KeyID(), secrets.LegacyKeyID())
	}
	keys := p.Graph().JWKS().Keys
	if len(keys) != 2 || keys[0].Kid != want || keys[1].Kid != secrets.LegacyKeyID() || keys[0].N != keys[1].N || keys[0].E != keys[1].E {
		t.Fatalf("JWKS %+v", keys)
	}

	earlier, err := token.New(token.Config{PrivateKey: private, PublicKey: public, KeyID: secrets.LegacyKeyID(), Issuer: contracttest.Issuer, TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	old, err := earlier.Mint("at+jwt", token.Claims{}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Graph().Tokens().VerifyJWT(old, 0); err != nil {
		t.Fatalf("a token naming the legacy kid: %v", err)
	}
	minted, err := p.Graph().Tokens().Mint("at+jwt", token.Claims{}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if tok, err := p.Graph().Tokens().VerifyJWT(minted, 0); err != nil || tok.Header("kid") != want {
		t.Fatalf("a new token names %v (%v), want the thumbprint", tok, err)
	}

	p, _ = boot("key-2026")
	if keys := p.Graph().JWKS().Keys; len(keys) != 1 || keys[0].Kid != "key-2026" {
		t.Fatalf("explicit kid JWKS %+v", keys)
	}
	if _, err := p.Graph().Tokens().VerifyJWT(old, 0); err == nil {
		t.Fatal("an explicit kid accepted the legacy default kid")
	}
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
