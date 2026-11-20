package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/security"
)

// benchServer boots a server whose login and refresh budgets never run out (the test rate clock
// is frozen) and a verified account, through the whole HTTP pipeline on SQLite.
func benchServer(b *testing.B, opts ...polaristest.Option) (*polaristest.Server, *contracttest.Client) {
	b.Helper()
	opts = append(opts, polaristest.WithAuth(func(a *config.Auth) {
		a.RateLimits.Login.Limit = 1 << 30
		a.RateLimits.TokenRefresh.Limit = 1 << 30
		a.RateLimits.Register.Limit = 1 << 30
	}))
	srv := polaristest.New(b, opts...)
	c := contracttest.NewClient(b, srv.Handler(), nil)
	c.Post("/auth/register", map[string]any{"email": authEmail, "password": authPassword})
	var token string
	for _, e := range srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			token = r.VerificationToken
		}
	}
	if resp := c.Post("/auth/email/verify", map[string]any{"token": token}); resp.StatusCode != http.StatusOK {
		b.Fatalf("verify: %d", resp.StatusCode)
	}
	return srv, c
}

// BenchmarkLogin is POST /auth/login end to end: rate limit, user lookup, Argon2id verify,
// session row, refresh secret, RS256 access token. "production" is security.Argon2id{} (PHP's
// password_hash defaults: 64 MiB, 4 passes, 1 lane); "cheap" is the test suite's 1 MiB, 1 pass.
func BenchmarkLogin(b *testing.B) {
	for _, h := range []struct {
		name   string
		hasher security.PasswordHasher
	}{
		{"argon2=production", security.Argon2id{}},
		{"argon2=cheap", security.Argon2id{Memory: 1024, Time: 1, Threads: 1}},
	} {
		b.Run(h.name, func(b *testing.B) {
			_, c := benchServer(b, polaristest.WithHasher(h.hasher))
			body := map[string]any{"email": authEmail, "password": authPassword}
			b.ReportAllocs()
			for b.Loop() {
				if resp := c.Post("/auth/login", body); resp.StatusCode != http.StatusOK {
					b.Fatalf("login: %d", resp.StatusCode)
				}
			}
		})
	}
}

// BenchmarkRefresh is POST /auth/token/refresh end to end: each iteration presents the refresh
// token the previous one received (single-use rotation: the old row consumed, a new one written,
// a new access token signed).
func BenchmarkRefresh(b *testing.B) {
	_, c := benchServer(b)
	_, refresh := authPair(b, c.Post("/auth/login", map[string]any{"email": authEmail, "password": authPassword}))
	b.ReportAllocs()
	for b.Loop() {
		resp := c.Post("/auth/token/refresh", map[string]any{"refresh_token": refresh})
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("refresh: %d", resp.StatusCode)
		}
		_, refresh = authPair(b, resp)
	}
}
