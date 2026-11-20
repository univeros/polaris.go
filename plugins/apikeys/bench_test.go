package apikeys_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/plugins/apikeys"
	"github.com/univeros/polaris-go/polaristest"
)

// BenchmarkProtect is a host route behind Protect, authenticated by a session access token (JWT:
// signature and claims, denylist) and by an API key (the bearer resolver: hashed-secret lookup,
// owner and expiry checks, delegated principal), on SQLite.
func BenchmarkProtect(b *testing.B) {
	keys := apikeys.New(apikeys.Config{})
	srv := polaristest.New(b, polaristest.WithPlugins(keys), polaristest.WithAuth(func(a *config.Auth) {
		a.RateLimits.Login.Limit = 1 << 30
	}))
	c := contracttest.NewClient(b, srv.Handler(), nil)
	const email, password = "ada@example.com", "correct horse battery staple"
	c.Post("/auth/register", map[string]any{"email": email, "password": password})
	for _, e := range srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			c.Post("/auth/email/verify", map[string]any{"token": r.VerificationToken})
		}
	}
	login, _ := contracttest.JSON(b, c.Post("/auth/login", map[string]any{"email": email, "password": password}))["data"].(map[string]any)
	jwt, _ := login["access_token"].(string)
	ctx := context.Background()
	user, err := srv.Graph().Repos().Users.ByEmail(ctx, email)
	if err != nil {
		b.Fatal(err)
	}
	issued, err := keys.Keys().Create(ctx, apikeys.CreateParams{
		OwnerType: apikeys.OwnerUser, OwnerID: user.ID, CreatedBy: user.ID, Name: "bench", Permissions: []string{},
	})
	if err != nil {
		b.Fatal(err)
	}

	host := srv.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	for _, cred := range []struct{ name, bearer string }{{"jwt", jwt}, {"api_key", issued.Secret}} {
		b.Run(cred.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				r := httptest.NewRequest(http.MethodGet, "/api/invoices", nil)
				r.Header.Set("Authorization", "Bearer "+cred.bearer)
				w := httptest.NewRecorder()
				host.ServeHTTP(w, r)
				if w.Code != http.StatusOK {
					b.Fatalf("%s: %d %s", cred.name, w.Code, w.Body)
				}
			}
		})
	}
}
