package sentinel_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/sentinel"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

// The sentinel needs the audit and admin plugins. In enforce mode with a captcha verifier
// (sentinel.Turnstile(secret) in production) a risky sign-up is challenged before core sees it.
func Example() {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(slices.Concat(schema.Core(), audit.Models(), admin.Models(), sentinel.Models())...),
		Plugins: []polaris.Plugin{audit.New(audit.Config{}), admin.New(admin.Config{}), sentinel.New(sentinel.Config{
			Mode:    sentinel.Enforce,
			Captcha: goodToken{}, // sentinel.Turnstile(os.Getenv("TURNSTILE_SECRET"))
		})},
	})
	if err != nil {
		log.Fatal(err)
	}
	if _, err := p.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	// A sign-up with a disposable mailbox scores 60: challenged.
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader(`{"email":"ada@mailinator.com","password":"correct horse battery staple"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)
	fmt.Println(rec.Code, rec.Header().Get("Content-Type"))
	// Output: 403 application/problem+json
}
