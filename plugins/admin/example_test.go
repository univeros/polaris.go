package admin_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/plugins/admin"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

// An operator API key for a dashboard: created once from code, then sent as a bearer to /admin.
func Example() {
	ctx := context.Background()
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(slices.Concat(schema.Core(), audit.Models(), admin.Models())...),
		Plugins: []polaris.Plugin{audit.New(audit.Config{}), admin.New(admin.Config{})},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	_, secret, err := admin.Of(p.Graph()).Keys().Create(ctx, admin.Key{Name: "dashboard", Role: admin.RoleViewer})
	if err != nil {
		fmt.Println(err)
		return
	}
	req := httptest.NewRequest(http.MethodGet, "/admin/stats", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)
	fmt.Println(rec.Code, strings.HasPrefix(secret, admin.KeyPrefix))

	req = httptest.NewRequest(http.MethodGet, "/admin/keys", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec = httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)
	fmt.Println(rec.Code, "a viewer cannot manage keys")
	// Output:
	// 200 true
	// 403 a viewer cannot manage keys
}
