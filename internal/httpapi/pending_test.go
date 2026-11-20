package httpapi

import (
	"testing"

	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/wiring"
)

// TestNoPendingRoutes fails while a core route has no Go endpoint (it would answer 501).
func TestNoPendingRoutes(t *testing.T) {
	auth := config.Defaults()
	auth.Issuer = contracttest.Issuer
	private, public := contracttest.TestRSAKeyPEM()
	g, err := wiring.New(wiring.Config{
		Secrets: config.Secrets{AppKey: contracttest.AppKey, JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      memstore.New(schema.Core()...),
	})
	if err != nil {
		t.Fatal(err)
	}
	implemented := map[string]bool{}
	for _, area := range []func(*wiring.Graph) map[string]endpoint.Endpoint{authEndpoints, mfaEndpoints, orgEndpoints} {
		for name := range area(g) {
			implemented[name] = true
		}
	}
	for _, r := range g.Manifest().Routes() {
		if r.Plugin == "" && !implemented[r.Name] {
			t.Errorf("core route %s (%s) has no endpoint", r.Name, r.Pattern())
		}
	}
}
