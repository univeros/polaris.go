package apikeys_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/plugins/apikeys"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

// API keys authenticate every Polaris route and every host route behind Protect. Users mint keys
// with POST /api-keys; here the key service mints one directly.
func Example() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	db := memstore.New(append(append(schema.Core(), audit.Models()...), apikeys.Models()...)...) // sqlstore.Open(...) in production

	keys := apikeys.New(apikeys.Config{})
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth,
		DB:      db,
		Plugins: []polaris.Plugin{audit.New(audit.Config{}), keys},
	})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/auth/", p.Handler())
	mux.Handle("/api/", p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		fmt.Fprintf(w, "%s %s key=%v delegated=%v %v", who.UserID, who.Kind, who.KeyID != "", who.Delegated, who.Permissions)
	})))

	ctx := context.Background()
	verified := time.Now()
	_ = p.Graph().Repos().Users.Insert(ctx, model.User{ID: "user-1", Email: "ada@example.com", EmailVerifiedAt: &verified, CreatedAt: verified, UpdatedAt: verified})
	issued, err := keys.Keys().Create(ctx, apikeys.CreateParams{
		OwnerType: apikeys.OwnerUser, OwnerID: "user-1", CreatedBy: "user-1", Name: "CI deploy",
		Permissions: []string{}, // a subset of what the owner holds in the key's organization
	})
	if err != nil {
		log.Fatal(err)
	}

	r := httptest.NewRequest(http.MethodGet, "/api/invoices", nil)
	r.Header.Set("Authorization", "Bearer "+issued.Secret) // or x-api-key: pk_live_…
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	fmt.Println(w.Code, w.Body.String())
	// Output: 200 user-1 api_key key=true delegated=true []
}
