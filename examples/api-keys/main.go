// Command api-keys adds user and organization API keys to Polaris: a key (`Authorization: Bearer
// pk_live_…` or `x-api-key`) authenticates every Polaris route and every host route behind Protect as
// its owner, limited to the key's permissions.
//
// Same environment as examples/minimal.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/plugins/apikeys"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/sqlstore"
)

func main() {
	ctx := context.Background()
	db, err := sqlstore.Open(ctx, store.SQLite, "file:polaris.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := polaris.FromEnv(db, audit.New(audit.Config{}), apikeys.New(apikeys.Config{}))
	if err != nil {
		log.Fatal(err)
	}
	p, err := polaris.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := p.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // Polaris routes, including POST /api-keys to mint a key
	// A host route needing a permission: an API key passes only if it (and its owner) holds it.
	mux.Handle("GET /api/invoices", p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user": who.UserID, "api_key": who.Kind == polaris.KindAPIKey, "key_id": who.KeyID, "permissions": who.Permissions,
		})
	}), "org.read"))
	srv := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
