// Command minimal is the smallest complete Polaris host: core authentication (register, verify,
// login, refresh, MFA, organizations, RBAC) on SQLite, plus one host route protected by Polaris.
//
// Environment: APP_KEY (≥ 32 bytes), AUTH_JWT_PRIVATE_KEY and AUTH_JWT_PUBLIC_KEY (PEM), AUTH_ISSUER.
//
//	export APP_KEY=$(openssl rand -base64 32)
//	openssl genrsa -out jwt.key 2048 && openssl rsa -in jwt.key -pubout -out jwt.pub
//	export AUTH_JWT_PRIVATE_KEY="$(cat jwt.key)" AUTH_JWT_PUBLIC_KEY="$(cat jwt.pub)" AUTH_ISSUER=http://localhost:8080
//	go run ./examples/minimal
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/sqlstore"
)

func main() {
	ctx := context.Background()
	db, err := sqlstore.Open(ctx, store.SQLite, "file:polaris.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	cfg, err := polaris.FromEnv(db)
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
	mux.Handle("/", p.Handler()) // every Polaris route: /auth/register, /auth/login, /orgs, …
	mux.Handle("GET /hello", p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello %s\n", polaris.Principal(r.Context()).Subject())
	})))
	log.Fatal(http.ListenAndServe(":8080", mux))
}
