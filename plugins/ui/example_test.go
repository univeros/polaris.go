package ui_test

import (
	"cmp"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/ui"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

// Sign-in pages for a server-rendered app: p.Handler() serves them under /auth/ui, and
// RequireSignIn sends a signed-out browser there from a protected page.
func Example() {
	private, public := contracttest.TestRSAKeyPEM() // AUTH_JWT_* in production
	auth := config.Defaults()
	auth.Issuer = "https://app.example.com"
	db := memstore.New(schema.Core()...) // sqlstore.Open(...) in production

	web := ui.New(ui.Config{AppName: "Acme", AfterSignIn: "/dashboard"})
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: db, Plugins: []polaris.Plugin{web},
	})
	if err != nil {
		log.Fatal(err)
	}

	dashboard := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		fmt.Fprintln(w, "hello", who.UserID)
	})
	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // the pages and every JSON route
	mux.Handle("GET /dashboard", web.RequireSignIn(p.Protect(dashboard)))

	for _, path := range []string{"/auth/ui/sign-in", "/dashboard"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://app.example.com"+path, nil))
		fmt.Println(path, w.Code, cmp.Or(w.Header().Get("Location"), w.Header().Get("Content-Type")))
	}
	// Output:
	// /auth/ui/sign-in 200 text/html; charset=utf-8
	// /dashboard 303 /auth/ui/refresh?return_to=%2Fdashboard
}
