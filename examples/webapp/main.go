// Command webapp is a complete server-rendered app on Polaris: the sign-in, sign-up, email
// verification, password reset and sign-out pages of plugins/ui, and a /dashboard only a signed-in
// browser sees. SQLite, no JavaScript.
//
// Environment: APP_KEY (≥ 32 bytes), AUTH_JWT_PRIVATE_KEY and AUTH_JWT_PUBLIC_KEY (PEM), AUTH_ISSUER;
// ADDR (default :8080).
//
//	export APP_KEY=$(openssl rand -base64 32)
//	openssl genrsa -out jwt.key 2048 && openssl rsa -in jwt.key -pubout -out jwt.pub
//	export AUTH_JWT_PRIVATE_KEY="$(cat jwt.key)" AUTH_JWT_PUBLIC_KEY="$(cat jwt.pub)" AUTH_ISSUER=http://localhost:8080
//	go run ./examples/webapp
//
// Then open http://localhost:8080 (the session cookies are Secure: browsers keep them on
// localhost; anywhere else serve HTTPS). The verification and reset links are printed to the log,
// where a real Mailer would email them.
package main

import (
	"cmp"
	"context"
	"html/template"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/plugins/ui"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// linkMailer logs the links the pages expect in the verification and reset emails; other mail
// goes to Polaris's development log mailer.
type linkMailer struct {
	web  *ui.Plugin
	next notify.Mailer
}

func (m linkMailer) Send(ctx context.Context, to, tmpl string, data map[string]any) error {
	token, _ := data["token"].(string)
	switch tmpl {
	case notify.TemplateVerifyEmail:
		slog.InfoContext(ctx, "verification email", "to", to, "link", m.web.VerifyEmailURL(token))
	case notify.TemplatePasswordReset:
		slog.InfoContext(ctx, "password reset email", "to", to, "link", m.web.ResetPasswordURL(token))
	default:
		return m.next.Send(ctx, to, tmpl, data)
	}
	return nil
}

var dashboard = template.Must(template.New("dashboard").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard</title><link rel="stylesheet" href="/auth/ui/style.css"></head>
<body><main><h1>Dashboard</h1><p>Signed in as {{.}}.</p>
<p><a class="button" href="/auth/ui/sign-out">Sign out</a></p></main></body></html>`))

func main() {
	ctx := context.Background()
	db, err := sqlstore.Open(ctx, store.SQLite, "file:webapp.db?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	web := ui.New(ui.Config{AppName: "Acme", AfterSignIn: "/dashboard"})
	cfg, err := polaris.FromEnv(db, web)
	if err != nil {
		log.Fatal(err)
	}
	cfg.Mailer = linkMailer{web: web, next: notify.NewLogMailer(slog.Default())}
	p, err := polaris.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := p.Migrate(ctx); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // the pages under /auth/ui and every JSON route
	mux.Handle("GET /{$}", http.RedirectHandler("/dashboard", http.StatusSeeOther))
	mux.Handle("GET /dashboard", web.RequireSignIn(p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		user, err := p.Users().Get(r.Context(), who.UserID)
		if err != nil {
			http.Error(w, "The account could not be read.", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		_ = dashboard.Execute(w, user.Email)
	}))))
	srv := &http.Server{Addr: cmp.Or(os.Getenv("ADDR"), ":8080"), Handler: mux, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
