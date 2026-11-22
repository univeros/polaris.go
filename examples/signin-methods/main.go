// Command signin-methods is one Polaris server with every way to sign in besides a password:
// magic links and email codes (passwordless), usernames, guest sessions converted on sign-up
// (anonymous), several accounts per device (multisession), a generic OpenID Connect provider
// (social), passkeys, plus the messaging plugin delivering the mails and sentinel scoring every
// attempt in observe mode. Core's MFA (TOTP, email codes) gates all of them.
//
//	go run ./examples/signin-methods
//
// Zero setup: SQLite in a temporary directory, and APP_KEY, AUTH_JWT_PRIVATE_KEY,
// AUTH_JWT_PUBLIC_KEY and AUTH_ISSUER generated when the environment lacks them. ADDR (default
// localhost:8080) is where it listens. Optional:
//
//   - OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET: an OpenID Connect provider, offered as
//     /social/oidc/*; register <base URL>/social/oidc/callback at it. Absent: no social sign-in.
//   - SMTP_ADDR (host:port), SMTP_FROM, SMTP_USER, SMTP_PASSWORD: deliver mail over SMTP. Absent:
//     every message (links and codes included) is written to the server's log.
//
// README.md walks through each method with curl.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/anonymous"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/messaging"
	"github.com/univeros/polaris.go/plugins/multisession"
	"github.com/univeros/polaris.go/plugins/passkey"
	"github.com/univeros/polaris.go/plugins/passwordless"
	"github.com/univeros/polaris.go/plugins/sentinel"
	"github.com/univeros/polaris.go/plugins/social"
	"github.com/univeros/polaris.go/plugins/username"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

func main() {
	ctx := context.Background()
	addr := envOr("ADDR", "localhost:8080")
	baseURL := "http://" + addr
	if err := devEnv(baseURL); err != nil {
		log.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "polaris-signin-")
	if err != nil {
		log.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(dir, "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	h, err := newServer(ctx, db, baseURL, emailChannel())
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Polaris serving on %s", baseURL)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// newServer is the host: Polaris with every sign-in plugin, and the page a magic link or a social
// sign-in lands on. email is the mail channel (nil: the log).
func newServer(ctx context.Context, db store.Adapter, baseURL string, email messaging.Channel) (http.Handler, error) {
	landing := baseURL + "/signed-in" // where a magic link or a social sign-in ends, with ?code=
	plugins := []polaris.Plugin{
		audit.New(audit.Config{}),
		admin.New(admin.Config{}), // sentinel's decisions and IP rules are admin routes
		passwordless.New(passwordless.Config{RedirectURIs: []string{landing}}),
		username.New(username.Config{}),
		anonymous.New(anonymous.Config{
			// Move the guest's data (a cart, drafts) to the account it signed up as.
			OnConvert: func(ctx context.Context, guestID, userID string) error {
				log.Printf("guest %s is now user %s", guestID, userID)
				return nil
			},
		}),
		multisession.New(multisession.Config{}),
		passkey.New(passkey.Config{Origins: []string{baseURL}, RPName: "Sign-in methods example"}),
		// Leave cfg.Mailer and cfg.SMS nil: the plugin becomes core's mailer and SMS sender.
		messaging.New(messaging.Config{Email: email}),
		sentinel.New(sentinel.Config{}), // observe mode: scores and records, never blocks
	}
	if s := socialPlugin(baseURL, landing); s != nil {
		plugins = append(plugins, s)
	}

	cfg, err := polaris.FromEnv(db, plugins...)
	if err != nil {
		return nil, err
	}
	p, err := polaris.New(cfg)
	if err != nil {
		return nil, err
	}
	if _, err := p.Migrate(ctx); err != nil {
		return nil, err
	}
	// A read-only operator key, to read sentinel's decisions at GET /admin/sentinel/decisions.
	// Development only: a real deployment mints it once (`polaris admin:key`) and never logs it.
	_, secret, err := admin.Of(p.Graph()).Keys().Create(ctx, admin.Key{Name: "example", Role: admin.RoleViewer})
	if err != nil {
		return nil, err
	}
	log.Printf("operator key (viewer): %s", secret)

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler())
	// The host's landing page: a real app's front end trades the code for the session with
	// POST /magic-link/exchange or /social/exchange; this one shows it.
	mux.HandleFunc("GET /signed-in", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"code": r.URL.Query().Get("code"), "state": r.URL.Query().Get("state")})
	})
	return mux, nil
}

// socialPlugin offers the OpenID Connect provider OIDC_ISSUER as "oidc", or nil when it is not
// configured. Any catalog provider ("google", "github", …) needs only ClientID and ClientSecret.
func socialPlugin(baseURL, landing string) polaris.Plugin {
	issuer, id, secret := os.Getenv("OIDC_ISSUER"), os.Getenv("OIDC_CLIENT_ID"), os.Getenv("OIDC_CLIENT_SECRET")
	if issuer == "" || id == "" {
		log.Print("social sign-in off: set OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET to offer /social/oidc/*")
		return nil
	}
	return social.New(social.Config{
		BaseURL:      baseURL,
		RedirectURIs: []string{landing},
		Providers:    map[string]social.Provider{"oidc": {Issuer: issuer, ClientID: id, ClientSecret: secret, Name: "OpenID Connect"}},
	})
}

// emailChannel is SMTP when SMTP_ADDR is set; nil (the log) otherwise.
func emailChannel() messaging.Channel {
	addr := os.Getenv("SMTP_ADDR")
	if addr == "" {
		log.Print("mail goes to this log: set SMTP_ADDR (host:port) and SMTP_FROM to send it")
		return nil
	}
	host, _, _ := net.SplitHostPort(addr)
	var auth smtp.Auth
	if user := os.Getenv("SMTP_USER"); user != "" {
		auth = smtp.PlainAuth("", user, os.Getenv("SMTP_PASSWORD"), host)
	}
	return &messaging.SMTP{Addr: addr, From: envOr("SMTP_FROM", "noreply@localhost"), Auth: auth}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// devEnv sets what polaris.FromEnv reads and the environment lacks, so the example runs with zero
// setup: a random APP_KEY, a fresh RS256 key pair, AUTH_ISSUER. Tokens signed with a generated key
// die with the process; in production set the variables (`polaris init` writes them to .env).
func devEnv(issuer string) error {
	if os.Getenv("APP_KEY") == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		if err := os.Setenv("APP_KEY", base64.StdEncoding.EncodeToString(b)); err != nil {
			return err
		}
	}
	if os.Getenv("AUTH_JWT_PRIVATE_KEY") == "" {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}
		priv, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return err
		}
		pub, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return err
		}
		if err := os.Setenv("AUTH_JWT_PRIVATE_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv}))); err != nil {
			return err
		}
		if err := os.Setenv("AUTH_JWT_PUBLIC_KEY", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))); err != nil {
			return err
		}
		log.Print("generated a throwaway JWT key pair (set AUTH_JWT_PRIVATE_KEY and AUTH_JWT_PUBLIC_KEY to keep tokens across restarts)")
	}
	if os.Getenv("AUTH_ISSUER") == "" {
		return os.Setenv("AUTH_ISSUER", issuer)
	}
	return nil
}
