// Command hooks keeps the host's own data in step with Polaris: a `profiles` table of the app's,
// next to Polaris's tables in the same database.
//
//   - Hooks.OnUserCreated / OnUserDeleted write and erase the profile row inside the transaction
//     that creates or erases the account, on every path (registration, Users().Create, admin, …).
//   - Hooks.Claims puts the profile's plan into every access token as `app_plan`.
//   - Listeners log every domain event; Middleware gives every request an X-Request-Id that the
//     log lines carry.
//   - POST /api/signup is the host's own onboarding: account, organization and profile in ONE
//     host transaction (sqlstore.WithTx). A plan the profiles table refuses undoes it all.
//   - GET /api/profile is a host route behind Protect that reads the profile and the claim.
//   - p.Prune runs at start and every hour.
//
// Run it, then follow README.md:
//
//	go run ./examples/hooks
//
// Zero setup: SQLite in a temporary directory, and APP_KEY, AUTH_JWT_PRIVATE_KEY,
// AUTH_JWT_PUBLIC_KEY and AUTH_ISSUER generated when the environment lacks them. ADDR (default
// localhost:8080) is where it listens.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// profiles is the host's own table. The CHECK is the host's rule a signup can break.
const profilesDDL = `CREATE TABLE IF NOT EXISTS profiles (
	user_id         VARCHAR(36) PRIMARY KEY,
	plan            TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro')),
	organization_id VARCHAR(36)
)`

func main() {
	ctx := context.Background()
	addr := envOr("ADDR", "localhost:8080")
	if err := devEnv("http://" + addr); err != nil {
		log.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "polaris-hooks-")
	if err != nil {
		log.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(dir, "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	h, p, err := newServer(ctx, db)
	if err != nil {
		log.Fatal(err)
	}
	go prune(ctx, p, time.Hour)

	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	log.Printf("listening on http://%s", addr)
	log.Fatal(srv.ListenAndServe())
}

// newServer is the host: Polaris with the hooks, the listener and the middleware, plus the host's
// own routes.
func newServer(ctx context.Context, db *sqlstore.Store) (http.Handler, *polaris.Polaris, error) {
	if _, err := db.DB().ExecContext(ctx, profilesDDL); err != nil {
		return nil, nil, err
	}
	cfg, err := polaris.FromEnv(db)
	if err != nil {
		return nil, nil, err
	}
	cfg.Hooks = polaris.Hooks{
		// ctx carries the account's transaction: a write through db with it commits or rolls back
		// with the account. An error aborts the creation.
		OnUserCreated: func(ctx context.Context, u polaris.User) error {
			return db.Exec(ctx, "INSERT INTO profiles (user_id) VALUES (?)", u.ID)
		},
		OnUserDeleted: func(ctx context.Context, userID string) error {
			return db.Exec(ctx, "DELETE FROM profiles WHERE user_id = ?", userID)
		},
		// Runs on every token mint (sign-in, refresh, org switch): keep it to one indexed read.
		// FindOne with ctx joins the transaction when the mint runs inside one.
		Claims: func(ctx context.Context, in polaris.ClaimsInput) (map[string]any, error) {
			row, err := db.FindOne(ctx, "profiles", store.Criteria{"user_id": in.UserID})
			if err != nil || row == nil {
				return nil, err
			}
			return map[string]any{"app_plan": row.String("plan")}, nil
		},
	}
	cfg.Listeners = []event.Listener{func(ctx context.Context, e event.Event) {
		log.Printf("event %s request_id=%s", e.EventName(), requestIDFrom(ctx))
	}}
	cfg.Middleware = []func(http.Handler) http.Handler{requestID} // around Handler and every Protect
	p, err := polaris.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	if _, err := p.Migrate(ctx); err != nil {
		return nil, nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // /auth/register, /auth/login, /users/{id}, …
	mux.Handle("POST /api/signup", requestID(signup(db, p)))
	mux.Handle("GET /api/profile", p.Protect(profile(db)))
	return mux, p, nil
}

// signup creates the account, its organization and the profile's plan in one host transaction:
// every Polaris call joins it through sqlstore.WithTx, OnUserCreated included. Events (and the
// verification mail) go out when Polaris's part is done, even if the host then rolls back.
func signup(db *sqlstore.Store, p *polaris.Polaris) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Email, Password, Company, Plan string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Company == "" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "send email, password, company and plan"})
			return
		}
		ctx := r.Context()
		tx, err := db.DB().BeginTx(ctx, nil)
		if err != nil {
			fail(w, err)
			return
		}
		defer func() { _ = tx.Rollback() }() // no-op once committed
		txCtx := sqlstore.WithTx(ctx, tx)

		user, err := p.Users().Create(txCtx, polaris.NewUser{Email: in.Email, Password: in.Password})
		switch {
		case errors.Is(err, polaris.ErrConflict):
			writeJSON(w, http.StatusConflict, map[string]any{"error": "the email is taken"})
			return
		case errors.Is(err, polaris.ErrInvalidInput):
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
			return
		case err != nil:
			fail(w, err)
			return
		}
		org, err := p.Orgs().Create(txCtx, user.ID, in.Company, "")
		if errors.Is(err, polaris.ErrConflict) { // the slug derived from the name is taken
			writeJSON(w, http.StatusConflict, map[string]any{"error": "the company name is taken"})
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		// The host's own write, after Polaris's: a plan the CHECK refuses rolls back the account,
		// its profile row and the organization with it.
		if _, err := tx.ExecContext(ctx, "UPDATE profiles SET plan = ?, organization_id = ? WHERE user_id = ?", in.Plan, org.ID, user.ID); err != nil {
			log.Printf("signup rolled back: %v", err)
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "plan is free or pro; nothing was created"})
			return
		}
		if err := tx.Commit(); err != nil {
			fail(w, err)
			return
		}
		// The account signs in once its email is verified (the link went to the log).
		writeJSON(w, http.StatusCreated, map[string]any{
			"user_id": user.ID, "organization_id": org.ID,
			// Can re-resolves from the database: the owner of the new organization may delete it.
			"can_delete_org": p.Can(ctx, polaris.Principal{UserID: user.ID, OrganizationID: org.ID}, "org.delete"),
		})
	}
}

// profile answers the caller's profile row and the claim Hooks.Claims minted into their token.
func profile(db *sqlstore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		var plan string
		var org *string
		err := db.DB().QueryRowContext(r.Context(), "SELECT plan, organization_id FROM profiles WHERE user_id = ?", who.UserID).Scan(&plan, &org)
		if errors.Is(err, sql.ErrNoRows) { // erased: OnUserDeleted removed it (the access token lives until it expires)
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "no profile"})
			return
		}
		if err != nil {
			fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user_id": who.UserID, "plan": plan, "organization_id": org, "token_app_plan": who.Claims["app_plan"],
		})
	}
}

// prune deletes expired refresh tokens, codes and invitations now and then every interval.
// Idempotent: every replica may run it.
func prune(ctx context.Context, p *polaris.Polaris, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		n, err := p.Prune(ctx)
		if err != nil {
			log.Printf("prune: %v", err)
		} else {
			log.Printf("pruned %v", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// requestID gives every request an id (the client's X-Request-Id, or a fresh one), echoes it in
// the response and puts it in the context, where the event listener reads it.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = base64.RawURLEncoding.EncodeToString(b)
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

type requestIDKey struct{}

func requestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, err error) {
	log.Printf("error: %v", err)
	writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "internal error"})
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
