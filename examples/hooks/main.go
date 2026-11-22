// Command hooks keeps the host's own data in step with Polaris: a `profiles` table of the app's,
// next to Polaris's tables in the same database.
//
//   - Hooks.OnUserCreated / OnUserDeleted write and erase the profile row inside the transaction
//     that creates or erases the account, on every path (registration, Users().Create, admin, …),
//     with plain database/sql through db.Conn(ctx).
//   - Hooks.Claims puts the profile's plan into every access token as `app_plan`.
//   - Listeners log every domain event; Middleware gives every request an X-Request-Id that the
//     log lines carry (p.Wrap puts it around the host's own public route too).
//   - POST /api/signup is the host's own onboarding: account, organization and profile in ONE
//     host transaction (db.Tx). A plan the profiles table refuses undoes it all, and its events
//     never go out: they wait for the commit.
//   - GET /api/profile is a host route behind Protect that reads the profile and the claim.
//   - p.Prune runs at start and every hour.
//
// Run it, then follow README.md:
//
//	POLARIS_DEV=1 go run ./examples/hooks
//
// SQLite in a temporary directory; with POLARIS_DEV=1, polaris.DevEnv generates APP_KEY,
// AUTH_JWT_PRIVATE_KEY, AUTH_JWT_PUBLIC_KEY and AUTH_ISSUER when the environment lacks them.
// ADDR (default localhost:8080) is where it listens.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
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

// errPlan is the host's own refusal, which rolls the signup back.
var errPlan = errors.New("plan is free or pro; nothing was created")

func main() {
	ctx := context.Background()
	addr := envOr("ADDR", "localhost:8080")
	if err := polaris.DevEnv("http://" + addr); err != nil { // POLARIS_DEV=1; in production set the variables
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
func newServer(ctx context.Context, db *sqlstore.Store, tune ...func(*polaris.Config)) (http.Handler, *polaris.Polaris, error) {
	if _, err := db.Conn(ctx).ExecContext(ctx, profilesDDL); err != nil {
		return nil, nil, err
	}
	cfg, err := polaris.FromEnv(db)
	if err != nil {
		return nil, nil, err
	}
	// The statements below use ? placeholders: SQLite's and MySQL's. PostgreSQL's are $1, $2, ….
	cfg.Hooks = polaris.Hooks{
		// ctx carries the account's transaction: db.Conn(ctx) is it, so the row commits or rolls
		// back with the account. An error aborts the creation.
		OnUserCreated: func(ctx context.Context, u polaris.User) error {
			_, err := db.Conn(ctx).ExecContext(ctx, "INSERT INTO profiles (user_id) VALUES (?)", u.ID)
			return err
		},
		OnUserDeleted: func(ctx context.Context, userID string) error {
			_, err := db.Conn(ctx).ExecContext(ctx, "DELETE FROM profiles WHERE user_id = ?", userID)
			return err
		},
		// Runs on every token mint (sign-in, refresh, org switch): keep it to one indexed read.
		Claims: func(ctx context.Context, in polaris.ClaimsInput) (map[string]any, error) {
			var plan string
			err := db.Conn(ctx).QueryRowContext(ctx, "SELECT plan FROM profiles WHERE user_id = ?", in.UserID).Scan(&plan)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, nil
			}
			return map[string]any{"app_plan": plan}, err
		},
	}
	cfg.Listeners = []event.Listener{func(ctx context.Context, e event.Event) {
		log.Printf("event %s request_id=%s", e.EventName(), requestIDFrom(ctx))
	}}
	cfg.Middleware = []func(http.Handler) http.Handler{requestID} // around Handler, every Protect and p.Wrap
	// tune is the tests': a cheap hasher (polaristest.Hasher).
	for _, f := range tune {
		f(&cfg)
	}
	p, err := polaris.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	if _, err := p.Migrate(ctx); err != nil {
		return nil, nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // /auth/register, /auth/login, /users/{id}, …
	mux.Handle("POST /api/signup", p.Wrap(signup(db, p)))
	mux.Handle("GET /api/profile", p.Protect(profile(db)))
	return mux, p, nil
}

// signup creates the account, its organization and the profile's plan in one host transaction:
// every Polaris call made with the ctx db.Tx passes joins it, OnUserCreated included, and so does
// the host's own UPDATE through db.Conn(ctx). The events, and the verification mail, wait for the
// commit: a rolled-back signup sends nothing.
func signup(db *sqlstore.Store, p *polaris.Polaris) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Email, Password, Company, Plan string }
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Company == "" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "send email, password, company and plan"})
			return
		}
		var user polaris.User
		var org polaris.Organization
		err := db.Tx(r.Context(), func(ctx context.Context) error {
			var err error
			if user, err = p.Users().Create(ctx, polaris.NewUser{Email: in.Email, Password: in.Password}); err != nil {
				return err
			}
			if org, err = p.Orgs().Create(ctx, user.ID, in.Company, ""); err != nil {
				return err
			}
			// The host's own write, after Polaris's: a plan the CHECK refuses rolls back the
			// account, its profile row and the organization with it.
			_, err = db.Conn(ctx).ExecContext(ctx, "UPDATE profiles SET plan = ?, organization_id = ? WHERE user_id = ?", in.Plan, org.ID, user.ID)
			if err != nil {
				log.Printf("signup rolled back: %v", err)
				return errPlan
			}
			return nil
		})
		switch {
		case errors.Is(err, polaris.ErrConflict): // the email, or the slug derived from the company
			writeJSON(w, http.StatusConflict, map[string]any{"error": "the email or the company name is taken"})
		case errors.Is(err, polaris.ErrInvalidInput), errors.Is(err, errPlan):
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		case err != nil:
			fail(w, err)
		default:
			// The account signs in once its email is verified (the link went to the log).
			writeJSON(w, http.StatusCreated, map[string]any{
				"user_id": user.ID, "organization_id": org.ID,
				// Can re-resolves from the database: the owner of the new organization may delete it.
				"can_delete_org": p.Can(r.Context(), polaris.Principal{UserID: user.ID, OrganizationID: org.ID}, "org.delete"),
			})
		}
	}
}

// profile answers the caller's profile row and the claim Hooks.Claims minted into their token.
func profile(db *sqlstore.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		var plan string
		var org *string
		err := db.Conn(r.Context()).QueryRowContext(r.Context(), "SELECT plan, organization_id FROM profiles WHERE user_id = ?", who.UserID).Scan(&plan, &org)
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
