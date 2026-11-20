package polaris_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/notify/notifytest"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/sqlstore"
)

// TestQuickstart is the integration a coding agent copies from llms.txt: env config, Migrate,
// Handler, Protect, Principal.
func TestQuickstart(t *testing.T) {
	private, public := contracttest.TestRSAKeyPEM()
	t.Setenv("APP_KEY", contracttest.AppKey)
	t.Setenv("AUTH_JWT_PRIVATE_KEY", private)
	t.Setenv("AUTH_JWT_PUBLIC_KEY", public)
	t.Setenv("AUTH_ISSUER", "http://localhost")

	ctx := context.Background()
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "q.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB().Close()
	cfg, err := polaris.FromEnv(db)
	if err != nil {
		t.Fatal(err)
	}
	mailer := &notifytest.Mailer{}
	cfg.Mailer = mailer
	cfg.Hasher = security.Argon2id{Memory: 1024, Time: 1, Threads: 1}
	p, err := polaris.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	created, err := p.Migrate(ctx)
	if err != nil || len(created) == 0 {
		t.Fatalf("migrate: %v %v", created, err)
	}
	if again, err := p.Migrate(ctx); err != nil || len(again) != 0 {
		t.Fatalf("second migrate must be a no-op: %v %v", again, err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", p.Handler())
	mux.Handle("GET /hello", p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello "+polaris.Principal(r.Context()).Subject())
	})))
	c := contracttest.NewClient(t, mux, nil)

	const email, password = "ada@example.com", "correct horse battery staple"
	if r := c.Post("/auth/register", map[string]any{"email": email, "password": password}); r.StatusCode != 202 {
		t.Fatalf("register %d", r.StatusCode)
	}
	sent := mailer.Sent()
	if len(sent) != 1 {
		t.Fatalf("mails %v", sent)
	}
	if r := c.Post("/auth/email/verify", map[string]any{"token": sent[0].Data["token"]}); r.StatusCode != 200 {
		t.Fatalf("verify %d", r.StatusCode)
	}
	login := contracttest.JSON(t, c.Post("/auth/login", map[string]any{"email": email, "password": password}))
	access := login["data"].(map[string]any)["access_token"].(string)

	if r := c.Get("/hello"); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated host route: %d", r.StatusCode)
	}
	req := httptest.NewRequest("GET", "/hello", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "hello ") || len(rec.Body.String()) < 10 {
		t.Fatalf("protected host route: %d %q", rec.Code, rec.Body.String())
	}
}

func TestHostPermissionsJoinTheCatalog(t *testing.T) {
	private, public := contracttest.TestRSAKeyPEM()
	t.Setenv("APP_KEY", contracttest.AppKey)
	t.Setenv("AUTH_JWT_PRIVATE_KEY", private)
	t.Setenv("AUTH_JWT_PUBLIC_KEY", public)
	t.Setenv("AUTH_ISSUER", "http://localhost")
	ctx := context.Background()
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "p.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB().Close()
	cfg, err := polaris.FromEnv(db)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Permissions = map[string]string{"billing.refund": "Refund an invoice"}
	p, err := polaris.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Graph().Repos.Permissions.ByKey(ctx, "billing.refund"); err != nil {
		t.Fatalf("host permission not seeded: %v", err)
	}
}
