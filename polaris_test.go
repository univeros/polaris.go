package polaris_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/cli"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/contracttest"
	"github.com/univeros/polaris-go/notify/notifytest"
	"github.com/univeros/polaris-go/plugins/mcp"
	"github.com/univeros/polaris-go/polaristest"
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

// TestEdDSAFromEnv boots Polaris with the keys "polaris keys:generate --alg=EdDSA" prints: login
// issues an EdDSA token that verifies with the public key, the JWKS route publishes it as an RFC
// 8037 OKP key (upstream cannot), and mcp.Protect verifies the token through that JWKS URL.
func TestEdDSAFromEnv(t *testing.T) {
	ctx := context.Background()
	var out, stderr bytes.Buffer
	if code := cli.Run(ctx, polaristest.New(t).Polaris, []string{"keys:generate", "--alg=EdDSA", "--json"}, &out, &stderr); code != 0 {
		t.Fatalf("keys:generate: %d %s", code, stderr.String())
	}
	var generated struct{ Env map[string]string }
	if err := json.Unmarshal(out.Bytes(), &generated); err != nil {
		t.Fatal(err)
	}
	for k, v := range generated.Env {
		t.Setenv(k, v)
	}
	t.Setenv("AUTH_ISSUER", "http://localhost")
	const resource = "https://tools.example.com/mcp"
	t.Setenv("AUTH_AUDIENCE", resource)

	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "e.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.DB().Close()
	cfg, err := polaris.FromEnv(db)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Auth.AccessToken.Signer = config.SignerEdDSA
	mailer := &notifytest.Mailer{}
	cfg.Mailer = mailer
	cfg.Hasher = security.Argon2id{Memory: 1024, Time: 1, Threads: 1}
	p, err := polaris.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	c := contracttest.NewClient(t, p.Handler(), nil)

	const email, password = "ada@example.com", "correct horse battery staple"
	c.Post("/auth/register", map[string]any{"email": email, "password": password})
	c.Post("/auth/email/verify", map[string]any{"token": mailer.Sent()[0].Data["token"]})
	login := contracttest.JSON(t, c.Post("/auth/login", map[string]any{"email": email, "password": password}))
	access := login["data"].(map[string]any)["access_token"].(string)

	parts := strings.Split(access, ".")
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	pub, _ := base64.StdEncoding.DecodeString(generated.Env["AUTH_JWT_PUBLIC_KEY"])
	kid := sha256.Sum256(pub) // upstream's default kid: SHA-256 hex of the raw public key
	var h struct{ Alg, Kid string }
	if err := json.Unmarshal(header, &h); err != nil || h.Alg != "EdDSA" || h.Kid != hex.EncodeToString(kid[:]) {
		t.Fatalf("header %s", header)
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		t.Fatal("the access token does not verify with AUTH_JWT_PUBLIC_KEY")
	}
	if r := c.Get("/auth/me", contracttest.Bearer(access)); r.StatusCode != 200 {
		t.Fatalf("/auth/me %d", r.StatusCode)
	}
	jwks := contracttest.JSON(t, c.Get("/auth/.well-known/jwks.json"))
	want := map[string]any{"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA", "kid": h.Kid, "x": base64.RawURLEncoding.EncodeToString(pub)}
	if keys := jwks["keys"].([]any); len(keys) != 1 || !maps.Equal(keys[0].(map[string]any), want) {
		t.Fatalf("jwks %v", jwks)
	}

	issuer := httptest.NewTLSServer(p.Handler())
	defer issuer.Close()
	tools, err := mcp.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "tools for "+mcp.Claims(r.Context())["sub"].(string))
	}), mcp.ProtectConfig{Resource: resource, Issuer: "http://localhost", JWKSURL: issuer.URL + "/auth/.well-known/jwks.json", HTTPClient: issuer.Client()})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", resource, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+access)
	rec := httptest.NewRecorder()
	tools.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.HasPrefix(rec.Body.String(), "tools for ") {
		t.Fatalf("mcp.Protect over the EdDSA JWKS: %d %s", rec.Code, rec.Body.String())
	}
}
