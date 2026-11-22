// Command b2b is a multi-tenant SaaS on Polaris: every customer is an organization with its own
// members, roles and API keys; the host's own permissions (projects.read, projects.write) gate the
// host's own routes; invitations bring colleagues in; and an organization admin connects their
// company's identity provider (OIDC or SAML single sign-on) and directory (SCIM provisioning).
//
//   - GET  /api/projects  needs projects.read  (p.Protect)
//   - POST /api/projects  needs projects.write (p.Protect)
//
// Users, API keys and SCIM-provisioned accounts all reach those routes the same way. Every change
// is in the audit log; the admin plugin serves the operator API. README.md has the curl
// walkthrough: sign up, create an organization, custom roles, an invitation, an organization API
// key, an OIDC provider with a verified domain, and a SCIM connection.
//
//	go run ./examples/b2b
//
// Zero setup: SQLite in a temporary directory, and APP_KEY, AUTH_JWT_PRIVATE_KEY,
// AUTH_JWT_PUBLIC_KEY and AUTH_ISSUER generated when the environment lacks them. ADDR (default
// localhost:8080) is where it listens. Emails (verification, invitations) are written to the log.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/notify"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/apikeys"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/scim"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// permissions are the host's own, in the catalog next to core's: roles, API keys and OAuth scopes
// can carry them, and Protect can require them.
var permissions = map[string]string{
	"projects.read":  "Read the organization's projects",
	"projects.write": "Create and change the organization's projects",
}

func main() {
	ctx := context.Background()
	addr := envOr("ADDR", "localhost:8080")
	baseURL := "http://" + addr
	if err := devEnv(baseURL); err != nil {
		log.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "polaris-b2b-")
	if err != nil {
		log.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(dir, "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		log.Fatal(err)
	}
	h, p, err := newServer(ctx, db, nil)
	if err != nil {
		log.Fatal(err)
	}
	// An operator API key for the admin plugin's /admin/* routes, shown once. In production mint
	// it with `polaris admin:key <name> <role>` and keep it in a secrets manager.
	_, secret, err := admin.Of(p.Graph()).Keys().Create(ctx, admin.Key{Name: "example operator", Role: admin.RoleViewer})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("operator key (viewer, this run only): %s\n", secret)
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 120 * time.Second}
	log.Printf("Polaris b2b example on %s", baseURL)
	log.Fatal(srv.ListenAndServe())
}

// newServer is the host: Polaris with organizations, the host's permissions, API keys, SSO, SCIM,
// audit and admin, plus the host's own project routes. mailer nil keeps the logging mailer.
func newServer(ctx context.Context, db store.Adapter, mailer notify.Mailer) (http.Handler, *polaris.Polaris, error) {
	cfg, err := polaris.FromEnv(db,
		audit.New(audit.Config{}),     // every event, append-only: GET /audit/organization/{id}
		admin.New(admin.Config{}),     // the operator API, /admin/*
		apikeys.New(apikeys.Config{}), // pk_live_… keys owned by a user or an organization
		sso.New(sso.Config{}),         // per-organization OIDC and SAML identity providers
		scim.New(scim.Config{}),       // per-organization SCIM 2.0 provisioning
	)
	if err != nil {
		return nil, nil, err
	}
	cfg.Permissions = permissions
	if mailer != nil {
		cfg.Mailer = mailer
	}
	// A new organization's owner and admin roles get the host's permissions, so its owner can put
	// them into custom roles, invitations and API keys (see grantToRole).
	var p *polaris.Polaris
	cfg.Listeners = []event.Listener{func(ctx context.Context, e event.Event) {
		created, ok := e.(event.OrganizationCreated)
		if !ok {
			return
		}
		for _, role := range []string{"owner", "admin"} {
			if err := grantToRole(ctx, p, created.OrganizationID, role, "projects.read", "projects.write"); err != nil {
				slog.ErrorContext(ctx, "granting the host permissions failed", "organization", created.OrganizationID, "role", role, "error", err)
			}
		}
	}}
	if p, err = polaris.New(cfg); err != nil {
		return nil, nil, err
	}
	if _, err := p.Migrate(ctx); err != nil {
		return nil, nil, err
	}

	projects := &projectStore{byOrg: map[string][]project{}}
	mux := http.NewServeMux()
	mux.Handle("/", p.Handler()) // /auth/*, /orgs/*, /api-keys, /sso/*, /scim/v2/*, /audit/*, /admin/*
	mux.Handle("GET /api/projects", p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{"organization": who.OrganizationID, "caller": who.Kind, "projects": projects.list(who.OrganizationID)})
	}), "projects.read"))
	mux.Handle("POST /api/projects", p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		var in struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || in.Name == "" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "validation_failed", "message": "name is required"})
			return
		}
		writeJSON(w, http.StatusCreated, projects.add(who.OrganizationID, in.Name, who.UserID))
	}), "projects.write"))
	return mux, p, nil
}

// project is the host's own data, kept per organization: a tenant only ever sees its own.
type project struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	CreatedBy string `json:"created_by"`
}

// projectStore stands in for the host's own table (organization_id, name, created_by).
type projectStore struct {
	mu    sync.Mutex
	byOrg map[string][]project
}

func (s *projectStore) list(orgID string) []project {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]project{}, s.byOrg[orgID]...)
}

func (s *projectStore) add(orgID, name, userID string) project {
	s.mu.Lock()
	defer s.mu.Unlock()
	pr := project{ID: len(s.byOrg[orgID]) + 1, Name: name, CreatedBy: userID}
	s.byOrg[orgID] = append(s.byOrg[orgID], pr)
	return pr
}

// grantToRole grants the host's own permissions to an organization's role. Polaris has no host call
// for it: over HTTP an owner cannot (POST /orgs/{id}/roles refuses keys the caller does not hold,
// and no system role holds the host's permissions), so this goes through the plugin SDK's
// repositories. Run it when the organization is created.
func grantToRole(ctx context.Context, p *polaris.Polaris, orgID, roleSlug string, keys ...string) error {
	repos := p.Graph().Repos()
	role, err := repos.Roles.ByOrganizationAndSlug(ctx, &orgID, roleSlug)
	if err != nil {
		return fmt.Errorf("role %s: %w", roleSlug, err)
	}
	for _, key := range keys {
		perm, err := repos.Permissions.ByKey(ctx, key)
		if err != nil {
			return fmt.Errorf("permission %s: %w", key, err)
		}
		if err := repos.RolePermissions.Insert(ctx, model.RolePermission{RoleID: role.ID, PermissionID: perm.ID}); err != nil {
			return fmt.Errorf("grant %s: %w", key, err)
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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
