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
//	POLARIS_DEV=1 go run ./examples/b2b
//
// SQLite in a temporary directory; with POLARIS_DEV=1, polaris.DevEnv generates APP_KEY,
// AUTH_JWT_PRIVATE_KEY, AUTH_JWT_PUBLIC_KEY and AUTH_ISSUER when the environment lacks them. ADDR (default
// localhost:8080) is where it listens. Emails (verification, invitations) are written to the log.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	polaris "github.com/univeros/polaris.go"
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
	if err := polaris.DevEnv(baseURL); err != nil {
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
	h, p, err := newServer(ctx, db)
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
// audit and admin, plus the host's own project routes.
func newServer(ctx context.Context, db store.Adapter, tune ...func(*polaris.Config)) (http.Handler, *polaris.Polaris, error) {
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
	// Every organization's owner and admin roles hold the host's permissions, so its owner can put
	// them into custom roles, invitations and API keys (only what you hold can be granted).
	cfg.RolePermissions = map[string][]string{
		"owner": {"projects.read", "projects.write"},
		"admin": {"projects.read", "projects.write"},
	}
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
