package scim

import (
	"context"
	"fmt"
	"io/fs"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/internal/maintenance"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.scim.*.
const ID = "scim"

var absoluteURL = regexp.MustCompile(`^https?://[^/]+`)

// Config configures the plugin; the zero value works.
type Config struct {
	// BaseURL is where Polaris is mounted, prefix included ("https://app.example.com/auth"): every
	// resource's meta.location and a connection's scim_base_url derive from it. Default: the
	// issuer (Auth.Issuer) followed by Config.PathPrefix.
	BaseURL string
}

// Plugin is the SCIM plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg   Config
	g     *wiring.Graph
	base  string
	conns *Connections
	dir   *directory
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_scim_connection, polaris_scim_resource and
// polaris_scim_membership_provenance.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's 22 routes (declared in internal/apispec/api/scim).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(apispec.API, "api/scim")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// AuditNames adds the scim.* names to the audit plugin's catalog.
func (*Plugin) AuditNames() map[string]string { return auditNames }

// Init builds the plugin's services.
func (p *Plugin) Init(g *wiring.Graph) error {
	base := p.cfg.BaseURL
	if base == "" {
		base = strings.TrimRight(g.Auth().Issuer, "/") + "/" + strings.Trim(g.Config().PathPrefix, "/")
	}
	if !absoluteURL.MatchString(base) {
		return fmt.Errorf("scim: Config.BaseURL is %q: set it to the absolute http(s) URL where Polaris is mounted (\"https://app.example.com/auth\")", base)
	}
	p.g, p.base = g, strings.TrimRight(base, "/")
	p.conns = &Connections{db: g.DB(), pepper: g.Pepper(), clock: g.Clock()}
	res := &resources{db: g.DB(), clock: g.Clock()}
	p.dir = &directory{db: g.DB(), repos: g.Repos(), identity: g.Identity(), orgs: g.Orgs(), resources: res, events: g.Events(), clock: g.Clock(),
		domains: func() any { return g.Plugin("sso") }}
	return nil
}

// Connections is the connection service: create, rotate and decommission connections from code.
func (p *Plugin) Connections() *Connections { return p.conns }

// BaseURL is the SCIM base URL of a connection, the one its directory is configured with.
func (p *Plugin) BaseURL(connectionID string) string { return p.base + "/scim/v2/" + connectionID }

// Endpoints serves the 22 scim routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Middleware refuses an organization route outside the caller's active organization before
// core's permission check.
func (*Plugin) Middleware(*wiring.Graph) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{activeOrganization}
}

// Provisioned reports whether a directory of the organization created the account (its
// provenance row carries the account's own creation time, as owns reads it). The sso plugin asks
// it (found as g.Plugin("scim")): an organization's identity provider signs in the accounts its
// directory created.
func (p *Plugin) Provisioned(ctx context.Context, organizationID string, u model.User) (bool, error) {
	row, err := p.g.DB().FindOne(ctx, TableProvenance, store.Criteria{"organization_id": organizationID, "user_id": u.ID})
	if err != nil || row == nil {
		return false, err
	}
	created, _ := row.Time("created_at")
	return created.UTC().Truncate(time.Second).Equal(u.CreatedAt.UTC().Truncate(time.Second)), nil
}

// Of returns the scim plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}

// EraseUser implements wiring.UserEraser: an erased user's directory provenance, stored name
// parts and user mappings go with the account, in its transaction.
func (p *Plugin) EraseUser(ctx context.Context, userID string) error {
	return maintenance.EraseUser(ctx, p.g.DB(), userID,
		maintenance.UserRows{Table: TableProvenance, Column: "user_id"},
		maintenance.UserRows{Table: TableUserNames, Column: "user_id"},
		maintenance.UserRows{Table: TableResources, Column: "local_id", Where: store.Criteria{"kind": KindUser}})
}
