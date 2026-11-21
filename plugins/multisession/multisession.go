// Package multisession is the multi-session plugin: several accounts
// signed in on one device (one browser), a switch between them without signing in again, signing
// one out, and the device's last sign-in method for the client to pre-select its button.
//
//	p, err := polaris.New(polaris.Config{
//		Secrets: secrets, Auth: auth, DB: db,
//		Plugins: []polaris.Plugin{multisession.New(multisession.Config{})},
//	})
//
// Every response of a Polaris route that opens or refreshes a session (any sign-in method, a
// refresh, a switch) is recorded against the device, which the server mints and answers in the
// X-Polaris-Device header and the HttpOnly cookie polaris_ms_device; the client sends either back.
// Only ids the server minted are accepted, and a sign-in that joins a device with accounts rotates
// its id, so an id planted in a victim's browser never names the device the victim signs into.
//
// Routes: GET /multi-session/list, POST /multi-session/switch, DELETE /multi-session/{sessionId}
// (bearer, whose session must be on the device) and GET /multi-session/last-method (public).
package multisession

import (
	"io/fs"
	"net/http"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.multi-session.*.
const ID = "multi-session"

// The device travels in this header and, unless Config.DisableCookie, this HttpOnly cookie.
const (
	Header = "X-Polaris-Device"
	Cookie = "polaris_ms_device"
)

// TableDevices is the table the plugin owns: one row per device and account.
const TableDevices = "polaris_multi_session_device"

// Models returns polaris_multi_session_device as upstream declares it.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableDevices,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("deviceId", 64),
			schema.StringField("userId", 36),
			schema.StringField("sessionId", 36),
			schema.StringField("lastMethod", 32),
			schema.StringField("signInId", 36),
			schema.DateTimeField("signedInAt"),
			schema.DateTimeField("lastSeen"),
		).
			Unique([]string{"device_id", "user_id"}, "polaris_multi_session_device_unique").
			Index([]string{"session_id"}, "polaris_multi_session_device_session_index"),
	}
}

// Config configures the plugin; the zero value is upstream's defaults.
type Config struct {
	// DisableCookie stops setting the polaris_ms_device cookie; the device then travels in the
	// X-Polaris-Device header only.
	DisableCookie bool
}

// Plugin is the multi-session plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg     Config
	g       *wiring.Graph
	devices *devices
}

// New returns the plugin.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_multi_session_device.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's routes (upstream api/multi-session).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(apispec.API, "api/multi-session")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// Init builds the device service.
func (p *Plugin) Init(g *wiring.Graph) error {
	p.g = g
	p.devices = &devices{db: g.DB(), repos: g.Repos(), sessions: g.Sessions(), principals: g.Principals(), clock: g.Clock()}
	return nil
}

// Endpoints serves the /multi-session routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Middleware tracks the device on every Polaris route.
func (p *Plugin) Middleware(*wiring.Graph) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{p.middleware}
}
