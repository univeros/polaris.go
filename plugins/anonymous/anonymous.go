// Package anonymous is the guest-session plugin (port of polaris/anonymous): a visitor gets a
// session before having an account, and once they sign up or in by any method the guest is
// converted into that account through a host hook that moves what the host kept under the guest's
// id. Guests nobody converted are pruned.
//
//	guests := anonymous.New(anonymous.Config{
//		OnConvert: func(ctx context.Context, guestID, userID string) error {
//			return carts.Reassign(ctx, guestID, userID)
//		},
//	})
//	p, err := polaris.New(polaris.Config{..., Plugins: []polaris.Plugin{guests}})
//	// cron: n, err := guests.Prune(ctx)
//
// POST /anonymous/sign-in creates a core user with the placeholder email <id>@anonymous.invalid
// (RFC 2606), no password, no organization, and answers core's login envelope (201) with
// amr ["anonymous"]. POST /anonymous/convert, with the guest's bearer and the new account's
// access_token in the body, runs OnConvert, then records the conversion, ends the guest's
// sessions and disables it; its id stays for the host's data.
package anonymous

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"time"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/upstream"
	"github.com/univeros/polaris-go/wiring"
)

// ID is the plugin id; its routes read polaris.anonymous.*.
const ID = "anonymous"

// TableGuests is the table the plugin owns: which core users are guests, and the account each was
// converted into.
const TableGuests = "polaris_anonymous"

// DefaultPruneAfter is how old an unconverted guest gets before Prune deletes it.
const DefaultPruneAfter = 30 * 24 * time.Hour

// SentinelRoutes is the sign-in route for the sentinel plugin's guarded routes (path to attempt
// kind): a guest is judged as a sign-up.
var SentinelRoutes = map[string]string{"/anonymous/sign-in": "sign_up"}

// Refusals of Convert, matched with errors.Is.
var (
	// ErrNotAGuest: the caller is not a guest still waiting to be converted.
	ErrNotAGuest = errors.New("anonymous: not a guest")
	// ErrTokenInvalid: the access token is not a live session of another, real account.
	ErrTokenInvalid = errors.New("anonymous: the access token is not a live session of another account")
)

// Config configures the plugin; the zero value is upstream's defaults.
type Config struct {
	// OnConvert moves the host's data from the guest to the account it became. It runs before
	// anything is recorded: an error converts nothing and the guest can retry. nil: nothing to move.
	OnConvert func(ctx context.Context, guestID, userID string) error
	// PruneAfter is the age past which Prune deletes an unconverted guest; zero: 30 days. It must
	// be at least a day.
	PruneAfter time.Duration
}

// Plugin is the anonymous plugin. Its service exists once polaris.New has run.
type Plugin struct {
	cfg    Config
	guests *Guests
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// Of returns the anonymous plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_anonymous.
func (*Plugin) Schema() []schema.Model { return Models() }

// Models returns polaris_anonymous as upstream declares it.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableGuests,
			schema.StringField("userId", 36).AsPrimary(),
			schema.DateTimeField("createdAt"),
			schema.DateTimeField("convertedAt").AsNullable(),
			schema.StringField("convertedUserId", 36).AsNullable(),
		).Index([]string{"created_at"}, "polaris_anonymous_created_index"),
	}
}

// Manifest returns the plugin's routes (upstream api/anonymous).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(upstream.API, "api/anonymous")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// Init builds the guest service.
func (p *Plugin) Init(g *wiring.Graph) error {
	pruneAfter := p.cfg.PruneAfter
	switch {
	case pruneAfter == 0:
		pruneAfter = DefaultPruneAfter
	case pruneAfter < 24*time.Hour:
		return fmt.Errorf("anonymous: Config.PruneAfter is %s, want at least 24h (0 means %s)", pruneAfter, DefaultPruneAfter)
	}
	p.guests = &Guests{g: g, onConvert: p.cfg.OnConvert, pruneAfter: pruneAfter}
	return nil
}

// Guests is the guest service.
func (p *Plugin) Guests() *Guests { return p.guests }

// Prune deletes the unconverted guests older than Config.PruneAfter; see Guests.Prune. Run it from
// cron (upstream's `polaris anonymous:prune`).
func (p *Plugin) Prune(ctx context.Context) (int, error) { return p.guests.Prune(ctx) }

// Endpoints serves the /anonymous routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}
