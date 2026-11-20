// Package passkey is the passkey plugin (port of polaris/passkey): WebAuthn registration from a
// session, discoverable sign-in with conditional UI (the browser offers the user's passkeys,
// autofill included) ending in core's login envelope with amr ["passkey"], naming and removal;
// and, by default, every passkey is also a core MFA factor of type "passkey", verified through
// core's own /auth/mfa/verify and /auth/mfa/step-up with the assertion JSON as the code.
//
//	pk := passkey.New(passkey.Config{Origins: []string{"https://app.example.com"}, RPName: "App"})
//	p, err := polaris.New(polaris.Config{…, Plugins: []polaris.Plugin{pk}})
//
// The relying party id (the domain passkeys are bound to) is the first origin's host unless RPID
// says otherwise. An assertion whose authenticator verified the user (UV) is two factors in one:
// the session carries mfa true and core's MFA gate is skipped; without UV the gate applies.
package passkey

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/upstream"
	"github.com/univeros/polaris.go/mfa"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.passkey.*.
const ID = "passkey"

// FactorType is the auth_mfa_factors.type of the factors passkeys back.
const FactorType = "passkey"

// User verification requirements (Config.UserVerification).
const (
	UVRequired    = "required"
	UVPreferred   = "preferred"
	UVDiscouraged = "discouraged"
)

// Defaults.
const (
	DefaultRPName       = "Polaris"
	DefaultTimeout      = time.Minute
	DefaultChallengeTTL = 5 * time.Minute
)

// Config configures the plugin. Origins is required; every other field's zero value is
// upstream's default.
type Config struct {
	// Origins are the exact origins the browser pages live on ("https://app.example.com"); a plain
	// http origin is accepted on localhost and 127.0.0.1 only.
	Origins []string
	// RPID is the relying party id, the domain passkeys are bound to; default the first origin's
	// host. A parent domain covers its subdomains.
	RPID string
	// RPName is what the authenticator shows; default "Polaris".
	RPName string
	// NoMFAFactor keeps passkeys out of core's MFA (by default each one is also a confirmed factor).
	NoMFAFactor bool
	// UserVerification is UVRequired, UVPreferred (default) or UVDiscouraged.
	UserVerification string
	// Attachment is "platform", "cross-platform" or "" for no preference.
	Attachment string
	// Timeout is the browser's ceremony timeout; default one minute.
	Timeout time.Duration
	// ChallengeTTL is how long a challenge waits in the cache; default five minutes.
	ChallengeTTL time.Duration
}

type settings struct {
	origins          []string
	rpID, rpName     string
	mfaFactor        bool
	userVerification string
	attachment       string
	timeout          time.Duration
	challengeTTL     time.Duration
}

var originPattern = regexp.MustCompile(`^https?://[^/]+$`)

func (c Config) settings() (settings, error) {
	var errs []error
	s := settings{rpID: c.RPID, rpName: c.RPName, mfaFactor: !c.NoMFAFactor, userVerification: c.UserVerification,
		attachment: c.Attachment, timeout: c.Timeout, challengeTTL: c.ChallengeTTL}
	for _, o := range c.Origins {
		o = strings.TrimRight(o, "/")
		u, err := url.Parse(o)
		if !originPattern.MatchString(o) || err != nil {
			errs = append(errs, fmt.Errorf("passkey: Config.Origins: %q is not an origin: pass scheme://host[:port] without a path, such as https://app.example.com", o))
			continue
		}
		if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
			errs = append(errs, fmt.Errorf("passkey: Config.Origins: %q is plain http: passkeys need https outside localhost", o))
			continue
		}
		s.origins = append(s.origins, o)
	}
	if len(c.Origins) == 0 {
		errs = append(errs, errors.New("passkey: Config.Origins is empty: pass the origins your pages live on, such as https://app.example.com"))
	}
	if s.rpID == "" && len(s.origins) > 0 {
		u, _ := url.Parse(s.origins[0])
		s.rpID = u.Hostname()
	}
	if s.rpName == "" {
		s.rpName = DefaultRPName
	}
	if s.userVerification == "" {
		s.userVerification = UVPreferred
	}
	if !slices.Contains([]string{UVRequired, UVPreferred, UVDiscouraged}, s.userVerification) {
		errs = append(errs, fmt.Errorf("passkey: Config.UserVerification is %q: use required, preferred or discouraged", c.UserVerification))
	}
	if s.attachment != "" && s.attachment != "platform" && s.attachment != "cross-platform" {
		errs = append(errs, fmt.Errorf("passkey: Config.Attachment is %q: use platform, cross-platform or empty", c.Attachment))
	}
	if s.timeout == 0 {
		s.timeout = DefaultTimeout
	}
	if s.challengeTTL == 0 {
		s.challengeTTL = DefaultChallengeTTL
	}
	if s.timeout < 0 || s.challengeTTL < 0 {
		errs = append(errs, errors.New("passkey: Config.Timeout and Config.ChallengeTTL must be positive (zero means the default)"))
	}
	return s, errors.Join(errs...)
}

// Plugin is the passkey plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg      Config
	settings settings
	g        *wiring.Graph
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_passkey.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's routes (upstream api/passkey).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(upstream.API, "api/passkey")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// MFAFactorTypes registers the passkey factor type with core (unless Config.NoMFAFactor).
func (p *Plugin) MFAFactorTypes() []mfa.FactorType {
	if p.cfg.NoMFAFactor {
		return nil
	}
	return []mfa.FactorType{factor{p}}
}

// Init validates the configuration.
func (p *Plugin) Init(g *wiring.Graph) error {
	s, err := p.cfg.settings()
	p.settings, p.g = s, g
	return err
}

// Endpoints serves the /passkey routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Listeners keep a passkey as a sign-in credential when core removes its factor, and erase an
// erased user's passkeys.
func (p *Plugin) Listeners(*wiring.Graph) []event.Listener {
	return []event.Listener{func(ctx context.Context, e event.Event) {
		var err error
		switch e := e.(type) {
		case event.MFAFactorRemoved:
			err = p.detachFactor(ctx, e.FactorID)
		case event.UserDeleted:
			err = p.deleteForUser(ctx, e.UserID)
		default:
			return
		}
		if err != nil {
			p.g.Logger().ErrorContext(ctx, "passkey: listener failed", "event", e.EventName(), "reason", err.Error())
		}
	}}
}
