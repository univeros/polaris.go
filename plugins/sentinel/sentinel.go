// Package sentinel is the sentinel plugin: a local risk engine in front
// of sign-up, sign-in, password reset and code sends. Signals score each attempt (velocity,
// credential stuffing, IP rules, devices, disposable domains and, with a provider, captcha,
// impossible travel and breached passwords); a policy allows, challenges or blocks; observe mode
// (the default) records without enforcing, so an instance tunes on its own decisions first.
//
//	p, err := polaris.New(polaris.Config{
//		Secrets: secrets, Auth: auth, DB: db,
//		Plugins: []polaris.Plugin{audit.New(audit.Config{}), admin.New(admin.Config{}), sentinel.New(sentinel.Config{
//			Mode:    sentinel.Enforce,
//			Captcha: sentinel.Turnstile(os.Getenv("TURNSTILE_SECRET")),
//		})},
//	})
//
// In enforce mode a block answers 403 sentinel/blocked and, with a Captcha verifier, a challenge
// answers 403 sentinel/challenge_required ("challenge": "captcha"): the client retries the same
// request with the captcha_token it obtained. Without a verifier nothing can answer a challenge,
// so the challenge band is recorded and let through.
//
// Every decision where a signal spoke is a polaris_sentinel_decision row and a sentinel.evaluated
// event; operators list them and manage IP rules under /admin/sentinel (admin plugin principals).
// With the messaging plugin registered, a recipient challenged or blocked in the last hour gets no
// non-essential email (quiet mode).
package sentinel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/apispec"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/wiring"
)

// ID is the plugin id; its routes read polaris.sentinel.*.
const ID = "sentinel"

// Mode is observe (record what would happen) or enforce (answer blocks and challenges).
type Mode string

// The modes.
const (
	Observe Mode = "observe"
	Enforce Mode = "enforce"
)

// QuietWindow is how long after a challenge or a block a recipient gets no non-essential email.
const QuietWindow = time.Hour

// Config configures the plugin; the zero value is the defaults (observe mode, the local
// signals, the bundled disposable-domain list).
type Config struct {
	// Mode is Observe (default) or Enforce.
	Mode Mode
	// Policy sets the score thresholds; zero means challenge from 40, block from 80.
	Policy Policy
	// Velocity bounds attempts per dimension ("ip", "email", "device"); nil means DefaultVelocity.
	// A dimension left out is not counted.
	Velocity map[string]Limit

	// Captcha verifies the captcha_token of a challenged retry (Turnstile, HCaptcha, your own).
	Captcha BotVerifier
	// Geo locates addresses for the impossible-travel signal; nil disables it (NoGeo).
	Geo GeoResolver
	// Breaches checks new passwords (security.HIBP{} for Have I Been Pwned); nil disables the
	// signal. When set it also serves core's breached-password port unless Config.Breaches is set.
	Breaches security.BreachedPasswordCheck

	// Domains replaces the disposable-domain list; nil means the bundled one, or the file
	// DisposableListFile names (one domain per line, # comments), plus DisposableDomains.
	Domains            DomainList
	DisposableDomains  []string
	DisposableListFile string

	// Counters count velocity and stuffing attempts; nil means NewCacheCounters on the graph's cache.
	Counters CounterStore
	// Routes are the guarded routes (manifest path => attempt kind); nil means DefaultRoutes.
	Routes map[string]string

	// Signals are the host's own, after the built-in ones; NoBuiltIn runs them alone.
	Signals   []Signal
	NoBuiltIn bool

	// HTTPClient fetches lists for RefreshDomainList; nil means http.DefaultClient.
	HTTPClient *http.Client
}

// Plugin is the sentinel plugin. Its services exist once polaris.New has run.
type Plugin struct {
	cfg       Config
	g         *wiring.Graph
	admin     *admin.Plugin
	engine    *Engine
	decisions *Decisions
	rules     *IPRules
	devices   *devices
	geo       GeoResolver
	stuffing  *stuffing
	routes    map[string]string
}

// New returns the plugin; configuration errors surface from polaris.New.
func New(cfg Config) *Plugin { return &Plugin{cfg: cfg} }

// ID implements wiring.Plugin.
func (*Plugin) ID() string { return ID }

// Schema declares polaris_sentinel_decision, polaris_sentinel_ip_rule and polaris_sentinel_device.
func (*Plugin) Schema() []schema.Model { return Models() }

// Manifest returns the plugin's routes (declared in internal/apispec/api/sentinel).
func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(apispec.API, "api/sentinel")
	if err != nil {
		panic(err) // the embedded tree is fixed at build time
	}
	return sub
}

// AuditNames adds the sentinel.* names to the audit plugin's catalog.
func (*Plugin) AuditNames() map[string]string { return auditNames }

// Ports serves core's breached-password port with Config.Breaches, when set.
func (p *Plugin) Ports() wiring.Ports { return wiring.Ports{Breaches: p.cfg.Breaches} }

// Init builds the engine; it fails when the admin plugin is not registered or the config is
// invalid.
func (p *Plugin) Init(g *wiring.Graph) error {
	c := p.cfg
	if c.Mode == "" {
		c.Mode = Observe
	}
	if c.Mode != Observe && c.Mode != Enforce {
		return fmt.Errorf("sentinel: Config.Mode is %q, want sentinel.Observe or sentinel.Enforce", c.Mode)
	}
	if p.admin = admin.Of(g); p.admin == nil {
		return errors.New("sentinel: the admin plugin is required (the operator routes use its principals): add admin.New(admin.Config{}) (and audit.New(audit.Config{})) to Config.Plugins")
	}
	if c.Velocity == nil {
		c.Velocity = DefaultVelocity
	}
	for dim, l := range c.Velocity {
		if l.Max < 1 || l.Window < time.Second {
			return fmt.Errorf("sentinel: Config.Velocity[%q] is %+v: want a Max ≥ 1 and a Window ≥ 1s", dim, l)
		}
	}
	domains, err := c.domains()
	if err != nil {
		return err
	}
	if c.Counters == nil {
		c.Counters = NewCacheCounters(g.Cache(), g.Clock())
	}
	p.routes = c.Routes
	if p.routes == nil {
		p.routes = DefaultRoutes
	}
	p.geo = c.Geo
	if p.geo == nil {
		p.geo = NoGeo{}
	}
	p.g, p.cfg = g, c
	p.decisions = &Decisions{db: g.DB(), clock: g.Clock()}
	p.rules = &IPRules{db: g.DB(), clock: g.Clock()}
	p.devices = &devices{db: g.DB(), clock: g.Clock()}
	p.stuffing = &stuffing{counters: c.Counters, seen: &seenSet{cache: g.Cache()}, window: 10 * time.Minute,
		distinctEmails: 5, minAttempts: 10, failureRatio: 0.8, score: 60}
	p.engine = &Engine{signals: p.signals(domains), policy: c.Policy, enforce: c.Mode == Enforce,
		decisions: p.decisions, events: g.Events(), logger: g.Logger()}
	return nil
}

func (c Config) domains() (DomainList, error) {
	if c.Domains != nil {
		return c.Domains, nil
	}
	var base DomainList = BundledDomains()
	if c.DisposableListFile != "" {
		f, err := os.Open(c.DisposableListFile)
		if err != nil {
			return nil, fmt.Errorf("sentinel: Config.DisposableListFile: %w (create it with RefreshDomainList, or leave it empty for the bundled list)", err)
		}
		defer f.Close()
		if base, err = ParseDomains(f); err != nil {
			return nil, fmt.Errorf("sentinel: Config.DisposableListFile: %w", err)
		}
	}
	extra, _ := ParseDomains(strings.NewReader(""), c.DisposableDomains...)
	return withExtra{base: base, extra: extra}, nil
}

func (p *Plugin) signals(domains DomainList) []Signal {
	c, g := p.cfg, p.g
	if c.NoBuiltIn {
		return c.Signals
	}
	s := []Signal{
		ipList{p.rules},
		velocity{counters: c.Counters, limits: c.Velocity, score: 50},
		p.stuffing,
		disposable{domains: domains, kinds: []string{SignUp}, score: 60},
		device{devices: p.devices, users: g.Repos().Users, score: 40},
	}
	if c.Captcha != nil {
		s = append(s, bot{verifier: c.Captcha, score: 80})
	}
	if c.Geo != nil {
		s = append(s, travel{geo: c.Geo, devices: p.devices, users: g.Repos().Users, clock: g.Clock(), maxKmh: 900, score: 70})
	}
	if c.Breaches != nil {
		s = append(s, breached{checker: c.Breaches, kinds: []string{SignUp, PasswordReset}, score: 50})
	}
	return append(s, c.Signals...)
}

// Endpoints serves the /admin/sentinel routes.
func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return p.endpoints(), nil
}

// Middleware judges the guarded routes before their endpoint runs.
func (p *Plugin) Middleware(*wiring.Graph) []func(http.Handler) http.Handler {
	return []func(http.Handler) http.Handler{p.guard}
}

// Listeners feed the outcomes the engine cannot see at attempt time: a failed sign-in counts for
// the credential-stuffing ratio; a sign-in records the device of the request with its address and
// location.
func (p *Plugin) Listeners(*wiring.Graph) []event.Listener {
	return []event.Listener{p.listen}
}

func (p *Plugin) listen(ctx context.Context, e event.Event) {
	var err error
	switch e := e.(type) {
	case event.UserLoginFailed:
		if e.IP != nil {
			err = p.stuffing.failed(ctx, *e.IP)
		}
	case event.UserLoggedIn:
		a, ok := attemptFrom(ctx)
		if !ok || a.DeviceID == "" {
			return
		}
		ip := ""
		var at *GeoPoint
		if e.IP != nil {
			ip = *e.IP
			if pt, ok := p.geo.Resolve(ctx, ip); ok {
				at = &pt
			}
		}
		err = p.devices.record(ctx, e.UserID, a.DeviceID, ip, at)
	}
	if err != nil {
		p.g.Logger().ErrorContext(ctx, "sentinel: listener failed", "event", e.EventName(), "error", err)
	}
}

// Engine is the risk engine (Evaluate, Unblock).
func (p *Plugin) Engine() *Engine { return p.engine }

// Decisions stores the recorded decisions.
func (p *Plugin) Decisions() *Decisions { return p.decisions }

// IPRules stores the operators' IP rules.
func (p *Plugin) IPRules() *IPRules { return p.rules }

// Mode is the configured mode.
func (p *Plugin) Mode() Mode { return p.cfg.Mode }

// Of returns the sentinel plugin registered on g, nil when absent.
func Of(g *wiring.Graph) *Plugin {
	p, _ := g.Plugin(ID).(*Plugin)
	return p
}

// QuietFor is quiet mode, which the messaging plugin takes when registered: true when kind is
// email and the recipient was challenged or blocked in the last QuietWindow. A failing store reads
// as false (the message goes).
func (p *Plugin) QuietFor(ctx context.Context, kind, recipient string) bool {
	if kind != "email" {
		return false
	}
	page, err := p.decisions.List(ctx, Filter{Email: strings.ToLower(recipient), Limit: 5})
	if err != nil {
		p.g.Logger().ErrorContext(ctx, "sentinel: quiet mode lookup failed", "error", err)
		return false
	}
	since := p.g.Clock().Now().Add(-QuietWindow)
	for _, d := range page["data"].([]map[string]any) {
		created, _ := time.Parse(dateAtom, d["created_at"].(string))
		if d["action"] != Allow && !created.Before(since) {
			return true
		}
	}
	return false
}

// RefreshDomainList fetches a disposable-domain list (one domain per line, # comments) from url
// and writes it to the file to ("" means Config.DisposableListFile), deduplicated and
// lower-cased; it answers the number of domains. Run it from a scheduled job or a deploy step
// (the CLI has no command for it). The running process keeps its list; the file is read at the
// next start.
func (p *Plugin) RefreshDomainList(ctx context.Context, url, to string) (int, error) {
	if url == "" {
		return 0, errors.New("sentinel: pass a URL: the list has no default source")
	}
	if to == "" {
		to = p.cfg.DisposableListFile
	}
	if to == "" {
		return 0, errors.New("sentinel: pass a file to write (or set Config.DisposableListFile): the bundled list is embedded")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("sentinel: %w", err)
	}
	client := p.cfg.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("sentinel: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("sentinel: %s answered HTTP %d", url, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return 0, fmt.Errorf("sentinel: %w", err)
	}
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if d := strings.ToLower(strings.TrimSpace(line)); d != "" && d[0] != '#' && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	content := fmt.Sprintf("# Disposable email domains, one per line. Source: %s.\n%s\n", url, strings.Join(out, "\n"))
	if err := os.WriteFile(to, []byte(content), 0o644); err != nil { //nolint:gosec // G306: a public domain list, meant to be read by the app and committed
		return 0, fmt.Errorf("sentinel: %w", err)
	}
	return len(out), nil
}
