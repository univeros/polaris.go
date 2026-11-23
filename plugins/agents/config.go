package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris.go/endpoint"
)

// Risk tiers of a capability: they decide the approval strength and the auto-approval.
const (
	RiskLow    = "low"
	RiskMedium = "medium"
	RiskHigh   = "high"
)

// Approval strengths: what the deciding session must be.
const (
	StrengthSession = "session" // any session of the owner
	StrengthStepUp  = "step_up" // core's step-up freshness
	StrengthPasskey = "passkey" // a recent passkey sign-in
)

var (
	risks     = []string{RiskLow, RiskMedium, RiskHigh}
	strengths = []string{StrengthSession, StrengthStepUp, StrengthPasskey}

	capabilityName  = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,79}$`)
	permissionName  = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,79}$`)
	locationFormat  = regexp.MustCompile(`^https?://[^\s?#]+$`)
	baseURLFormat   = regexp.MustCompile(`^https?://[^/\s]+`)
	pageURLFormat   = regexp.MustCompile(`^https?://[^\s?]+$`)
	defaultStrength = map[string]string{RiskLow: StrengthSession, RiskMedium: StrengthSession, RiskHigh: StrengthStepUp}
)

// Handler runs a capability executed at POST /agents/execute (or as an MCP tool). Its result is
// answered as the response's data. It runs inside the execution's transaction (ctx carries it):
// returning an error rolls back the budget spent and leaves no receipt; an *Error is answered as
// its problem, any other error as a 500.
type Handler func(ctx context.Context, call Call) (any, error)

// Call is what a capability handler, or a host route behind Protect, is told about the execution
// it runs in: the agent, the grant it runs under (its remaining budget already charged), the
// capability and the arguments.
type Call struct {
	Agent      Agent
	Grant      Grant
	Capability string
	Arguments  map[string]any
	InputHash  string
}

// Capability is something agents may ask to do: the permission its owner must hold, its risk tier,
// the JSON Schema of its arguments, and where it runs: a Handler (POST /agents/execute and MCP), or
// a Location, a host URL guarded by Plugin.Protect or Plugin.Guard. Exactly one of the two.
type Capability struct {
	Name        string         // lower case, starts with a letter, at most 80 characters
	Description string         // at most 500 characters
	Input       map[string]any // JSON Schema of the arguments; nil: any object
	Permission  string         // a permission name, such as "billing.refund"
	Risk        string         // RiskLow, RiskMedium (default) or RiskHigh
	Location    string         // absolute http(s) URL without a query
	Handler     Handler
}

// OperatorFunc authorizes an operator route (/admin/agents): capability is "read" or "own",
// organizationID the agent's ("" for an instance-wide action). It returns the operator's user id
// ("" for an operator API key), or ok false and the problem to answer. The admin plugin's
// AuthorizeOperator method has this shape and is used by default when admin is registered.
type OperatorFunc func(ctx context.Context, capability, organizationID string) (userID string, refusal endpoint.Result, ok bool)

// Config configures the plugin. Only Capabilities matter for most hosts; every other field's zero
// value is its default.
type Config struct {
	Capabilities []Capability
	// BaseURL is where Polaris is mounted ("https://app.example/auth"); the discovery document's
	// endpoints derive from it. Default: the oauth plugin's base URL.
	BaseURL string
	// ApprovalURL is the host's approval page, where a person types a user code. Empty: approvals
	// default to in_app and point at GET /agents/approvals/code.
	ApprovalURL string
	// AutoApprove maps a risk tier to the budget a grant gets when the policy approves it without a
	// person (the owner must hold the permission; an asked budget wider than this one waits for a
	// person). A zero Budget approves with no budget. nil: low risk, 100 executions; an empty map
	// turns auto-approval off.
	AutoApprove map[string]Budget
	// Strengths maps a risk tier to the approval strength it needs; unset tiers keep the default
	// (low and medium: session, high: step_up).
	Strengths map[string]string
	// ApprovalTTL is how long an approval waits; default 10 min.
	ApprovalTTL time.Duration
	// ProviderName and Description are what the discovery document says. Default "Polaris" and
	// "Polaris for Go agent provider".
	ProviderName, Description string
	// RequestJWTMaxAge bounds exp - iat of a request JWT; default and maximum 5 min.
	RequestJWTMaxAge time.Duration
	// Operators authorizes /admin/agents. Default: the admin plugin when registered; without it
	// nobody is an operator (401 admin/unauthorized).
	Operators OperatorFunc
	// MaxBodyBytes bounds the body Protect and Guard read (the arguments and the JWT's body hash);
	// a larger one is answered 413 agents/payload_too_large. Default 1 MiB. Polaris's own routes
	// are bounded by the pipeline (polaris.Config.MaxBodyBytes).
	MaxBodyBytes int64
}

// defaultMaxBodyBytes is Config.MaxBodyBytes when unset: 1 MiB.
const defaultMaxBodyBytes = 1 << 20

// settings is the validated configuration.
type settings struct {
	baseURL, approvalURL      string
	autoApprove               map[string]*budget // nil value: approve without a budget
	strengths                 map[string]string
	approvalTTL               int64
	providerName, description string
	maxAge                    int64
	operators                 OperatorFunc
	maxBody                   int64
}

func (s settings) strengthFor(risk string) string {
	if st, ok := s.strengths[risk]; ok {
		return st
	}
	return StrengthStepUp
}

func (cfg Config) resolve() (settings, *capabilities, error) {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf("agents: "+format, args...)) }
	s := settings{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"), approvalURL: strings.TrimRight(cfg.ApprovalURL, "/"),
		providerName: cfg.ProviderName, description: cfg.Description, operators: cfg.Operators,
		approvalTTL: 600, maxAge: 300, strengths: map[string]string{}, maxBody: defaultMaxBodyBytes,
	}
	if cfg.MaxBodyBytes < 0 {
		bad("Config.MaxBodyBytes must be positive (0 means 1 MiB), got %d", cfg.MaxBodyBytes)
	} else if cfg.MaxBodyBytes > 0 {
		s.maxBody = cfg.MaxBodyBytes
	}
	if cfg.BaseURL != "" && !baseURLFormat.MatchString(cfg.BaseURL) {
		bad("Config.BaseURL %q must be an absolute http(s) URL, where Polaris is mounted", cfg.BaseURL)
	}
	if cfg.ApprovalURL != "" && !pageURLFormat.MatchString(cfg.ApprovalURL) {
		bad("Config.ApprovalURL %q must be an absolute http(s) URL without a query", cfg.ApprovalURL)
	}
	if s.providerName == "" {
		s.providerName = "Polaris"
	}
	if s.description == "" {
		s.description = "Polaris for Go agent provider"
	}
	auto := cfg.AutoApprove
	if auto == nil {
		auto = map[string]Budget{RiskLow: {Count: 100}}
	}
	s.autoApprove = map[string]*budget{}
	for risk, b := range auto {
		if !slices.Contains(risks, risk) {
			bad("Config.AutoApprove: %q is not a risk tier (low, medium, high)", risk)
			continue
		}
		if b == (Budget{}) {
			s.autoApprove[risk] = nil
			continue
		}
		parsed, err := b.parse()
		if err != nil {
			detail := err.Error()
			if e, ok := errors.AsType[*Error](err); ok {
				detail = e.Detail
			}
			bad("Config.AutoApprove[%q]: %s", risk, detail)
			continue
		}
		s.autoApprove[risk] = parsed
	}
	for risk, st := range defaultStrength {
		s.strengths[risk] = st
	}
	for risk, st := range cfg.Strengths {
		if !slices.Contains(risks, risk) || !slices.Contains(strengths, st) {
			bad("Config.Strengths maps a risk tier (low, medium, high) to session, step_up or passkey, got %q: %q", risk, st)
			continue
		}
		s.strengths[risk] = st
	}
	if cfg.ApprovalTTL != 0 {
		if cfg.ApprovalTTL < time.Second || cfg.ApprovalTTL%time.Second != 0 {
			bad("Config.ApprovalTTL must be a whole number of seconds, at least one, got %s", cfg.ApprovalTTL)
		}
		s.approvalTTL = int64(cfg.ApprovalTTL / time.Second)
	}
	if cfg.RequestJWTMaxAge != 0 {
		if cfg.RequestJWTMaxAge < time.Second || cfg.RequestJWTMaxAge > 5*time.Minute || cfg.RequestJWTMaxAge%time.Second != 0 {
			bad("Config.RequestJWTMaxAge must be whole seconds between 1 s and 5 min, got %s", cfg.RequestJWTMaxAge)
		}
		s.maxAge = int64(cfg.RequestJWTMaxAge / time.Second)
	}
	caps, err := newCapabilities(cfg.Capabilities)
	if err != nil {
		errs = append(errs, err)
	}
	return s, caps, errors.Join(errs...)
}

// capabilities are the configured capabilities, by name and by normalised location.
type capabilities struct {
	list       []*Capability
	byName     map[string]*Capability
	byLocation map[string]*Capability
	byPath     map[string][]*Capability // the locations' paths (decodedPath), whatever their host
}

func newCapabilities(list []Capability) (*capabilities, error) {
	c := &capabilities{byName: map[string]*Capability{}, byLocation: map[string]*Capability{}, byPath: map[string][]*Capability{}}
	var errs []error
	for i := range list {
		capability := list[i]
		if err := capability.check(); err != nil {
			errs = append(errs, err)
			continue
		}
		if c.byName[capability.Name] != nil {
			errs = append(errs, fmt.Errorf("agents: capability %q is declared twice", capability.Name))
			continue
		}
		if capability.Location != "" {
			route := routeOf(capability.Location)
			if c.byLocation[route] != nil {
				errs = append(errs, fmt.Errorf("agents: two capabilities share the location %s", route))
				continue
			}
			c.byLocation[route] = &capability
			_, path, _ := strings.Cut(route, "/")
			c.byPath[decodedPath(path)] = append(c.byPath[decodedPath(path)], &capability)
		}
		c.byName[capability.Name] = &capability
		c.list = append(c.list, &capability)
	}
	return c, errors.Join(errs...)
}

// check validates the capability and puts its schema in decoded-JSON form.
func (c *Capability) check() error {
	bad := func(format string, args ...any) error {
		return fmt.Errorf("agents: capability %q: "+format, append([]any{c.Name}, args...)...)
	}
	if !capabilityName.MatchString(c.Name) {
		return fmt.Errorf("agents: a capability name is lower case, starts with a letter and is at most 80 characters (%q)", c.Name)
	}
	if c.Description == "" || utf8.RuneCountInString(c.Description) > 500 {
		return bad("needs a Description of at most 500 characters")
	}
	if !permissionName.MatchString(c.Permission) {
		return bad("Permission is a catalog name such as \"billing.refund\"")
	}
	if c.Risk == "" {
		c.Risk = RiskMedium
	}
	if !slices.Contains(risks, c.Risk) {
		return bad("Risk is agents.RiskLow, RiskMedium or RiskHigh")
	}
	if c.Location != "" && !locationFormat.MatchString(c.Location) {
		return bad("Location is an absolute http(s) URL without a query")
	}
	if (c.Location == "") == (c.Handler == nil) {
		return bad("needs exactly one of a Location or a Handler")
	}
	input := c.Input
	if input == nil {
		input = map[string]any{"type": "object"}
	}
	raw, err := json.Marshal(input)
	if err != nil {
		return bad("Input is not JSON: %v", err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var decoded map[string]any
	if err := dec.Decode(&decoded); err != nil {
		return bad("Input is not a JSON Schema object")
	}
	if err := checkSchema(decoded, "#"); err != nil {
		return bad("%v", err)
	}
	c.Input = decoded
	return nil
}

func (c *capabilities) find(name string) *Capability { return c.byName[name] }

// at is the capability whose location the request calls at url, whatever its spelling or scheme. The
// client writes the Host header, so one that no location on the path names does not take the request
// out of the guard: the capability is the path's. ambiguous: several hosts' locations share the path
// and the request names none of them.
func (c *capabilities) at(r *http.Request, url string) (capability *Capability, ambiguous bool) {
	if found := c.byLocation[routeOf(url)]; found != nil {
		return found, false
	}
	// Decoded whole, as a router may: an escaped character is the character, a slash included.
	var on []*Capability
	for _, path := range []string{decodedPath(requestPath(r)), decodedPath(r.URL.EscapedPath())} {
		for _, found := range c.byPath[path] {
			if !slices.Contains(on, found) {
				on = append(on, found)
			}
		}
	}
	switch len(on) {
	case 0:
		return nil, false
	case 1:
		return on[0], false
	}
	return nil, true
}

// permissions are the permissions the capabilities require, for the catalog.
func (c *capabilities) permissions() map[string]string {
	out := map[string]string{}
	for _, capability := range c.list {
		if _, ok := out[capability.Permission]; !ok {
			out[capability.Permission] = fmt.Sprintf("Required by the agent capability %q", capability.Name)
		}
	}
	return out
}

// view is the capability as GET /agents/capabilities shows it.
func (c *Capability) view() map[string]any {
	out := map[string]any{"name": c.Name, "description": c.Description, "input": c.Input, "permission": c.Permission, "risk": c.Risk}
	if c.Location != "" {
		out["location"] = c.Location
	}
	return out
}
