package manifest

// Auth is how a route authenticates its caller (endpoint.auth).
type Auth string

// The values of endpoint.auth.
const (
	AuthPublic   Auth = "public"
	AuthBearer   Auth = "bearer"
	AuthMfaToken Auth = "mfa_token" // the login_mfa ticket /auth/login returns
)

// Effect is what a route does to state (endpoint.effect).
type Effect string

// The values of endpoint.effect.
const (
	EffectRead        Effect = "read"
	EffectWrite       Effect = "write"
	EffectDestructive Effect = "destructive"
)

// Source is where a route's input fields come from (input.source).
type Source string

// The values of input.source.
const (
	SourceBody  Source = "body"
	SourcePath  Source = "path"
	SourceQuery Source = "query"
	SourceNone  Source = "none"
)

// Session is what a route does to the caller's session (endpoint.session); cookie token delivery
// follows it.
type Session string

// The values of endpoint.session.
const (
	SessionIssue   Session = "issue"
	SessionRefresh Session = "refresh"
	SessionEnd     Session = "end"
)

// The accepted values, in the order api/core/schema.json lists them.
var (
	Auths    = []Auth{AuthPublic, AuthBearer, AuthMfaToken}
	Effects  = []Effect{EffectRead, EffectWrite, EffectDestructive}
	Sources  = []Source{SourceBody, SourcePath, SourceQuery, SourceNone}
	Sessions = []Session{SessionIssue, SessionRefresh, SessionEnd}
)

// Route is one api/**/*.yaml spec: the route, its policy, its input and its documented output.
// A Route returned by a [Manifest] is shared and must not be modified.
type Route struct {
	// Name is the route name derived from the spec's file ("auth/login.yaml" is
	// "polaris.auth.login"); endpoints register under it.
	Name string
	// File is the spec's path inside the directory it was loaded from.
	File string
	// Plugin is the id of the plugin that declares the route (the first segment of File), "" for core.
	Plugin string

	Method  string // upper case
	Path    string // with {param} placeholders, as net/http patterns use them
	Summary string
	Tags    []string
	Auth    Auth
	// RateLimit is the rate-limit group (endpoint.rate_limit), "" for none.
	RateLimit string
	Effect    Effect
	// Receipt is endpoint.receipt, defaulting to true for every effect but read.
	Receipt bool
	StepUp  bool
	// Session is "" when the route leaves the caller's session alone.
	Session             Session
	RequiresPermissions []string

	Input Input

	// Class is domain.class, the PHP endpoint class. Go does not dispatch on it; it only feeds the
	// exports (OpenAPI operationId, the JSON manifest).
	Class       string
	Description string // domain.description

	Output Output
	Errors []Error
	Events []string
}

// Input is a route's input section.
type Input struct {
	Source Source
	Fields []Field // in declaration order
}

// Field is one input field.
type Field struct {
	Name string
	// Type is the declared type as written ("string", "?list<string>", "object", ...); "string"
	// when absent.
	Type      string
	Rules     []Rule
	Sensitive bool
}

// Output is a route's documented success response.
type Output struct {
	// Status is output.status, 0 when unset (200 is meant).
	Status int
	// Examples are output.example and every output.example_<variant>, in file order.
	Examples []Example
}

// Example is one documented response body: an [Object] or a []any, holding strings, ints,
// float64s, bools, nils, Objects and []anys.
type Example struct {
	Key   string
	Value any
}

// Error is one documented error response.
type Error struct {
	Status int
	// Code is the body's error code, "" for a codeless body.
	Code string
}

// Pattern returns "METHOD /path", the route's identity, in net/http.ServeMux pattern syntax.
func (r *Route) Pattern() string {
	return r.Method + " " + r.Path
}

// Example returns the example under key ("example", "example_mfa_required").
func (r *Route) Example(key string) (any, bool) {
	for _, e := range r.Output.Examples {
		if e.Key == key {
			return e.Value, true
		}
	}
	return nil, false
}

// Validate checks data, the decoded request input, against the route's field rules; see [Validate].
func (r *Route) Validate(data map[string]any) error {
	return Validate(r.Input.Fields, data)
}
