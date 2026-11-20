package manifest

import (
	"encoding/json"
	"errors"
	"io/fs"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/univeros/polaris.go/internal/upstream"
)

// pluginDirs is every plugin manifest in upstream.API, in the order packages/client-ts/polaris.php
// registers the plugins (the order of the all.*.json goldens).
var pluginDirs = []string{"audit", "admin", "sentinel", "sso", "scim", "passwordless", "username", "anonymous", "multi-session", "social", "passkey", "api-keys", "oauth-provider", "mcp", "agents"}

func sub(t testing.TB, dir string) fs.FS {
	t.Helper()
	fsys, err := fs.Sub(upstream.API, "api/"+dir)
	if err != nil {
		t.Fatal(err)
	}
	return fsys
}

func loadCore(t testing.TB) *Manifest {
	t.Helper()
	m, err := Load(sub(t, "core"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func loadAll(t testing.TB) *Manifest {
	t.Helper()
	dirs := []fs.FS{sub(t, "core")}
	for _, dir := range pluginDirs {
		dirs = append(dirs, sub(t, dir))
	}
	m, err := Load(dirs...)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEveryUpstreamDirectoryIsAPluginOrCore(t *testing.T) {
	entries, err := fs.ReadDir(upstream.API, "api")
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.Name() != "core" {
			dirs = append(dirs, e.Name())
		}
	}
	want := slices.Clone(pluginDirs)
	sort.Strings(want)
	if !reflect.DeepEqual(dirs, want) {
		t.Fatalf("internal/upstream/api has %v, the tests load %v", dirs, want)
	}
	if n := len(loadAll(t).Routes()); n != 226 {
		t.Errorf("%d routes, want 226 (spec §2)", n)
	}
}

// Port of ManifestTest::testEverySpecShowsItsSuccessBody.
func TestEverySpecShowsItsSuccessBody(t *testing.T) {
	m := loadCore(t)
	for _, r := range m.Routes() {
		if _, ok := r.Example("example"); !ok {
			t.Errorf("%s: output.example types the response for the clients", r.File)
		}
		for _, e := range r.Output.Examples {
			if isEmpty(e.Value) {
				t.Errorf("%s: %s is empty", r.File, e.Key)
			}
		}
	}
	login, ok := m.Find("POST", "/auth/login")
	if !ok {
		t.Fatal("POST /auth/login missing")
	}
	var keys []string
	for _, e := range login.Output.Examples {
		keys = append(keys, e.Key)
	}
	if !reflect.DeepEqual(keys, []string{"example", "example_mfa_required"}) {
		t.Errorf("login examples %v", keys)
	}
	if _, ok := login.Example("example_nope"); ok {
		t.Error("unknown example found")
	}
}

// Port of ManifestTest::testEverySpecRoutesToAnEndpointAndEveryEndpointIsSpecified (the part Go can
// check: Go keys endpoints on route names, so the PHP class only has to be named and not shared).
func TestEverySpecNamesOneClass(t *testing.T) {
	m := loadCore(t)
	if n := len(m.Routes()); n != 52 {
		t.Fatalf("%d core routes, want 52", n)
	}
	count := map[string]int{}
	for _, r := range m.Routes() {
		if !strings.HasPrefix(r.Class, `Polaris\Http\`) || !strings.HasSuffix(r.Class, "Endpoint") {
			t.Errorf("%s: class %s", r.File, r.Class)
		}
		count[r.Class]++
	}
	for class, n := range count {
		if n > 1 && class != `Polaris\Http\Auth\OtpFactorConfirmEndpoint` {
			t.Errorf("%s is referenced by %d specs", class, n)
		}
	}
}

// Port of ManifestTest::testRoutesAreUniqueAndFindable, plus lookup by route name.
func TestRoutesAreUniqueAndFindable(t *testing.T) {
	m := loadAll(t)
	patterns := map[string]bool{}
	names := map[string]bool{}
	for _, r := range m.Routes() {
		if patterns[r.Pattern()] || names[r.Name] {
			t.Errorf("duplicate %s / %s", r.Pattern(), r.Name)
		}
		patterns[r.Pattern()], names[r.Name] = true, true
		if got, ok := m.Named(r.Name); !ok || got != r {
			t.Errorf("Named(%s)", r.Name)
		}
	}
	login, ok := m.Find("post", "/auth/login")
	if !ok || login.Class != `Polaris\Http\Auth\LoginEndpoint` || login.Name != "polaris.auth.login" || login.Plugin != "" || login.File != "auth/login.yaml" {
		t.Errorf("login = %+v", login)
	}
	if _, ok := m.Find("GET", "/nope"); ok {
		t.Error("GET /nope found")
	}
	if _, ok := m.Named("polaris.nope"); ok {
		t.Error("polaris.nope found")
	}
	me, ok := m.Named("polaris.audit.me")
	if !ok || me.Plugin != "audit" || me.File != "audit/me.yaml" {
		t.Errorf("audit me = %+v", me)
	}
	execute, ok := m.Named("polaris.agents.execute")
	if !ok || execute.Plugin != "agents" {
		t.Errorf("agents execute = %+v", execute)
	}
	if oauth, ok := m.Find("POST", "/oauth2/token"); !ok || oauth.Plugin != "oauth" {
		t.Errorf("oauth token = %+v", oauth)
	}
}

// Port of ManifestTest::testPolicyValuesAreKnown (rate-limit groups are checked where the rate
// limiter lives).
func TestPolicyValuesAreKnown(t *testing.T) {
	for _, r := range loadCore(t).Routes() {
		if !slices.Contains(Auths, r.Auth) || !slices.Contains(Effects, r.Effect) || !slices.Contains(Sources, r.Input.Source) {
			t.Errorf("%s: %s %s %s", r.File, r.Auth, r.Effect, r.Input.Source)
		}
		if r.Session != "" && !slices.Contains(Sessions, r.Session) {
			t.Errorf("%s: session %s", r.File, r.Session)
		}
		if r.Method != strings.ToUpper(r.Method) {
			t.Errorf("%s: method %s", r.File, r.Method)
		}
		if r.Receipt != (r.Effect != EffectRead) {
			t.Errorf("%s: receipt follows the effect unless overridden", r.File)
		}
		if r.Method == "GET" && r.Effect != EffectRead {
			t.Errorf("%s: GET is a read", r.File)
		}
	}
}

// Port of ManifestTest::testSchemaJsonAgreesWithTheLoader.
func TestSchemaJSONAgreesWithTheLoader(t *testing.T) {
	raw, err := fs.ReadFile(upstream.API, "api/core/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Required   []string `json:"required"`
		Properties struct {
			Endpoint struct {
				Required   []string `json:"required"`
				Properties struct {
					Auth    struct{ Enum []Auth }   `json:"auth"`
					Effect  struct{ Enum []Effect } `json:"effect"`
					Session struct{ Enum []Session }
				} `json:"properties"`
			} `json:"endpoint"`
			Input struct {
				Properties struct {
					Source struct{ Enum []Source } `json:"source"`
				} `json:"properties"`
			} `json:"input"`
			Domain struct {
				Required []string `json:"required"`
			} `json:"domain"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	p := schema.Properties
	if !reflect.DeepEqual(schema.Required, []string{"endpoint", "domain"}) ||
		!reflect.DeepEqual(p.Endpoint.Required, []string{"method", "path", "auth", "effect"}) ||
		!reflect.DeepEqual(p.Endpoint.Properties.Auth.Enum, Auths) ||
		!reflect.DeepEqual(p.Endpoint.Properties.Effect.Enum, Effects) ||
		!reflect.DeepEqual(p.Input.Properties.Source.Enum, Sources) ||
		!reflect.DeepEqual(p.Domain.Required, []string{"class"}) {
		t.Errorf("schema.json disagrees: %+v", schema)
	}
}

// Port of ManifestTest::testSpecFilesAreTheOnlyYamlUnderApi.
func TestSpecFilesAreTheOnlyYamlUnderCore(t *testing.T) {
	n := 0
	_ = fs.WalkDir(sub(t, "core"), ".", func(path string, d fs.DirEntry, err error) error {
		if strings.HasSuffix(path, ".yaml") {
			n++
		}
		return err
	})
	if n != 52 {
		t.Errorf("%d yaml files", n)
	}
}

// Ports of SessionCoverageTest.
func TestEveryRouteThatAnswersARefreshTokenIsMarked(t *testing.T) {
	exceptions := []string{"POST /oauth2/token"}
	var unmarked, seen []string
	for _, r := range loadAll(t).Routes() {
		if !answersRefreshToken(r) {
			continue
		}
		if slices.Contains(exceptions, r.Pattern()) {
			seen = append(seen, r.Pattern())
			if r.Session != "" {
				t.Errorf("%s is an exception and must stay unmarked", r.Pattern())
			}
			continue
		}
		if r.Session != SessionIssue && r.Session != SessionRefresh {
			unmarked = append(unmarked, r.Pattern())
		}
	}
	if len(unmarked) > 0 {
		t.Errorf("answer data.refresh_token without session: issue | refresh: %v", unmarked)
	}
	if !reflect.DeepEqual(seen, exceptions) {
		t.Errorf("every exception still exists: %v", seen)
	}
}

func TestTheMarkedRoutesAreTheOnesTheSpecNames(t *testing.T) {
	marked := map[Session][]string{}
	for _, r := range loadAll(t).Routes() {
		if r.Session != "" {
			marked[r.Session] = append(marked[r.Session], r.Pattern())
		}
	}
	for _, routes := range marked {
		sort.Strings(routes)
	}
	want := map[Session][]string{
		SessionIssue: {
			"POST /anonymous/sign-in",
			"POST /auth/login",
			"POST /auth/mfa/verify",
			"POST /email-otp/verify",
			"POST /magic-link/exchange",
			"POST /multi-session/switch",
			"POST /one-time-token/verify",
			"POST /passkey/authenticate/verify",
			"POST /phone/verify",
			"POST /social/exchange",
			"POST /social/google/one-tap",
			"POST /sso/exchange",
			"POST /username/sign-in",
		},
		SessionRefresh: {"POST /auth/token/refresh"},
		SessionEnd:     {"POST /auth/logout", "POST /auth/logout-all", "POST /sso/logout"},
	}
	if !reflect.DeepEqual(marked, want) {
		t.Errorf("marked = %v", marked)
	}
}

func answersRefreshToken(r *Route) bool {
	for _, e := range r.Output.Examples {
		example, ok := e.Value.(Object)
		if !ok {
			continue
		}
		if v, ok := example.Get("refresh_token"); ok && v != nil {
			return true
		}
		if data, ok := example.Get("data"); ok {
			if data, ok := data.(Object); ok {
				if v, ok := data.Get("refresh_token"); ok && v != nil {
					return true
				}
			}
		}
	}
	return false
}

func TestLoaderRejectsInvalidSpecs(t *testing.T) {
	const ok = "endpoint: { method: post, path: /x, auth: public, effect: write }\ndomain: { class: X }\n"
	cases := map[string]string{
		"endpoint: { method: POST, path: /x, auth: public, effect: write, session: open }\ndomain: { class: X }\n": `x.yaml: unknown session "open".`,
		"endpoint: { method: POST, path: /x, auth: public, effect: write, session: true }\ndomain: { class: X }\n": `x.yaml: unknown session "1".`,
		"endpoint: { method: POST, path: /x, auth: public, effect: write, session: [a] }\ndomain: { class: X }\n":  `x.yaml: unknown session "array".`,
		"- a\n":           `x.yaml: missing "endpoint" section.`,
		"just a string\n": `x.yaml is not a spec document.`,
		"endpoint: { method: POST, path: /x, auth: public, effect: write }\n":                        `x.yaml: missing "domain" section.`,
		"endpoint: { path: /x, auth: public, effect: write }\ndomain: { class: X }\n":                `x.yaml: "method" is required.`,
		"endpoint: { method: POST, path: '', auth: public, effect: write }\ndomain: { class: X }\n":  `x.yaml: "path" is required.`,
		"endpoint: { method: POST, path: /x, auth: basic, effect: write }\ndomain: { class: X }\n":   `x.yaml: unknown auth "basic".`,
		"endpoint: { method: POST, path: /x, auth: public, effect: delete }\ndomain: { class: X }\n": `x.yaml: unknown effect "delete".`,
		"endpoint: { method: POST, path: /x, auth: public, effect: write }\ndomain: { class: 1 }\n":  `x.yaml: "class" is required.`,
		ok + "input: { source: header }\n":                                                           `x.yaml: unknown input source "header".`,
		ok + "input: { source: body, fields: { a: string } }\n":                                      `x.yaml: field "a" must be a map.`,
		ok + "input: { source: body, fields: { a: { rules: [between] } } }\n":                        `x.yaml: field "a": Unknown validation rule "between".`,
		ok + "errors: [{ status: 400 }]\n":                                                           "",
		ok + "errors: [{ code: x }]\n":                                                               `x.yaml: every error needs a status and a code (null for a codeless body).`,
		ok + "errors: [{ status: 400, code: 1 }]\n":                                                  `x.yaml: every error needs a status and a code (null for a codeless body).`,
		ok + "errors: [nope]\n": `x.yaml: every error needs a status and a code (null for a codeless body).`,
		"endpoint: { method: POST, method: GET, path: /x, auth: public, effect: write }\ndomain: { class: X }\n": `x.yaml: line 1: mapping key "method" already defined`,
		"endpoint: [\n":   `x.yaml: yaml:`,
		"endpoint: *a\n":  `x.yaml: yaml:`,
		"":                `x.yaml is not a spec document.`,
		ok + "input: 3\n": "",
	}
	for doc, want := range cases {
		_, err := Load(fstest.MapFS{"x.yaml": {Data: []byte(doc)}})
		switch {
		case want == "" && err != nil:
			t.Errorf("%q: %v", doc, err)
		case want != "" && (err == nil || !strings.HasPrefix(err.Error(), want)):
			t.Errorf("%q: got %v, want %s", doc, err, want)
		}
	}
}

func TestLoaderRejectsDuplicateRoutesAndNames(t *testing.T) {
	spec := func(method, path string) *fstest.MapFile {
		return &fstest.MapFile{Data: []byte("endpoint: { method: " + method + ", path: " + path + ", auth: public, effect: write }\ndomain: { class: X }\n")}
	}
	core := fstest.MapFS{"a/b.yaml": spec("POST", "/x")}
	_, err := Load(core, fstest.MapFS{"p/c.yaml": spec("post", "/x")})
	if err == nil || err.Error() != "p/c.yaml declares route POST /x already declared by a/b.yaml." {
		t.Errorf("duplicate route: %v", err)
	}
	_, err = Load(core, fstest.MapFS{"a/b.yaml": spec("GET", "/y")})
	if err == nil || err.Error() != "a/b.yaml declares route name polaris.a.b already declared by a/b.yaml." {
		t.Errorf("duplicate name: %v", err)
	}
	if _, err := Load(); err == nil {
		t.Error("Load() without directories must fail")
	}
	if _, err := Load(fstest.MapFS{"a.yml": spec("GET", "/y"), "README.md": {Data: []byte("#")}}); err != nil {
		t.Errorf("non-yaml files are skipped: %v", err)
	}
	m, err := Load(fstest.MapFS{"z.yaml": spec("GET", "/z"), "a/b.yaml": spec("GET", "/b"), "a-b.yaml": spec("GET", "/ab")}, fstest.MapFS{"top.yaml": spec("GET", "/t")})
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, r := range m.Routes() {
		files = append(files, r.File)
	}
	if !reflect.DeepEqual(files, []string{"a-b.yaml", "a/b.yaml", "z.yaml", "top.yaml"}) {
		t.Errorf("file order %v", files)
	}
	if top, _ := m.Named("polaris.top"); top.Plugin != "top.yaml" {
		t.Errorf("a plugin file at the root is its own plugin id, as upstream: %q", top.Plugin)
	}
}

func TestLoaderReadsEveryKey(t *testing.T) {
	doc := `endpoint:
  method: post
  path: /things/{id}
  summary: Do a thing
  tags: [things, 3]
  auth: bearer
  rate_limit: token_consume
  effect: read
  receipt: 1
  step_up: yes please
  session: issue
  requires_permissions: [things.write]
input:
  source: body
  fields:
    name: { type: "?string", rules: [required, "max:3"], sensitive: 1 }
    other: {}
domain:
  class: 'Polaris\Things\DoEndpoint'
  description: Does the thing.
output:
  status: 201
  example: { data: { id: x } }
  example_other: [1, 2]
  example_scalar: 3
  examples: { ignored: true }
errors:
  - { status: 404, code: not_found }
  - { status: 500, code: null }
events: [thing.done]
`
	m, err := Load(fstest.MapFS{"things/do.yaml": {Data: []byte(doc)}})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := m.Named("polaris.things.do")
	name, _ := ParseRule("required")
	maxRule, _ := ParseRule("max:3")
	want := &Route{
		Name: "polaris.things.do", File: "things/do.yaml", Method: "POST", Path: "/things/{id}",
		Summary: "Do a thing", Tags: []string{"things", "3"}, Auth: AuthBearer, RateLimit: "token_consume",
		Effect: EffectRead, Receipt: true, StepUp: true, Session: SessionIssue, RequiresPermissions: []string{"things.write"},
		Input: Input{Source: SourceBody, Fields: []Field{
			{Name: "name", Type: "?string", Rules: []Rule{name, maxRule}, Sensitive: true},
			{Name: "other", Type: "string"},
		}},
		Class: `Polaris\Things\DoEndpoint`, Description: "Does the thing.",
		Output: Output{Status: 201, Examples: []Example{
			{"example", Object{{"data", Object{{"id", "x"}}}}},
			{"example_other", []any{1, 2}},
		}},
		Errors: []Error{{Status: 404, Code: "not_found"}, {Status: 500}},
		Events: []string{"thing.done"},
	}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("got  %+v\nwant %+v", r, want)
	}

	m, err = Load(fstest.MapFS{"x.yaml": {Data: []byte("endpoint: { method: GET, path: /x, auth: public, effect: write, receipt: false }\ndomain: { class: X }\n")}})
	if err != nil {
		t.Fatal(err)
	}
	if r := m.Routes()[0]; r.Receipt || r.Input.Source != SourceNone || r.Output.Status != 0 {
		t.Errorf("defaults: %+v", r)
	}
}

func TestRouteValidate(t *testing.T) {
	m := loadCore(t)
	register, _ := m.Named("polaris.auth.register")
	err := register.Validate(map[string]any{"email": "nope"})
	if ve, ok := errors.AsType[*ValidationError](err); !ok || !reflect.DeepEqual(ve.Errors, []string{"email must be a valid email address.", "password is required."}) {
		t.Errorf("register: %v", err)
	}
}

func isEmpty(v any) bool {
	switch v := v.(type) {
	case Object:
		return len(v) == 0
	case []any:
		return len(v) == 0
	}
	return false
}
