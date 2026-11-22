package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/univeros/polaris.go/internal/services"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

const unitBase = "https://auth.polaris.test"

func ran(_ context.Context, c Call) (any, error) { return map[string]any{"ran": c.Arguments}, nil }

func unitCapability(name, risk, permission string) Capability {
	return Capability{Name: name, Description: "The " + name + " capability", Permission: permission, Risk: risk, Handler: ran,
		Input: map[string]any{"type": "object", "properties": map[string]any{"build": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"}}}}
}

func unitCaps() []Capability {
	return []Capability{unitCapability("deploy", RiskLow, "deploy.staging"), unitCapability("refund", RiskHigh, "billing.refund"),
		{Name: "members", Description: "List members", Permission: "members.read", Risk: RiskLow, Handler: ran}}
}

func bootUnit(t *testing.T, cfg Config) (*Plugin, *polaristest.Server) {
	t.Helper()
	if cfg.Capabilities == nil {
		cfg.Capabilities = unitCaps()
	}
	p := New(cfg)
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(oauth.Config{BaseURL: unitBase}), p))
	return p, srv
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantType(t *testing.T, err error, typ, message string) *Error {
	t.Helper()
	e, ok := asError(err)
	if !ok || e.Type != typ {
		t.Fatalf("%s: want %s, got %v", message, typ, err)
	}
	return e
}

type testKey struct {
	alg string
	ec  *ecdsa.PrivateKey
	ed  ed25519.PrivateKey
}

func newTestKey(alg string) *testKey {
	k := &testKey{alg: alg}
	if alg == AlgEdDSA {
		_, k.ed, _ = ed25519.GenerateKey(rand.Reader)
	} else {
		k.ec, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	return k
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (k *testKey) jwk() map[string]any {
	if k.alg == AlgEdDSA {
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "x": enc(k.ed.Public().(ed25519.PublicKey))}
	}
	pad := func(n *big.Int) string { b := make([]byte, 32); n.FillBytes(b); return enc(b) }
	return map[string]any{"kty": "EC", "crv": "P-256", "x": pad(k.ec.X), "y": pad(k.ec.Y)}
}

func (k *testKey) jwt(claims, header map[string]any) string {
	h := map[string]any{"typ": RequestJWTType, "alg": k.alg}
	for n, v := range header {
		h[n] = v
	}
	hj, _ := json.Marshal(h)
	pj, _ := json.Marshal(claims)
	input := enc(hj) + "." + enc(pj)
	if k.alg == AlgEdDSA {
		return input + "." + enc(ed25519.Sign(k.ed, []byte(input)))
	}
	sum := sha256.Sum256([]byte(input))
	r, s, _ := ecdsa.Sign(rand.Reader, k.ec, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return input + "." + enc(sig)
}

func (k *testKey) request(sub, aud string, extra map[string]any) map[string]any {
	now := time.Now().Unix()
	c := map[string]any{"sub": sub, "aud": aud, "iat": now, "exp": now + 120, "jti": repository.NewID()}
	for n, v := range extra {
		if v == nil {
			delete(c, n)
			continue
		}
		c[n] = v
	}
	return c
}

// newAgent registers an agent for a random user (key nil: an autonomous secret agent).
func newAgent(t *testing.T, p *Plugin, k *testKey) Agent {
	t.Helper()
	fields := map[string]any{"name": "Bot", "mode": ModeAutonomous, "auth": AuthClientSecret}
	if k != nil {
		fields = map[string]any{"name": "Bot", "mode": ModeDelegated, "auth": AuthPrivateKeyJWT, "jwk": k.jwk()}
	}
	user := repository.NewID()
	a, _, err := p.s.createAgent(context.Background(), fields, Agent{OwnerType: OwnerUser, OwnerID: user, CreatedBy: user})
	must(t, err)
	return a
}

// holder registers an agent whose owner owns an organization (so holds its permissions).
func holder(t *testing.T, p *Plugin, srv *polaristest.Server) Agent {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	user := model.User{ID: repository.NewID(), Email: repository.NewID() + "@example.com", EmailVerifiedAt: &now, CreatedAt: now, UpdatedAt: now}
	must(t, srv.Graph().Repos().Users.Insert(ctx, user))
	org, err := services.Of(srv.Graph()).Orgs.CreateOrganization(ctx, "Acme "+user.ID, "", user.ID)
	must(t, err)
	a, _, err := p.s.createAgent(ctx, map[string]any{"name": "Bot", "auth": AuthPrivateKeyJWT, "jwk": newTestKey(AlgES256).jwk()},
		Agent{OwnerType: OwnerUser, OwnerID: user.ID, OrganizationID: org.ID, CreatedBy: user.ID})
	must(t, err)
	return a
}

func TestSettingsAndCapabilitiesAreValidated(t *testing.T) {
	s, _, err := Config{}.resolve()
	must(t, err)
	if s.strengthFor(RiskHigh) != StrengthStepUp || s.strengthFor("unknown") != StrengthStepUp || s.providerName != "Polaris" {
		t.Errorf("defaults %+v", s)
	}
	s, _, _ = Config{Strengths: map[string]string{RiskHigh: StrengthPasskey}}.resolve()
	if s.strengthFor(RiskHigh) != StrengthPasskey {
		t.Error("strength override")
	}
	h := func(context.Context, Call) (any, error) { return nil, nil }
	for name, cfg := range map[string]Config{
		"base url":        {BaseURL: "not a url"},
		"approval url":    {ApprovalURL: "https://app.test/approve?x=1"},
		"risk tier":       {AutoApprove: map[string]Budget{"critical": {}}},
		"budget":          {AutoApprove: map[string]Budget{RiskLow: {Count: -1}}},
		"window":          {AutoApprove: map[string]Budget{RiskLow: {Count: 1, Window: time.Millisecond}}},
		"strength":        {Strengths: map[string]string{RiskHigh: "biometric"}},
		"max age":         {RequestJWTMaxAge: 10 * time.Minute},
		"approval ttl":    {ApprovalTTL: time.Millisecond},
		"name":            {Capabilities: []Capability{{Name: "Deploy", Description: "x", Permission: "deploy", Handler: h}}},
		"description":     {Capabilities: []Capability{{Name: "deploy", Permission: "deploy", Handler: h}}},
		"permission":      {Capabilities: []Capability{{Name: "deploy", Description: "x", Permission: "Deploy!", Handler: h}}},
		"capability risk": {Capabilities: []Capability{{Name: "deploy", Description: "x", Permission: "deploy", Risk: "critical", Handler: h}}},
		"no handler":      {Capabilities: []Capability{{Name: "deploy", Description: "x", Permission: "deploy"}}},
		"both":            {Capabilities: []Capability{{Name: "deploy", Description: "x", Permission: "deploy", Location: "https://h.test/x", Handler: h}}},
		"bad location":    {Capabilities: []Capability{{Name: "deploy", Description: "x", Permission: "deploy", Location: "https://h.test/x?q=1"}}},
		"twice":           {Capabilities: []Capability{unitCapability("a", RiskLow, "a"), unitCapability("a", RiskLow, "a")}},
		"same location": {Capabilities: []Capability{{Name: "a", Description: "x", Permission: "a", Location: "https://h.test/x"},
			{Name: "b", Description: "x", Permission: "b", Location: "https://H.test:443/x/"}}},
		"schema keyword": {Capabilities: []Capability{{Name: "a", Description: "x", Permission: "a", Handler: h, Input: map[string]any{"type": "object", "oneOf": []any{}}}}},
		"schema pattern": {Capabilities: []Capability{{Name: "a", Description: "x", Permission: "a", Handler: h, Input: map[string]any{"type": "string", "pattern": "(?<=a)"}}}},
		"not json":       {Capabilities: []Capability{{Name: "a", Description: "x", Permission: "a", Handler: h, Input: map[string]any{"x": func() {}}}}},
	} {
		if _, _, err := cfg.resolve(); err == nil || !strings.HasPrefix(err.Error(), "agents: ") {
			t.Errorf("%s: want an error, got %v", name, err)
		}
	}
	if New(Config{BaseURL: "nope"}).Init(nil) == nil {
		t.Error("Init reports the configuration error")
	}
}

func TestConstraintsAreParsedAndEvaluated(t *testing.T) {
	raw := map[string]any{"amount": map[string]any{"max": json.Number("100"), "min": json.Number("1")}, "currency": map[string]any{"in": []any{"EUR", "USD"}},
		"env": map[string]any{"not_in": []any{"prod"}}, "ref": map[string]any{"pattern": `[a-z]+-\d+`},
		"budget": map[string]any{"amount": json.Number("500"), "field": "amount", "window": json.Number("3600")}}
	parsed, err := parseConstraints(raw)
	must(t, err)
	if *parsed.budget != (budget{kind: BudgetAmount, total: 500, field: "amount", window: 3600}) {
		t.Errorf("budget %+v", parsed.budget)
	}
	if v := violations(parsed.fields, map[string]any{"amount": json.Number("50"), "currency": "EUR", "env": "staging", "ref": "abc-12"}); len(v) != 0 {
		t.Errorf("violations %v", v)
	}
	got := violations(parsed.fields, map[string]any{"amount": json.Number("150"), "currency": "GBP", "env": "prod", "x": []any{}})
	want := []Violation{{"amount", "max", json.Number("150")}, {"currency", "in", "GBP"}, {"env", "not_in", "prod"}, {"ref", "pattern", nil}}
	if g, w := mustJSON(got), mustJSON(want); g != w {
		t.Errorf("violations %s, want %s", g, w)
	}
	if v := violations(map[string]map[string]any{"a": {"in": []any{json.Number("1")}}}, map[string]any{"a": map[string]any{}}); len(v) != 1 || v[0].Actual != "<array>" {
		t.Errorf("non-scalar %v", v)
	}
	if v := violations(map[string]map[string]any{"a": {"max": json.Number("5")}, "b": {"in": []any{json.Number("1")}}}, map[string]any{"a": "4", "b": json.Number("1.0")}); len(v) != 1 || v[0].Field != "b" {
		t.Errorf("numeric string passes max, 1.0 is not 1: %v", v)
	}
	for name, c := range map[string]any{
		"operator":       map[string]any{"amount": map[string]any{"between": []any{1, 2}}},
		"list operators": map[string]any{"amount": []any{"x"}},
	} {
		_, err := parseConstraints(c)
		if e := wantType(t, err, ErrUnknownConstraintOperator, name); e.Status() != 400 {
			t.Errorf("%s status %d", name, e.Status())
		}
	}
	for name, c := range map[string]any{
		"two kinds":   map[string]any{"budget": map[string]any{"count": json.Number("1"), "amount": json.Number("2")}},
		"budget type": map[string]any{"budget": "x"},
		"zero":        map[string]any{"budget": map[string]any{"count": json.Number("0")}},
		"float":       map[string]any{"budget": map[string]any{"count": json.Number("1.5")}},
		"field":       map[string]any{"budget": map[string]any{"amount": json.Number("2")}},
		"window":      map[string]any{"budget": map[string]any{"count": json.Number("2"), "window": json.Number("0")}},
		"name":        map[string]any{"1bad": map[string]any{}},
		"max":         map[string]any{"a": map[string]any{"max": "x"}},
		"in":          map[string]any{"a": map[string]any{"in": []any{map[string]any{}}}},
		"pattern":     map[string]any{"a": map[string]any{"pattern": "(?<=x)"}},
		"shape":       "x",
		"list":        []any{"x"},
	} {
		_, err := parseConstraints(c)
		_ = wantType(t, err, ErrInvalidInput, name)
	}
	if c, err := parseConstraints([]any{}); err != nil || len(c.fields) != 0 {
		t.Error("[] is no constraint")
	}
	amount := Grant{BudgetKind: BudgetAmount, BudgetField: "amount"}
	if n, _ := cost(amount, map[string]any{"amount": json.Number("12.5")}); n != 13 {
		t.Errorf("cost %d", n)
	}
	if n, _ := cost(Grant{}, map[string]any{"amount": json.Number("12.5")}); n != 1 {
		t.Errorf("count cost %d", n)
	}
	_, err = cost(amount, map[string]any{"amount": "x"})
	_ = wantType(t, err, ErrInvalidArguments, "amount")
}

func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestSchemaSubsetRefusalMessages(t *testing.T) {
	str := map[string]any{"type": "string", "minLength": json.Number("2"), "maxLength": json.Number("3"), "pattern": "^[a-z]+$"}
	schema := map[string]any{"type": "object", "required": []any{"name"}, "additionalProperties": false, "properties": map[string]any{
		"name": str, "n": map[string]any{"type": "integer", "minimum": json.Number("1"), "maximum": json.Number("9"), "exclusiveMaximum": json.Number("5")},
		"tags": map[string]any{"type": "array", "minItems": json.Number("1"), "maxItems": json.Number("2"), "items": map[string]any{"enum": []any{"a", "b"}}},
		"k":    map[string]any{"const": "x"}, "f": map[string]any{"type": []any{"number", "null"}, "exclusiveMinimum": json.Number("0")},
		"meta": map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "boolean"}},
	}}
	if err := checkSchema(schema, "#"); err != nil {
		t.Fatal(err)
	}
	for data, want := range map[string]string{
		`{"name":"ab"}`:                   "",
		`{"name":"ab","f":null}`:          "",
		`{"name":"ab","n":2.0}`:           "",
		`{}`:                              "The required properties (name) are missing",
		`{"name":"ab","x":1,"y":2}`:       "Additional object properties are not allowed: x, y",
		`{"name":1}`:                      "/name: The data (integer) must match the type: string",
		`{"name":"a"}`:                    "/name: Minimum string length is 2, found 1",
		`{"name":"abcd"}`:                 "/name: Maximum string length is 3, found 4",
		`{"name":"AB"}`:                   "/name: The string should match pattern: ^[a-z]+$",
		`{"name":"ab","n":0}`:             "/n: Number must be greater than or equal to 1",
		`{"name":"ab","n":10}`:            "/n: Number must be lower than or equal to 9",
		`{"name":"ab","n":5}`:             "/n: Number must be lower than 5",
		`{"name":"ab","n":1.5}`:           "/n: The data (number) must match the type: integer",
		`{"name":"ab","tags":[]}`:         "/tags: Array should have at least 1 items, 0 found",
		`{"name":"ab","tags":[1,2,3]}`:    "/tags: Array should have at most 2 items, 3 found",
		`{"name":"ab","tags":["c"]}`:      "/tags/0: The data should match one item from enum",
		`{"name":"ab","k":"y"}`:           "/k: The data must match the const value",
		`{"name":"ab","f":0}`:             "/f: Number must be greater than 0",
		`{"name":"ab","f":"x"}`:           "/f: The data (string) must match the type: number, null",
		`{"name":"ab","meta":{"a":1}}`:    "/meta/a: The data (integer) must match the type: boolean",
		`{"name":"ab","meta":{"a":true}}`: "",
	} {
		var v map[string]any
		dec := json.NewDecoder(strings.NewReader(data))
		dec.UseNumber()
		must(t, dec.Decode(&v))
		if got := validateSchema(schema, v); got != want {
			t.Errorf("%s: got %q, want %q", data, got, want)
		}
	}
	if validateSchema(map[string]any{"type": "object"}, map[string]any{}) != "" || jsonType(true) != "boolean" || jsonType(struct{}{}) != "unknown" {
		t.Error("basics")
	}
	for _, bad := range []map[string]any{{"properties": "x"}, {"properties": map[string]any{"a": "x"}}, {"items": "x"}, {"additionalProperties": "x"}, {"items": map[string]any{"oneOf": []any{}}}} {
		if checkSchema(bad, "#") == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

func TestLocationsAndAudiencesAreComparedNormalised(t *testing.T) {
	loc := "https://host.polaris.test/invite"
	for _, v := range []string{loc + "/", "https://host.polaris.test//invite", "https://host.polaris.test/./invite", "https://host.polaris.test/a/../invite",
		"https://host.polaris.test:443/invite", "HTTPS://host.polaris.test/invite", "https://HOST.polaris.test/invite", "https://host.polaris.test/%69nvite", loc + "?x=1#f"} {
		if normalizeURL(v) != loc || routeOf(v) != "host.polaris.test/invite" {
			t.Errorf("%s: %s / %s", v, normalizeURL(v), routeOf(v))
		}
	}
	if routeOf("http://host.polaris.test/invite") != "host.polaris.test/invite" {
		t.Error("a proxy's scheme still lands on the location")
	}
	if got := normalizeURL("https://host.polaris.test:8443/a%2fb/%c3%a9"); got != "https://host.polaris.test:8443/a%2Fb/%C3%A9" {
		t.Errorf("escapes %s", got)
	}
	if normalizeURL("https://host.polaris.test") != "https://host.polaris.test/" || normalizeURL("not a url") != "not a url" ||
		normalizeURL("http://[::1]:80/x") != "http://[::1]/x" || routeOf("no scheme") != "no scheme" {
		t.Error("edge cases")
	}
	caps, err := newCapabilities([]Capability{{Name: "invite", Description: "x", Permission: "members.invite", Location: loc}})
	must(t, err)
	if caps.at("https://Host.polaris.test:443//invite/") == nil || caps.at("http://host.polaris.test/invite") == nil || caps.at("https://host.polaris.test/invites") != nil {
		t.Error("at")
	}
	p := New(Config{Capabilities: unitCaps()})
	defer func() {
		if recover() == nil {
			t.Error("Protect of a capability without a location panics")
		}
	}()
	p.Protect("deploy", http.NotFoundHandler())
}

func TestTheAgentKeyIsValidatedAndGetsAKid(t *testing.T) {
	k := newTestKey(AlgES256)
	jwk, err := publicJWK(k.jwk())
	must(t, err)
	tp, _ := oauth.Thumbprint(k.jwk())
	if jwk["alg"] != AlgES256 || jwk["kid"] != tp || jwk["use"] != "sig" {
		t.Errorf("jwk %v", jwk)
	}
	if j, _ := publicJWK(newTestKey(AlgEdDSA).jwk()); j["alg"] != AlgEdDSA {
		t.Error("EdDSA")
	}
	withKid := k.jwk()
	withKid["kid"] = "mine"
	if j, _ := publicJWK(withKid); j["kid"] != "mine" {
		t.Error("own kid")
	}
	with := func(extra map[string]any) map[string]any {
		out := k.jwk()
		for n, v := range extra {
			out[n] = v
		}
		return out
	}
	for name, bad := range map[string]any{
		"nil": nil, "rsa": map[string]any{"kty": "RSA", "n": "x", "e": "AQAB"}, "private": with(map[string]any{"d": "secret"}),
		"p-384": map[string]any{"kty": "EC", "crv": "P-384", "x": "a", "y": "b"}, "alg": with(map[string]any{"alg": "EdDSA"}),
		"coordinate": with(map[string]any{"x": "!!"}), "kid": with(map[string]any{"kid": strings.Repeat("k", 200)}),
		"off curve": with(map[string]any{"x": enc(make([]byte, 32))}),
	} {
		_, err := publicJWK(bad)
		_ = wantType(t, err, ErrInvalidInput, name)
	}
}

func TestRequestJWTsAreVerifiedAgainstTheAgentsKeyAndTheRequest(t *testing.T) {
	p, _ := bootUnit(t, Config{})
	ctx := context.Background()
	execute := unitBase + "/agents/execute"
	body := []byte(`{"capability":"deploy"}`)
	sum := sha256.Sum256(body)
	for _, alg := range []string{AlgES256, AlgEdDSA} {
		k := newTestKey(alg)
		a := newAgent(t, p, k)
		now := time.Now().Unix()
		caps, err := p.s.jwts.verify(ctx, k.jwt(k.request(a.ID, execute, map[string]any{"htm": "post", "htu": execute + "?x=1", "body_hash": enc(sum[:]), "capabilities": []any{"deploy"}}), nil), a, "POST", execute+"?x=1", body)
		must(t, err)
		if len(caps) != 1 || caps[0] != "deploy" {
			t.Errorf("capabilities %v", caps)
		}
		refused := map[string]string{
			"aud":                k.jwt(k.request(a.ID, unitBase+"/agents/session", nil), nil),
			"aud with query":     k.jwt(k.request(a.ID, execute+"?x=1", nil), nil),
			"exp - iat > 300":    k.jwt(k.request(a.ID, execute, map[string]any{"iat": now, "exp": now + 301}), nil),
			"expired":            k.jwt(k.request(a.ID, execute, map[string]any{"iat": now - 400, "exp": now - 100}), nil),
			"future":             k.jwt(k.request(a.ID, execute, map[string]any{"iat": now + 400, "exp": now + 500}), nil),
			"nbf":                k.jwt(k.request(a.ID, execute, map[string]any{"nbf": now + 400}), nil),
			"no jti":             k.jwt(k.request(a.ID, execute, map[string]any{"jti": nil}), nil),
			"no iat":             k.jwt(k.request(a.ID, execute, map[string]any{"iat": nil}), nil),
			"another agent":      k.jwt(k.request(repository.NewID(), execute, nil), nil),
			"wrong key":          newTestKey(alg).jwt(k.request(a.ID, execute, nil), nil),
			"jku header":         k.jwt(k.request(a.ID, execute, nil), map[string]any{"jku": "https://evil.test/jwks"}),
			"jwk header":         k.jwt(k.request(a.ID, execute, nil), map[string]any{"jwk": k.jwk()}),
			"typ":                k.jwt(k.request(a.ID, execute, nil), map[string]any{"typ": "JWT"}),
			"alg":                k.jwt(k.request(a.ID, execute, nil), map[string]any{"alg": "RS256"}),
			"htm":                k.jwt(k.request(a.ID, execute, map[string]any{"htm": "GET"}), nil),
			"htu":                k.jwt(k.request(a.ID, execute, map[string]any{"htu": unitBase + "/other"}), nil),
			"body_hash":          k.jwt(k.request(a.ID, execute, map[string]any{"body_hash": "x"}), nil),
			"capabilities shape": k.jwt(k.request(a.ID, execute, map[string]any{"capabilities": "deploy"}), nil),
			"garbage":            "a.b.c",
		}
		for why, jwt := range refused {
			_, err := p.s.jwts.verify(ctx, jwt, a, "POST", execute, body)
			want := ErrInvalidJWT
			if strings.HasPrefix(why, "aud") {
				want = ErrAudMismatch
			}
			_ = wantType(t, err, want, alg+" "+why)
		}
		replayed := k.jwt(k.request(a.ID, execute, nil), nil)
		_, err = p.s.jwts.verify(ctx, replayed, a, "POST", execute, body)
		must(t, err)
		_, err = p.s.jwts.verify(ctx, replayed, a, "POST", execute, body)
		if e := wantType(t, err, ErrInvalidJWT, "replay"); !strings.Contains(e.Detail, "jti") {
			t.Error(e.Detail)
		}
	}
	keyless := newAgent(t, p, nil)
	k := newTestKey(AlgES256)
	_, err := p.s.jwts.verify(ctx, k.jwt(k.request(keyless.ID, execute, nil), nil), keyless, "POST", execute, nil)
	if e := wantType(t, err, ErrInvalidJWT, "keyless"); !strings.Contains(e.Detail, "no registered key") {
		t.Error(e.Detail)
	}
}

func TestAgentRegistrationIsValidated(t *testing.T) {
	p, _ := bootUnit(t, Config{})
	ctx := context.Background()
	k := newTestKey(AlgES256)
	priv := k.jwk()
	priv["d"] = "secret"
	owner := Agent{OwnerType: OwnerUser, OwnerID: "user-1", CreatedBy: "user-1"}
	for _, f := range []map[string]any{
		{"name": "", "mode": "delegated", "auth": "client_secret"}, {"name": "X", "mode": "hybrid", "auth": "client_secret"},
		{"name": "X", "mode": "delegated", "auth": "password"}, {"name": "X", "mode": "autonomous", "auth": "delegated_token"},
		{"name": "X", "mode": "delegated", "auth": "private_key_jwt"}, {"name": "X", "mode": "delegated", "auth": "private_key_jwt", "jwk": priv},
	} {
		_, _, err := p.s.createAgent(ctx, f, owner)
		_ = wantType(t, err, ErrInvalidInput, mustJSON(f))
	}
	public, _, err := p.s.createAgent(ctx, map[string]any{"name": "X", "auth": AuthDelegatedToken}, owner)
	must(t, err)
	c, err := p.s.oauth.Client(ctx, public.ID)
	must(t, err)
	if c.Type != "public" || c.TokenEndpointAuthMethod != "none" || mustJSON(c.GrantTypes) != `["`+oauth.GrantTokenExchange+`"]` || mustJSON(c.Scopes) != `["profile"]` || public.Mode != ModeDelegated {
		t.Errorf("client %+v", c)
	}
}

func TestBudgetsAreSpentByAConditionalUpdate(t *testing.T) {
	p, srv := bootUnit(t, Config{AutoApprove: map[string]Budget{}})
	ctx := context.Background()
	a := holder(t, p, srv)
	res, err := p.s.requestGrants(ctx, a, []any{map[string]any{"name": "members", "constraints": map[string]any{"budget": map[string]any{"amount": json.Number("10"), "field": "amount"}}}})
	must(t, err)
	g := res.grants[0]
	if g.Status != GrantPending {
		t.Fatalf("auto-approval is off: %s", g.Status)
	}
	g, err = p.s.approveGrant(ctx, g, "owner", MethodInApp, nil)
	must(t, err)
	left, ok, err := p.s.spend(ctx, g, 3)
	if err != nil || !ok || *left != 7 {
		t.Fatalf("spend 3: %v %v %v", left, ok, err)
	}
	if _, ok, _ := p.s.spend(ctx, g, 8); ok {
		t.Error("more than what is left spends nothing")
	}
	if left, ok, _ = p.s.spend(ctx, g, 7); !ok || *left != 0 {
		t.Error("spend the rest")
	}
	_, err = p.s.endGrant(ctx, g, []string{GrantActive}, GrantExhausted)
	must(t, err)
	if active, _ := p.s.activeGrant(ctx, a, "members"); active != nil {
		t.Error("an exhausted grant is not active")
	}
	_, err = p.s.approveGrant(ctx, g, "owner", MethodInApp, nil)
	_ = wantType(t, err, ErrConflict, "approve twice")
}

func TestTheAskerCannotWidenTheAutoApprovalBudget(t *testing.T) {
	p, srv := bootUnit(t, Config{AutoApprove: map[string]Budget{RiskLow: {Count: 100, Window: time.Hour}}})
	ctx := context.Background()
	h := holder(t, p, srv)
	ask := func(a Agent, b map[string]any) Grant {
		item := any("members")
		if b != nil {
			item = map[string]any{"name": "members", "constraints": map[string]any{"budget": b}}
		}
		res, err := p.s.requestGrants(ctx, a, []any{item})
		must(t, err)
		return res.grants[0]
	}
	policy := ask(h, nil)
	if policy.Status != GrantActive || *policy.BudgetTotal != 100 || policy.ApprovedVia != ViaAuto || policy.ExpiresAt == nil {
		t.Errorf("policy %+v", policy)
	}
	_, _ = p.s.endGrant(ctx, policy, []string{GrantActive}, GrantRevoked)
	narrower := ask(h, map[string]any{"count": json.Number("10"), "window": json.Number("60")})
	if narrower.Status != GrantActive || *narrower.BudgetTotal != 10 {
		t.Errorf("narrower %+v", narrower)
	}
	_, _ = p.s.endGrant(ctx, narrower, []string{GrantActive}, GrantRevoked)
	for _, wider := range []map[string]any{
		{"count": json.Number("1000000000"), "window": json.Number("60")}, {"count": json.Number("100")},
		{"count": json.Number("100"), "window": json.Number("7200")}, {"amount": json.Number("10"), "field": "amount", "window": json.Number("60")},
	} {
		g := ask(h, wider)
		if g.Status != GrantPending {
			t.Errorf("%v: %s", wider, g.Status)
		}
		_, _ = p.s.endGrant(ctx, g, []string{GrantPending}, GrantDenied)
	}
	if ask(newAgent(t, p, nil), nil).Status != GrantPending {
		t.Error("an owner without the permission always waits")
	}
	_, err := p.s.requestGrants(ctx, h, nil)
	_ = wantType(t, err, ErrInvalidInput, "nothing asked")
}

func TestPendingGrantsAreReusedApprovalsAreCappedAndExpire(t *testing.T) {
	names := []string{"c1", "c2", "c3", "c4", "c5", "c6"}
	var caps []Capability
	for _, n := range names {
		caps = append(caps, unitCapability(n, RiskHigh, "deploy.staging"))
	}
	p, srv := bootUnit(t, Config{Capabilities: caps})
	ctx := context.Background()
	a := newAgent(t, p, nil)
	req := func(name string) ([]Grant, *Approval, error) {
		return p.s.requestGrantsAndApproval(ctx, a, []any{name}, "", "", "", true, client{})
	}
	g1, ap1, err := req("c1")
	must(t, err)
	g2, ap2, _ := req("c1")
	if g1[0].ID != g2[0].ID || ap1.ID != ap2.ID || ap1.Method != MethodInApp {
		t.Error("the same pending grant and approval")
	}
	_, err = srv.Graph().DB().Update(ctx, TableApprovals, store.Criteria{"id": ap1.ID}, store.Data{"expires_at": time.Now().Add(-time.Second)})
	must(t, err)
	expired, _, _ := p.s.approval(ctx, ap1.ID)
	if expired.Status != ApprovalExpired {
		t.Errorf("status %s", expired.Status)
	}
	if pending, _ := p.s.pendingApprovals(ctx, []Agent{a}); len(pending) != 0 {
		t.Error("expired is not pending")
	}
	_, _, err = p.s.decide(ctx, expired, true, "owner", nil)
	if e := wantType(t, err, ErrConflict, "decide expired"); e.Detail != "The approval is expired." {
		t.Error(e.Detail)
	}
	g3, ap3, _ := req("c1")
	if g3[0].ID != g1[0].ID || ap3.ID == ap1.ID || g3[0].ApprovalID != ap3.ID {
		t.Error("renewed approval")
	}
	for _, n := range names[1:5] {
		_, _, err := req(n)
		must(t, err)
	}
	_, _, err = req("c6")
	_ = wantType(t, err, ErrConflict, "capped")
	if g, _ := p.s.grantWith(ctx, a, "c6", GrantPending); g != nil {
		t.Error("nothing was written")
	}
	_, _, err = p.s.requestGrantsAndApproval(ctx, a, []any{"c1"}, "fax", "", "", true, client{})
	if err != nil {
		t.Error("a reused grant with an open approval needs no method")
	}
	_, err = p.s.openApproval(ctx, a, nil, "fax", StrengthSession, "")
	_ = wantType(t, err, ErrInvalidInput, "method")
	_, err = p.s.openApproval(ctx, a, nil, MethodCIBA, StrengthSession, strings.Repeat("x", 161))
	_ = wantType(t, err, ErrInvalidInput, "binding message")
}

func TestADecisionWithBadConstraintsLeavesTheApprovalPending(t *testing.T) {
	p, _ := bootUnit(t, Config{})
	ctx := context.Background()
	a := newAgent(t, p, nil)
	grants, ap, err := p.s.requestGrantsAndApproval(ctx, a, []any{"refund"}, "", "", "", true, client{})
	must(t, err)
	_, _, err = p.s.decide(ctx, *ap, true, "owner", map[string]any{"amount": map[string]any{"between": []any{}}})
	_ = wantType(t, err, ErrUnknownConstraintOperator, "bad constraints")
	still, _, _ := p.s.approval(ctx, ap.ID)
	g, _, _ := p.s.grant(ctx, grants[0].ID)
	if still.Status != ApprovalPending || g.Status != GrantPending {
		t.Error("nothing changed")
	}
	_, decided, err := p.s.decide(ctx, *ap, true, "owner", map[string]any{"amount": map[string]any{"max": json.Number("5")}})
	must(t, err)
	if len(decided) != 1 || decided[0].Status != GrantActive || decided[0].Constraints["amount"]["max"] != json.Number("5") {
		t.Errorf("decided %+v", decided)
	}
}

func TestReceiptsChainHashAndVerify(t *testing.T) {
	p, _ := bootUnit(t, Config{})
	ctx := context.Background()
	a := newAgent(t, p, nil)
	if got := canonicalJSON(map[string]any{"z": nil, "a": map[string]any{"c": "x/y", "b": []any{2, 1}}, "u": "é", "e": map[string]any{}}); got != `{"a":{"b":[2,1],"c":"x/y"},"e":[],"u":"\u00e9","z":null}` {
		t.Errorf("canonical %q", got)
	}
	if inputHash(map[string]any{}) != "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945" {
		t.Error("the empty input hashes as []")
	}
	ten, nine, eight := int64(10), int64(9), int64(8)
	first, err := p.s.appendReceipt(ctx, a, nil, "deploy", inputHash(map[string]any{"build": "1"}), OutcomeSuccess, &ten, &nine)
	must(t, err)
	second, err := p.s.appendReceipt(ctx, a, nil, "deploy", inputHash(map[string]any{"build": "2"}), OutcomeSuccess, &nine, &eight)
	must(t, err)
	if first.Seq != 1 || second.Seq != 2 || first.PrevHash != "" || second.PrevHash != first.Hash || second.Hash != hashOf(second) {
		t.Error("chain")
	}
	v, err := p.VerifyReceipt(ctx, second)
	must(t, err)
	if !v.Valid {
		t.Errorf("verify %+v", v)
	}
	second.Outcome = OutcomeFailed
	if v, _ = p.VerifyReceipt(ctx, second); v.Hash || v.Signature || !v.Chain {
		t.Errorf("a changed field breaks the hash and the signature: %+v", v)
	}
	list, err := p.Receipts(ctx, a.ID, 1, 0)
	must(t, err)
	if len(list) != 1 || list[0].Seq != 2 {
		t.Error("export page")
	}
	_, sealed, err := p.s.revoke(ctx, a, "", "system", client{})
	must(t, err)
	if sealed.Outcome != OutcomeSealed || sealed.Seq != 3 {
		t.Errorf("sealed %+v", sealed)
	}
	_, err = p.s.appendReceipt(ctx, a, nil, "deploy", inputHash(nil), OutcomeSuccess, nil, nil)
	_ = wantType(t, err, ErrSealed, "nothing after the seal")
}

func TestHostsAuthenticateByTheirEnrolmentToken(t *testing.T) {
	p, srv := bootUnit(t, Config{})
	ctx := context.Background()
	owner := Host{OwnerType: OwnerUser, OwnerID: "user-1", CreatedBy: "user-1"}
	h, secret, err := p.s.createHost(ctx, owner, "Laptop", []any{"deploy"})
	must(t, err)
	if !strings.HasPrefix(secret, HostTokenPrefix) {
		t.Error(secret)
	}
	if got, ok, _ := p.s.hostByToken(ctx, secret); !ok || got.ID != h.ID {
		t.Error("authenticates")
	}
	for _, bad := range []string{HostTokenPrefix + strings.Repeat("x", 43), "pk_live_" + strings.Repeat("x", 43)} {
		if _, ok, _ := p.s.hostByToken(ctx, bad); ok {
			t.Error(bad)
		}
	}
	must(t, p.s.revokeHosts(ctx, store.Criteria{"id": h.ID}))
	if _, ok, _ := p.s.hostByToken(ctx, secret); ok {
		t.Error("revoked")
	}
	_, _, err = p.s.createHost(ctx, owner, "Laptop", []any{"nope"})
	_ = wantType(t, err, ErrCapabilityNotFound, "unknown capability")
	_, _, err = p.s.createHost(ctx, owner, "", nil)
	_ = wantType(t, err, ErrInvalidInput, "no name")
	_, _, err = p.s.createHost(ctx, owner, "X", make([]any, 51))
	_ = wantType(t, err, ErrInvalidInput, "too many")

	// A member who leaves takes the organization's hosts they created; erasures leave nothing.
	org := Host{OwnerType: OwnerOrganization, OwnerID: "org-1", OrganizationID: "org-1", CreatedBy: "user-1"}
	_, orgSecret, _ := p.s.createHost(ctx, org, "CI", nil)
	other := org
	other.CreatedBy = "user-2"
	_, otherSecret, _ := p.s.createHost(ctx, other, "CI 2", nil)
	_, ownSecret, _ := p.s.createHost(ctx, Host{OwnerType: OwnerUser, OwnerID: "user-1", OrganizationID: "org-1", CreatedBy: "user-1"}, "Laptop", nil)
	srv.Events.Dispatch(ctx, event.MemberRemoved{OrganizationID: "org-1", UserID: "user-1"})
	for secret, want := range map[string]bool{orgSecret: false, otherSecret: true, ownSecret: true} {
		if _, ok, _ := p.s.hostByToken(ctx, secret); ok != want {
			t.Errorf("after the member left: %v, want %v", ok, want)
		}
	}
	srv.Events.Dispatch(ctx, event.OrganizationDeleted{OrganizationID: "org-1"})
	srv.Events.Dispatch(ctx, event.UserDeleted{UserID: "user-1"})
	if n, _ := srv.Graph().DB().Count(ctx, TableHosts, store.Criteria{}); n != 0 {
		t.Errorf("%d hosts left", n)
	}
}

func TestListenersEraseAndRevokeAgents(t *testing.T) {
	p, srv := bootUnit(t, Config{})
	ctx := context.Background()
	mk := func(owner Agent) Agent {
		a, _, err := p.s.createAgent(ctx, map[string]any{"name": "Bot", "auth": AuthClientSecret}, owner)
		must(t, err)
		return a
	}
	orgAgent := mk(Agent{OwnerType: OwnerOrganization, OwnerID: "org-1", OrganizationID: "org-1", CreatedBy: "user-1"})
	userAgent := mk(Agent{OwnerType: OwnerUser, OwnerID: "user-2", CreatedBy: "user-2"})
	srv.Events.Dispatch(ctx, event.MemberRemoved{OrganizationID: "org-1", UserID: "user-1"})
	if a, _, _ := p.s.agent(ctx, orgAgent.ID); a.Status != StatusRevoked || a.SealedAt == nil {
		t.Errorf("revoked with the member: %s", a.Status)
	}
	srv.Events.Dispatch(ctx, event.MemberRemoved{OrganizationID: "org-1", UserID: "user-1"})
	srv.Events.Dispatch(ctx, event.OrganizationDeleted{OrganizationID: "org-1"})
	srv.Events.Dispatch(ctx, event.UserDeleted{UserID: "user-2"})
	for _, id := range []string{orgAgent.ID, userAgent.ID} {
		if _, ok, _ := p.s.agent(ctx, id); ok {
			t.Error("erased")
		}
		if _, err := p.s.oauth.Client(ctx, id); !errors.Is(err, oauth.ErrClientNotFound) {
			t.Error("the client is erased")
		}
	}
}

func TestExecutionIsRefusedWithoutAGrantAndHoldsTheAgentRow(t *testing.T) {
	p, srv := bootUnit(t, Config{})
	ctx := context.Background()
	a := newAgent(t, p, nil)
	pr := principal{agent: a, via: ViaJWT}
	for name, typ := range map[string]string{"nope": ErrCapabilityNotFound, "deploy": ErrCapabilityNotGranted} {
		_, err := p.s.execute(ctx, pr, name, map[string]any{"build": "1"}, client{})
		_ = wantType(t, err, typ, name)
	}
	if got, err := p.s.fromToken(ctx, token.NewPrincipal(map[string]any{"sub": "x", "client_id": "nobody"}).Delegate(nil)); got != nil || err != nil {
		t.Error("not an agent's token")
	}
	if got, _ := p.s.fromToken(ctx, token.NewPrincipal(map[string]any{"sub": a.ID, "client_id": a.ID})); got != nil {
		t.Error("a token no resolver delegated is never an agent's")
	}

	h := holder(t, p, srv)
	hp := principal{agent: h, via: ViaJWT}
	_, err := p.s.requestGrants(ctx, h, []any{"members"})
	must(t, err)
	ev, err := p.s.evaluate(ctx, hp, "members", []any{})
	must(t, err)
	done, err := p.s.run(ctx, ev, ran, nil, client{})
	must(t, err)
	if done.receipt.Seq != 1 {
		t.Error("seq")
	}
	failing := func(context.Context, Call) (any, error) { return nil, errors.New("boom") }
	if _, err := p.s.run(ctx, ev, failing, nil, client{}); err == nil || err.Error() != "boom" {
		t.Errorf("a handler error rolls back: %v", err)
	}
	if last, _, _ := p.s.lastReceipt(ctx, h.ID); last.Seq != 1 {
		t.Error("no receipt for a failed handler")
	}
	_, err = p.s.transition(ctx, h, StatusActive, StatusSuspended, "")
	must(t, err)
	ranIt := false
	_, err = p.s.run(ctx, ev, func(context.Context, Call) (any, error) { ranIt = true; return nil, nil }, nil, client{})
	if e := wantType(t, err, ErrAgentInactive, "suspended meanwhile"); e.code() != "agent_suspended" || ranIt {
		t.Error("nothing runs")
	}
	_, err = p.s.evaluate(ctx, hp, "members", "x")
	_ = wantType(t, err, ErrInvalidArguments, "not an object")
	_, err = p.s.evaluate(ctx, principal{agent: h, via: ViaOAuth}, "members", nil)
	_ = wantType(t, err, ErrCapabilityNotGranted, "the token lacks the permission")
	_, err = p.s.evaluate(ctx, principal{agent: h, via: ViaJWT, capabilities: []string{"deploy"}}, "members", nil)
	_ = wantType(t, err, ErrCapabilityNotGranted, "the JWT does not name it")

	// A grant without a budget revoked between the evaluation and the run runs nothing.
	_, err = p.s.transition(ctx, h, StatusSuspended, StatusActive, "")
	must(t, err)
	_, err = srv.Graph().DB().Update(ctx, TableGrants, store.Criteria{"agent_id": h.ID}, store.Data{"status": GrantRevoked})
	must(t, err)
	ev.grant.BudgetKind = ""
	_, err = p.s.run(ctx, ev, ran, nil, client{})
	_ = wantType(t, err, ErrCapabilityNotGranted, "revoked meanwhile")
}

func TestReceiptCollisionIsAConflict(t *testing.T) {
	p, srv := bootUnit(t, Config{})
	ctx := context.Background()
	a := newAgent(t, p, nil)
	r, err := p.s.appendReceipt(ctx, a, nil, "x", inputHash(nil), OutcomeSuccess, nil, nil)
	must(t, err)
	// Another writer appended the same seq meanwhile: the unique (agent_id, seq) refuses it.
	colliding := *p.s
	colliding.db = staleLast{Adapter: srv.Graph().DB(), row: r.row()}
	_, err = colliding.appendReceipt(ctx, a, nil, "x", inputHash(nil), OutcomeSuccess, nil, nil)
	if e := wantType(t, err, ErrConflict, "collision"); e.Status() != 409 {
		t.Error(e.Status())
	}
}

// staleLast answers an out-of-date last receipt, as a concurrent append leaves it.
type staleLast struct {
	store.Adapter
	row store.Row
}

func (s staleLast) FindMany(ctx context.Context, table string, c store.Criteria, q store.Query) ([]store.Row, error) {
	if table == TableReceipts {
		prev := store.Row{}
		for k, v := range s.row {
			prev[k] = v
		}
		prev["seq"] = int64(0)
		return []store.Row{prev}, nil
	}
	return s.Adapter.FindMany(ctx, table, c, q)
}

func TestEventsAreAuditableWithTheAgentAsActor(t *testing.T) {
	a := Agent{ID: "agent-1", OwnerType: OwnerUser, OwnerID: "user-1", OrganizationID: "org-1"}
	e := byAgent(EventExecuted, a, map[string]any{"capability": "deploy"}, client{}).AuditEvent(time.Now())
	if e.ActorType != "agent" || e.ActorID != "agent-1" || e.SubjectID != "user-1" || e.OrganizationID != "org-1" || mustJSON(e.Data) != `{"agent_id":"agent-1","capability":"deploy"}` {
		t.Errorf("%+v", e)
	}
	if byUser(EventRevoked, a, "user-1", nil, client{}).AuditEvent(time.Now()).ActorType != "user" || bySystem(EventRevoked, a, nil).EventName() != EventRevoked {
		t.Error("user / system")
	}
	if (&Error{Type: "other"}).Status() != 400 || !strings.Contains((&Error{Type: ErrSealed, Detail: "d"}).Error(), "sealed") {
		t.Error("error basics")
	}
}

func TestTheDiscoveryDocumentMatchesTheProtocolSchema(t *testing.T) {
	p, srv := bootUnit(t, Config{})
	doc := p.discovery()
	for _, k := range []string{"version", "provider_name", "description", "issuer", "default_location", "algorithms", "modes", "approval_methods", "approval_strengths", "endpoints", "token_endpoint"} {
		if doc[k] == nil {
			t.Errorf("missing %s", k)
		}
	}
	endpoints := doc["endpoints"].(map[string]any)
	for _, k := range []string{"register", "enroll", "capabilities", "execute", "request_capability", "status", "revoke", "grants", "approvals", "receipts", "token"} {
		if s, _ := endpoints[k].(string); !strings.HasPrefix(s, "https://") {
			t.Errorf("endpoint %s", k)
		}
	}
	if doc["default_location"] != endpoints["execute"] || doc["token_endpoint"] != unitBase+"/oauth2/token" || endpoints["mcp"] != nil {
		t.Error("discovery")
	}
	w := httptest.NewRecorder()
	p.DiscoveryHandler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/.well-known/agent-configuration", nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "3600") {
		t.Error("root handler")
	}
	if Of(srv.Graph()) != p {
		t.Error("Of")
	}
	if names := p.AuditNames(); len(names) != 13 {
		t.Error("audit names")
	}
	if perms := p.Permissions(); perms["deploy.staging"] == "" || perms["members.read"] != "" {
		t.Errorf("permissions %v", perms)
	}
}
