package sentinel_test

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/sentinel"
	"github.com/univeros/polaris.go/polaristest"
)

const (
	password = "correct horse battery staple"
	operator = "operator@example.com"
	clientIP = "203.0.113.7"
	deviceID = "device-of-the-fixtures"
)

// goodToken is a captcha verifier accepting the token "good".
type goodToken struct{}

func (goodToken) Verify(_ context.Context, token, _ string) bool { return token == "good" }

// flow is upstream's SentinelTestCase: audit, admin and the sentinel under the pipeline, every
// request from clientIP with the device cookie (so no Set-Cookie lands in a fixture).
type flow struct {
	t     *testing.T
	srv   *polaristest.Server
	c     *contracttest.Client
	admin *admin.Plugin
}

func newFlow(t *testing.T, cfg sentinel.Config, class, method string) *flow {
	t.Helper()
	f := &flow{t: t, admin: admin.New(admin.Config{})}
	// Counters on a frozen clock: polaristest runs on the system clock, and a test crossing a
	// window boundary (a wall-clock multiple of 10 minutes) would split its attempts over two
	// buckets and miss the velocity signal.
	frozen := clock.NewFrozen(time.Now())
	cfg.Counters = sentinel.NewCacheCounters(cache.NewMemory(frozen), frozen)
	f.srv = polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), f.admin, sentinel.New(cfg)))
	fx := contracttest.For(t, contracttest.Fixtures(t, "sentinel"), `Polaris\Sentinel\Tests\Functional\`+class, method)
	f.c = contracttest.NewClient(t, f.srv.Handler(), fx)
	return f
}

type call struct {
	token string
	ip    string
}

func (f *flow) send(method, path string, body map[string]any, opts ...func(*call)) *http.Response {
	f.t.Helper()
	c := call{ip: clientIP}
	for _, o := range opts {
		o(&c)
	}
	options := []contracttest.Option{contracttest.RemoteAddr(c.ip + ":1234"), contracttest.Cookie(sentinel.DeviceCookie, deviceID)}
	if c.token != "" {
		options = append(options, contracttest.Bearer(c.token))
	}
	if body == nil {
		return f.c.Do(f.c.NewRequest(method, path, nil, options...))
	}
	return f.c.JSONRequest(method, path, body, options...)
}

func as(token string) func(*call) { return func(c *call) { c.token = token } }
func from(ip string) func(*call)  { return func(c *call) { c.ip = ip } }

// login registers (once), verifies and logs email in: its access token.
func (f *flow) login(email, captcha string) string {
	f.t.Helper()
	body := map[string]any{"email": email, "password": password}
	reg := map[string]any{"email": email, "password": password}
	if captcha != "" {
		reg["captcha_token"] = captcha
	}
	if f.send("POST", "/auth/register", reg).StatusCode < 300 {
		var registered event.UserRegistered
		for _, e := range f.srv.Events.All() {
			if r, ok := e.(event.UserRegistered); ok {
				registered = r
			}
		}
		f.send("POST", "/auth/email/verify", map[string]any{"token": registered.VerificationToken})
	}
	access, _ := data(f.t, f.send("POST", "/auth/login", body))["access_token"].(string)
	return access
}

// operator logs the operator in with an instance-wide grant of role.
func (f *flow) operator(role admin.Role) string {
	f.t.Helper()
	access := f.login(operator, "")
	u, err := f.srv.Graph().Repos().Users.ByEmail(context.Background(), operator)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.admin.Grants().Grant(context.Background(), admin.Grant{UserID: u.ID, Role: role}); err != nil {
		f.t.Fatal(err)
	}
	return access
}

func (f *flow) key(role admin.Role) string {
	f.t.Helper()
	_, secret, err := f.admin.Keys().Create(context.Background(), admin.Key{Name: "test", Role: role, CreatedBy: "test"})
	if err != nil {
		f.t.Fatal(err)
	}
	return secret
}

func body(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	return contracttest.JSON(t, resp)
}

func data(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := body(t, resp)["data"].(map[string]any)
	return d
}

func list(t *testing.T, resp *http.Response) []map[string]any {
	t.Helper()
	items, _ := body(t, resp)["data"].([]any)
	out := []map[string]any{}
	for _, i := range items {
		m, _ := i.(map[string]any)
		out = append(out, m)
	}
	return out
}

func column(items []map[string]any, key string) []any {
	out := []any{}
	for _, i := range items {
		out = append(out, i[key])
	}
	return out
}

func want(t *testing.T, cond bool, format string, args ...any) {
	t.Helper()
	if !cond {
		t.Fatalf(format, args...)
	}
}

// problem asserts a problem document; its body.
func problem(t *testing.T, resp *http.Response, status int, code string) map[string]any {
	t.Helper()
	b := body(t, resp)
	want(t, resp.StatusCode == status && resp.Header.Get("Content-Type") == "application/problem+json" && b["error"] == code &&
		b["type"] == "https://polaris.univeros.io/problems/"+strings.Replace(code, "_", "/", 1), "problem %d %v, want %d %s", resp.StatusCode, b, status, code)
	return b
}

func TestSentinelEnforce(t *testing.T) {
	t.Run("testAttemptsAreBlockedChallengedAndCleared", func(t *testing.T) {
		// Five attempts per email fire the velocity signal.
		f := newFlow(t, sentinel.Config{Mode: sentinel.Enforce, Captcha: goodToken{}, Velocity: map[string]sentinel.Limit{
			"ip": {100, 10 * time.Minute}, "email": {4, 10 * time.Minute}, "device": {100, 10 * time.Minute}}}, "SentinelEnforceTest", "testAttemptsAreBlockedChallengedAndCleared")
		signUp := map[string]any{"email": "ada@mailinator.com", "password": password}
		challenge := problem(t, f.send("POST", "/auth/register", signUp), 403, "sentinel_challenge_required")
		want(t, challenge["challenge"] == "captcha" && challenge["title"] == "Challenge required", "challenge %v", challenge)
		problem(t, f.send("POST", "/auth/register", map[string]any{"email": "ada@mailinator.com", "password": password, "captcha_token": "bad"}), 403, "sentinel_blocked")
		want(t, f.login("ada@mailinator.com", "good") != "", "the retry with a valid token registers, and the sign-in is clean")

		dave := map[string]any{"email": "dave@example.com", "password": "not the password"}
		for i := 1; i <= 4; i++ {
			want(t, f.send("POST", "/auth/login", dave).StatusCode == 401, "attempt %d", i)
		}
		problem(t, f.send("POST", "/auth/login", dave), 403, "sentinel_challenge_required")
		owner := f.operator(admin.RoleOwner)
		want(t, data(t, f.send("POST", "/admin/sentinel/unblock", map[string]any{"identifier": "dave@example.com"}, as(owner)))["status"] == "unblocked", "unblock")
		want(t, f.send("POST", "/auth/login", dave).StatusCode == 401, "the counters are cleared")

		f.send("POST", "/admin/sentinel/ip-rules", map[string]any{"cidr": "198.51.100.0/24", "action": "block", "note": "scanner"}, as(owner))
		blocked := problem(t, f.send("POST", "/auth/login", map[string]any{"email": "eve@example.com", "password": password}, from("198.51.100.9")), 403, "sentinel_blocked")
		want(t, blocked["detail"] == "The request was refused.", "the reason stays in the record")
		f.send("POST", "/admin/sentinel/ip-rules", map[string]any{"cidr": clientIP, "action": "allow", "note": "office"}, as(owner))
		want(t, f.send("POST", "/auth/register", map[string]any{"email": "carol@mailinator.com", "password": password}).StatusCode == 202, "an allow rule clears the disposable domain")

		decisions := list(t, f.send("GET", "/admin/sentinel/decisions", nil, as(owner)))
		want(t, slices.Equal(column(decisions, "action"), []any{"allow", "block", "challenge", "allow", "block", "challenge"}), "actions %v", column(decisions, "action"))
		reasons := list(t, f.send("GET", "/admin/sentinel/decisions?ip=198.51.100.9", nil, as(owner)))[0]["reasons"].([]any)
		want(t, len(reasons) == 1 && reasons[0] == "address blocked by rule 198.51.100.0/24", "reasons %v", reasons)
	})
}

func TestSentinelObserve(t *testing.T) {
	// Three attempts per email fire the velocity signal.
	cfg := sentinel.Config{Mode: sentinel.Observe, Velocity: map[string]sentinel.Limit{"ip": {100, 10 * time.Minute}, "email": {2, 10 * time.Minute}, "device": {100, 10 * time.Minute}}}

	t.Run("testDecisionsAreRecordedNotEnforcedAndListedForOperators", func(t *testing.T) {
		f := newFlow(t, cfg, "SentinelObserveTest", "testDecisionsAreRecordedNotEnforcedAndListedForOperators")
		want(t, f.login("ada@mailinator.com", "") != "", "a disposable domain is let through in observe mode")
		want(t, f.send("POST", "/auth/password/forgot", map[string]any{"email": "ada@mailinator.com"}).StatusCode == 202, "over the velocity limit, still let through")
		owner := f.operator(admin.RoleOwner)

		problem(t, f.send("GET", "/admin/sentinel/decisions", nil), 401, "admin_unauthorized")
		problem(t, f.send("GET", "/admin/sentinel/decisions?action=nope", nil, as(owner)), 422, "admin_invalid_input")
		problem(t, f.send("GET", "/admin/sentinel/decisions?limit=0", nil, as(owner)), 422, "admin_invalid_input")
		decisions := list(t, f.send("GET", "/admin/sentinel/decisions", nil, as(owner)))
		want(t, slices.Equal(column(decisions, "kind"), []any{"password_reset", "sign_up"}), "newest first; silence is not recorded: %v", decisions)
		want(t, decisions[0]["email"] == "ada@mailinator.com" && decisions[0]["ip"] == clientIP && decisions[0]["enforced"] == false, "%v", decisions[0])
		want(t, len(list(t, f.send("GET", "/admin/sentinel/decisions?action=challenge&limit=1", nil, as(owner)))) == 1, "limit")
		want(t, len(list(t, f.send("GET", "/admin/sentinel/decisions?action=block", nil, as(owner)))) == 0, "no block")
		want(t, len(list(t, f.send("GET", "/admin/sentinel/decisions?email=bob@example.com", nil, as(owner)))) == 0, "other email")
		want(t, len(list(t, f.send("GET", "/admin/sentinel/decisions?email=Ada@mailinator.com&ip="+clientIP, nil, as(owner)))) == 2, "email and ip")
		audited := list(t, f.send("GET", "/admin/audit?names=sentinel.evaluated", nil, as(owner)))
		want(t, slices.Equal(column(audited, "name"), []any{"sentinel.evaluated", "sentinel.evaluated"}), "audit %v", audited)
	})

	t.Run("testIpRulesNeedAnOwnerAndUnblockASupportRole", func(t *testing.T) {
		f := newFlow(t, cfg, "SentinelObserveTest", "testIpRulesNeedAnOwnerAndUnblockASupportRole")
		owner := f.operator(admin.RoleOwner)
		viewer, support := f.key(admin.RoleViewer), f.key(admin.RoleSupport)

		problem(t, f.send("POST", "/admin/sentinel/ip-rules", map[string]any{"cidr": "nowhere", "action": "block"}, as(owner)), 422, "admin_invalid_input")
		problem(t, f.send("POST", "/admin/sentinel/ip-rules", map[string]any{"cidr": "198.51.100.0/24", "action": "deny"}, as(owner)), 422, "admin_invalid_input")
		problem(t, f.send("POST", "/admin/sentinel/ip-rules", map[string]any{"cidr": "198.51.100.0/24", "action": "block", "note": strings.Repeat("n", 256)}, as(owner)), 422, "admin_invalid_input")
		problem(t, f.send("POST", "/admin/sentinel/ip-rules", map[string]any{"cidr": "198.51.100.0/24", "action": "block"}, as(support)), 403, "admin_forbidden")
		rule := data(t, f.send("POST", "/admin/sentinel/ip-rules", map[string]any{"cidr": "198.51.100.0/24", "action": "block", "note": "scanner"}, as(owner)))
		want(t, rule["cidr"] == "198.51.100.0/24" && rule["action"] == "block" && rule["note"] == "scanner", "rule %v", rule)
		allow := data(t, f.send("POST", "/admin/sentinel/ip-rules", map[string]any{"cidr": "2001:db8::/32", "action": "allow"}, as(owner)))
		want(t, allow["note"] == nil, "no note")

		problem(t, f.send("GET", "/admin/sentinel/ip-rules", nil), 401, "admin_unauthorized")
		want(t, slices.Equal(column(list(t, f.send("GET", "/admin/sentinel/ip-rules", nil, as(viewer))), "id"), []any{rule["id"], allow["id"]}), "in creation order; a viewer reads")

		problem(t, f.send("POST", "/admin/sentinel/unblock", map[string]any{"identifier": "ada@example.com"}, as(viewer)), 403, "admin_forbidden")
		problem(t, f.send("POST", "/admin/sentinel/unblock", map[string]any{"identifier": " "}, as(support)), 422, "admin_invalid_input")
		unblocked := data(t, f.send("POST", "/admin/sentinel/unblock", map[string]any{"identifier": "Ada@Example.com"}, as(support)))
		want(t, unblocked["status"] == "unblocked" && unblocked["identifier"] == "ada@example.com", "%v", unblocked)

		problem(t, f.send("DELETE", "/admin/sentinel/ip-rules/"+rule["id"].(string), nil, as(support)), 403, "admin_forbidden")
		want(t, data(t, f.send("DELETE", "/admin/sentinel/ip-rules/"+rule["id"].(string), nil, as(owner)))["status"] == "deleted", "deleted")
		problem(t, f.send("DELETE", "/admin/sentinel/ip-rules/"+rule["id"].(string), nil, as(owner)), 404, "admin_not_found")
		want(t, slices.Equal(column(list(t, f.send("GET", "/admin/sentinel/ip-rules", nil, as(owner))), "id"), []any{allow["id"]}), "one left")
		audited := list(t, f.send("GET", "/admin/audit?names=sentinel.ip_rule_created,sentinel.ip_rule_deleted,sentinel.unblocked", nil, as(owner)))
		want(t, slices.Equal(column(audited, "name"), []any{"sentinel.ip_rule_deleted", "sentinel.unblocked", "sentinel.ip_rule_created", "sentinel.ip_rule_created"}), "audit %v", column(audited, "name"))
		d := audited[1]["data"].(map[string]any)
		want(t, audited[1]["actor_type"] == "api_key" && d["kind"] == "email" && d["identifier"] == nil, "the identifier is hashed: %v", audited[1])
	})
}

func TestEverySentinelFixtureHasAGoTest(t *testing.T) {
	uncovered, err := contracttest.Uncovered(contracttest.Fixtures(t, "sentinel"), []string{
		`Polaris\Sentinel\Tests\Functional\SentinelEnforceTest::testAttemptsAreBlockedChallengedAndCleared`,
		`Polaris\Sentinel\Tests\Functional\SentinelObserveTest::testDecisionsAreRecordedNotEnforcedAndListedForOperators`,
		`Polaris\Sentinel\Tests\Functional\SentinelObserveTest::testIpRulesNeedAnOwnerAndUnblockASupportRole`,
	})
	if err != nil || len(uncovered) > 0 {
		t.Fatalf("uncovered %v %v", uncovered, err)
	}
}
