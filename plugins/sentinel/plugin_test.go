package sentinel_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/plugins/admin"
	"github.com/univeros/polaris-go/plugins/audit"
	"github.com/univeros/polaris-go/plugins/messaging"
	"github.com/univeros/polaris-go/plugins/sentinel"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/token"
)

var now = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)

type env struct {
	p        *polaris.Polaris
	sentinel *sentinel.Plugin
	clk      *clock.Frozen
	mail     *messaging.Memory
}

// boot is upstream's PluginTest::polaris(): core, audit, admin, messaging and the sentinel in
// memory, a frozen clock.
func boot(t *testing.T, cfg sentinel.Config) env {
	t.Helper()
	e, err := start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func start(cfg sentinel.Config) (env, error) {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	clk := clock.NewFrozen(now)
	mail := messaging.NewMemory("mail", messaging.KindEmail)
	models := slices.Concat(schema.Core(), audit.Models(), admin.Models(), messaging.Models(), sentinel.Models())
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: memstore.New(models...), Clock: clk,
		Plugins: []polaris.Plugin{audit.New(audit.Config{}), admin.New(admin.Config{}),
			messaging.New(messaging.Config{Email: mail, SMS: messaging.NewMemory("sms", messaging.KindSMS)}), sentinel.New(cfg)},
	})
	if err != nil {
		return env{}, err
	}
	return env{p: p, sentinel: sentinel.Of(p.Graph()), clk: clk, mail: mail}, nil
}

const ip = "203.0.113.7"

// guarded runs the sentinel middleware on path with body, from addr, with the device cookie
// (none when ""); the handler behind answers 201, dispatching what onPass returns.
func (e env) guarded(t *testing.T, path, body, addr, cookie string, onPass func(ctx context.Context)) *http.Response {
	t.Helper()
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if onPass != nil {
			onPass(r.Context())
		}
		if b, _ := io.ReadAll(r.Body); string(b) != body {
			t.Errorf("the endpoint reads the body %q, want %q", b, body)
		}
		endpoint.Write(w, endpoint.Data(http.StatusCreated, map[string]any{"ok": true}))
	})
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sentinel.DeviceCookie, Value: cookie})
	}
	ctx := endpoint.WithRoute(req.Context(), &manifest.Route{Path: path})
	ctx = endpoint.WithClient(ctx, token.ClientContext{IP: addr, UserAgent: "ua/1"})
	rec := httptest.NewRecorder()
	e.sentinel.Middleware(e.p.Graph())[0](next).ServeHTTP(rec, req.WithContext(ctx))
	return rec.Result()
}

func (e env) decisions(t *testing.T, f sentinel.Filter) []map[string]any {
	t.Helper()
	page, err := e.sentinel.Decisions().List(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	return page["data"].([]map[string]any)
}

func TestEverythingIsWiredThroughTheGraphAndMessagingTakesTheQuietMode(t *testing.T) {
	ctx := context.Background()
	e := boot(t, sentinel.Config{})
	g := e.p.Graph()

	var routes []string
	for _, r := range g.Manifest().Routes() {
		if slices.Contains(r.Tags, "sentinel") {
			want(t, r.Auth == manifest.AuthPublic && slices.Contains(r.Tags, "admin") && strings.HasPrefix(r.Path, "/admin/sentinel"), "%s", r.File)
			routes = append(routes, r.Method+" "+r.Path)
		}
	}
	slices.Sort(routes)
	want(t, slices.Equal(routes, []string{"DELETE /admin/sentinel/ip-rules/{id}", "GET /admin/sentinel/decisions", "GET /admin/sentinel/ip-rules",
		"POST /admin/sentinel/ip-rules", "POST /admin/sentinel/unblock"}), "routes %v", routes)
	for name := range map[string]bool{sentinel.AuditEvaluated: true, sentinel.AuditIPRuleCreated: true, sentinel.AuditIPRuleDeleted: true, sentinel.AuditUnblocked: true} {
		want(t, audit.Of(g).Catalog().Has(name), "catalog %s", name)
	}
	want(t, e.sentinel.Mode() == sentinel.Observe, "observe by default")

	if _, err := e.sentinel.Engine().Evaluate(ctx, sentinel.Attempt{Kind: sentinel.SignUp, Email: "ada@mailinator.com", IP: ip}); err != nil {
		t.Fatal(err)
	}
	sender := messaging.Of(g).Sender()
	send := func(to, template string, essential bool) error {
		_, err := sender.Send(ctx, messaging.Message{Kind: messaging.KindEmail, To: to, Template: template, Essential: essential,
			Vars: map[string]any{"ip": "1", "user_agent": "x", "token": "t"}}, nil)
		return err
	}
	want(t, errors.Is(send("ada@mailinator.com", "email.new_device", false), messaging.ErrRefused), "a challenged recipient gets no non-essential mail")
	want(t, send("ADA@mailinator.com", "email.verify", true) == nil, "an essential one goes")
	_, err := sender.Deliver(ctx, messaging.Message{Kind: messaging.KindSMS, To: "+15551234567", Template: "sms.otp", Text: "x"}, nil)
	want(t, err == nil, "an SMS is not quiet: %v", err)
	want(t, send("bob@example.com", "email.new_device", false) == nil, "another recipient")
	e.clk.Advance(sentinel.QuietWindow + time.Second)
	want(t, send("ada@mailinator.com", "email.new_device", false) == nil, "quiet mode ends after the window")
}

func TestObserveModeRecordsWhatASignalSaidAndLetsEverythingThrough(t *testing.T) {
	e := boot(t, sentinel.Config{})
	clean := e.guarded(t, "/auth/register", `{"email":"ada@example.com","password":"x"}`, ip, "", nil)
	want(t, clean.StatusCode == 201, "status %d", clean.StatusCode)
	cookie := regexp.MustCompile(`^polaris_device=[0-9a-f]{32}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax$`)
	want(t, cookie.MatchString(clean.Header.Get("Set-Cookie")), "a device cookie for a request without one: %q", clean.Header.Get("Set-Cookie"))
	want(t, len(e.decisions(t, sentinel.Filter{})) == 0, "silence is not recorded")

	flagged := e.guarded(t, "/auth/register", `{"email":"ada@mailinator.com","password":"x"}`, ip, "dev-1", nil)
	want(t, flagged.StatusCode == 201 && flagged.Header.Get("Set-Cookie") == "", "observe mode enforces nothing; the request had a cookie")
	d := e.decisions(t, sentinel.Filter{})[0]
	want(t, d["kind"] == "sign_up" && d["email"] == "ada@mailinator.com" && d["ip"] == ip && d["score"] == int64(60) &&
		d["action"] == "challenge" && d["enforced"] == false, "decision %v", d)
	want(t, slices.Equal(d["signals"].([]string), []string{"disposable_email"}) && slices.Equal(d["reasons"].([]string), []string{"disposable domain mailinator.com"}), "decision %v", d)
	page, err := audit.Of(e.p.Graph()).Store().Read(context.Background(), audit.Query{Names: []string{sentinel.AuditEvaluated}})
	if err != nil || len(page.Events) != 1 {
		t.Fatalf("audit %v %v", page, err)
	}
	ev := page.Events[0]
	want(t, ev.ActorType == "system" && ev.IP == ip && ev.UserAgent == "ua/1", "event %+v", ev)
	want(t, ev.Data["email_hash"] == sha("ada@mailinator.com") && ev.Data["score"] != nil && ev.Data["password"] == nil, "the email is hashed: %v", ev.Data)

	other := e.guarded(t, "/auth/me", "", ip, "", nil)
	want(t, other.StatusCode == 201 && other.Header.Get("Set-Cookie") == "", "an unguarded route is untouched")
	want(t, len(e.decisions(t, sentinel.Filter{})) == 1, "one decision")
}

func TestEnforceModeBlocksChallengesWhenACaptchaCanAnswerAndHonoursTheRules(t *testing.T) {
	ctx := context.Background()
	e := boot(t, sentinel.Config{Mode: sentinel.Enforce, Captcha: goodToken{}})
	signUp := `{"email":"ada@mailinator.com","password":"x"`

	challenged := e.guarded(t, "/auth/register", signUp+"}", ip, "d", nil)
	assertProblem(t, challenged, 403, "sentinel_challenge_required")
	want(t, e.guarded(t, "/auth/register", signUp+`,"captcha_token":"good"}`, ip, "d", nil).StatusCode == 201, "the retry with a valid token passes")
	assertProblem(t, e.guarded(t, "/auth/register", signUp+`,"captcha_token":"bad"}`, ip, "d", nil), 403, "sentinel_blocked")
	ds := e.decisions(t, sentinel.Filter{})
	want(t, ds[0]["action"] == "block" && ds[1]["action"] == "allow" && ds[2]["action"] == "challenge" && ds[0]["enforced"] == true, "newest first %v", ds)

	if _, err := e.sentinel.IPRules().Add(ctx, ip, sentinel.Allow, "office", "test"); err != nil {
		t.Fatal(err)
	}
	want(t, e.guarded(t, "/auth/register", signUp+"}", ip, "d", nil).StatusCode == 201, "an allow rule clears the address")
	want(t, slices.Equal(e.decisions(t, sentinel.Filter{})[0]["signals"].([]string), []string{"ip_list", "disposable_email"}), "signals")
	if _, err := e.sentinel.IPRules().Add(ctx, "198.51.100.0/24", sentinel.Block, "scanner", "test"); err != nil {
		t.Fatal(err)
	}
	blocked := e.guarded(t, "/auth/login", `{"email":"ada@example.com","password":"x"}`, "198.51.100.9", "d", nil)
	b := assertProblem(t, blocked, 403, "sentinel_blocked")
	want(t, b["detail"] == "The request was refused.", "generic detail")
	want(t, slices.Equal(e.decisions(t, sentinel.Filter{IP: "198.51.100.9"})[0]["reasons"].([]string), []string{"address blocked by rule 198.51.100.0/24"}), "reason recorded")
	_, err := e.sentinel.IPRules().Add(ctx, "nowhere", sentinel.Block, "", "")
	want(t, errors.Is(err, sentinel.ErrInvalidRule), "invalid rule: %v", err)
}

func TestWithoutACaptchaVerifierTheChallengeBandIsRecordedAndLetThrough(t *testing.T) {
	e := boot(t, sentinel.Config{Mode: sentinel.Enforce})
	want(t, e.guarded(t, "/auth/register", `{"email":"ada@mailinator.com","password":"x"}`, ip, "", nil).StatusCode == 201, "let through")
	d := e.decisions(t, sentinel.Filter{})[0]
	want(t, d["action"] == "challenge" && d["enforced"] == true, "%v", d)
}

// geo places two addresses.
type geo struct{}

func (geo) Resolve(_ context.Context, addr string) (sentinel.GeoPoint, bool) {
	switch addr {
	case ip:
		return sentinel.GeoPoint{Latitude: 48.8566, Longitude: 2.3522}, true
	case "198.51.100.9":
		return sentinel.GeoPoint{Latitude: 40.7128, Longitude: -74.0060}, true
	}
	return sentinel.GeoPoint{}, false
}

func TestTheListenerRecordsDevicesAndFailuresForTheDeviceTravelAndStuffingSignals(t *testing.T) {
	ctx := context.Background()
	big := map[string]sentinel.Limit{"ip": {100, 10 * time.Minute}, "email": {100, 10 * time.Minute}, "device": {100, 10 * time.Minute}}
	e := boot(t, sentinel.Config{Geo: geo{}, Velocity: big})
	g := e.p.Graph()
	if err := g.Repos().Users.Insert(ctx, model.User{ID: "u1", Email: "ada@example.com", Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	engine := e.sentinel.Engine()
	eval := func(email, addr, device string) sentinel.Decision {
		t.Helper()
		d, err := engine.Evaluate(ctx, sentinel.Attempt{Kind: sentinel.SignIn, Email: email, IP: addr, DeviceID: device})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	signIn := func(addr, device string) {
		t.Helper()
		e.guarded(t, "/auth/login", `{"email":"ada@example.com"}`, addr, device, func(ctx context.Context) {
			a := addr
			g.Events().Dispatch(ctx, event.UserLoggedIn{UserID: "u1", SessionID: "s", IP: &a})
		})
	}

	want(t, eval("ada@example.com", ip, "dev-1").Action == sentinel.Allow, "no known device yet")
	signIn(ip, "dev-1")
	want(t, eval("ada@example.com", ip, "dev-1").Score == 0, "the known device from the same place")
	e.clk.Advance(time.Hour)
	travel := eval("ada@example.com", "198.51.100.9", "dev-2")
	want(t, travel.Action == sentinel.Block && travel.Score == 100 && slices.Equal(travel.Signals(), []string{"device", "impossible_travel"}), "travel %+v", travel)
	want(t, travel.Reasons()[0] == "unknown device" && strings.Contains(travel.Reasons()[1], "km/h"), "reasons %v", travel.Reasons())
	want(t, slices.Equal(eval("ada@example.com", ip, "").Reasons(), []string{"no device cookie"}), "no cookie")
	want(t, eval("bob@example.com", "198.51.100.9", "dev-9").Score == 0, "an unknown user has no devices")
	signIn("198.51.100.9", "dev-2")
	n, _ := g.DB().Count(ctx, sentinel.TableDevices, map[string]any{"user_id": "u1"})
	want(t, n == 2, "the device of the attempt in flight: %d", n)
	signIn("198.51.100.9", "dev-2")
	n, _ = g.DB().Count(ctx, sentinel.TableDevices, map[string]any{"user_id": "u1"})
	want(t, n == 2, "a known device is updated, not duplicated: %d", n)

	failed := "192.0.2.1"
	for range 10 {
		eval("ada@example.com", failed, "dev-1")
		g.Events().Dispatch(ctx, event.UserLoginFailed{UserID: "u1", IP: &failed})
	}
	stuffed := eval("ada@example.com", failed, "dev-1")
	want(t, slices.Contains(stuffed.Signals(), sentinel.SignalCredentialStuffing) && stuffed.Reasons()[0] == "10 of 11 sign-ins from the address failed", "stuffed %+v", stuffed)
}

// broken is a signal whose provider is down.
type broken struct{}

func (broken) Name() string { return "broken" }
func (broken) Evaluate(context.Context, sentinel.Attempt) (sentinel.Verdict, error) {
	return sentinel.Verdict{}, errors.New("provider down")
}

func TestTheEngineFailsOpenAndUnblockClearsTheCounters(t *testing.T) {
	ctx := context.Background()
	e := boot(t, sentinel.Config{Signals: []sentinel.Signal{broken{}}, Velocity: map[string]sentinel.Limit{"email": {1, 10 * time.Minute}}})
	engine := e.sentinel.Engine()
	a := sentinel.Attempt{Kind: sentinel.PasswordReset, Email: "ada@example.com", IP: ip}
	eval := func() sentinel.Decision {
		d, err := engine.Evaluate(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	want(t, eval().Action == sentinel.Allow, "the broken signal is skipped")
	want(t, eval().Score == 50, "the second attempt is over the email limit")
	if err := engine.Unblock(ctx, "ada@example.com"); err != nil {
		t.Fatal(err)
	}
	want(t, eval().Score == 0 && !engine.Enforces(), "cleared")
}

func TestTheListsCommandFetchesADomainListIntoAFile(t *testing.T) {
	ctx := context.Background()
	lists := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "# source\nA.example\n\nb.example\na.example\n")
	}))
	defer lists.Close()
	file := filepath.Join(t.TempDir(), "domains.txt")
	e := boot(t, sentinel.Config{})

	_, err := e.sentinel.RefreshDomainList(ctx, "", file)
	want(t, err != nil, "no URL, nothing fetched")
	_, err = e.sentinel.RefreshDomainList(ctx, lists.URL, "")
	want(t, err != nil, "no file: the bundled list is embedded")
	n, err := e.sentinel.RefreshDomainList(ctx, lists.URL+"/list", file)
	want(t, err == nil && n == 2, "wrote %d %v", n, err)
	raw, _ := os.ReadFile(file)
	want(t, string(raw) == "# Disposable email domains, one per line. Source: "+lists.URL+"/list.\na.example\nb.example\n", "file %q", raw)
	_, err = e.sentinel.RefreshDomainList(ctx, lists.URL+"/missing", file)
	want(t, err != nil && strings.Contains(err.Error(), "HTTP 404"), "%v", err)
	_, err = e.sentinel.RefreshDomainList(ctx, "http://127.0.0.1:1/x", file)
	want(t, err != nil, "unreachable")

	listed := boot(t, sentinel.Config{DisposableListFile: file, DisposableDomains: []string{"Trash.Example"}})
	d, _ := listed.sentinel.Engine().Evaluate(ctx, sentinel.Attempt{Kind: sentinel.SignUp, Email: "x@b.example"})
	want(t, d.Score == 60, "the file's list")
	d, _ = listed.sentinel.Engine().Evaluate(ctx, sentinel.Attempt{Kind: sentinel.SignUp, Email: "x@trash.example"})
	want(t, d.Score == 60, "the extra domains")
	d, _ = listed.sentinel.Engine().Evaluate(ctx, sentinel.Attempt{Kind: sentinel.SignUp, Email: "x@mailinator.com"})
	want(t, d.Score == 0, "the bundled list is replaced by the file")
}

func TestStartupErrorsNameTheirFix(t *testing.T) {
	for name, cfg := range map[string]sentinel.Config{
		"Config.Mode":               {Mode: "loud"},
		"Config.Velocity":           {Velocity: map[string]sentinel.Limit{"ip": {0, time.Minute}}},
		"Config.DisposableListFile": {DisposableListFile: "/nowhere/list.txt"},
	} {
		_, err := start(cfg)
		want(t, err != nil && strings.Contains(err.Error(), name), "%s: %v", name, err)
	}
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	_, err := polaris.New(polaris.Config{Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth: auth, DB: memstore.New(slices.Concat(schema.Core(), sentinel.Models())...), Plugins: []polaris.Plugin{sentinel.New(sentinel.Config{})}})
	want(t, err != nil && strings.Contains(err.Error(), "admin.New"), "admin is required: %v", err)
}

func TestTheBreachCheckerServesCoresPortAndTheSignal(t *testing.T) {
	checker := breachedOnly("password1")
	e := boot(t, sentinel.Config{Breaches: checker})
	want(t, e.p.Graph().Breaches().IsBreached(context.Background(), "password1"), "core's port is the sentinel's checker")
	d, _ := e.sentinel.Engine().Evaluate(context.Background(), sentinel.Attempt{Kind: sentinel.SignUp, Password: "password1"})
	want(t, slices.Equal(d.Signals(), []string{sentinel.SignalBreachedPassword}), "%v", d.Signals())
	plain := boot(t, sentinel.Config{})
	_, none := plain.p.Graph().Breaches().(security.NoBreachCheck)
	want(t, none, "no checker, core's default")
}

type breachedOnly string

func (b breachedOnly) IsBreached(_ context.Context, pw string) bool { return pw == string(b) }

func assertProblem(t *testing.T, resp *http.Response, status int, code string) map[string]any {
	t.Helper()
	b := contracttest.JSON(t, resp)
	want(t, resp.StatusCode == status && resp.Header.Get("Content-Type") == "application/problem+json" && b["error"] == code &&
		b["detail"] == b["message"], "problem %d %v", resp.StatusCode, b)
	return b
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestAFormBodyIsJudgedLikeJSON(t *testing.T) {
	e := boot(t, sentinel.Config{Mode: sentinel.Enforce, Captcha: goodToken{}})
	req := httptest.NewRequest(http.MethodPost, "/auth/register", strings.NewReader("email=ada%40mailinator.com&password=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ctx := endpoint.WithRoute(req.Context(), &manifest.Route{Path: "/auth/register"})
	rec := httptest.NewRecorder()
	e.sentinel.Middleware(e.p.Graph())[0](http.NotFoundHandler()).ServeHTTP(rec, req.WithContext(ctx))
	want(t, rec.Code == http.StatusForbidden, "the form's email is judged: %d", rec.Code)
}
