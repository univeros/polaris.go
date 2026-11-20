package sentinel

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
)

func check(t *testing.T, cond bool, format string, args ...any) {
	t.Helper()
	if !cond {
		t.Fatalf(format, args...)
	}
}

var at = time.Date(2026, 9, 11, 10, 0, 0, 0, time.UTC)

func counters() (*CacheCounters, *cache.Memory, *clock.Frozen) {
	clk := clock.NewFrozen(at)
	c := cache.NewMemory(clk)
	return NewCacheCounters(c, clk), c, clk
}

func eval(t *testing.T, s Signal, a Attempt) Verdict {
	t.Helper()
	a.Email = strings.ToLower(strings.TrimSpace(a.Email))
	v, err := s.Evaluate(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVelocityScoresEachDimensionOverItsLimitAndResets(t *testing.T) {
	ctx := context.Background()
	c, _, _ := counters()
	v := velocity{counters: c, limits: map[string]Limit{"ip": {2, 10 * time.Minute}, "email": {3, 10 * time.Minute}}, score: 50}
	a := Attempt{Kind: SignIn, Email: "Ada@Example.com ", IP: "203.0.113.7", DeviceID: "dev-1"}

	check(t, eval(t, v, a).Score == 0 && eval(t, v, a).Score == 0, "under the limits")
	third := eval(t, v, a)
	check(t, third.Score == 50 && slices.Equal(third.Reasons, []string{"ip: 3 attempts in 600 s (limit 2)"}), "the address is over: %+v", third)
	check(t, eval(t, v, a).Score == 100, "the address and the email")
	check(t, v.Reset(ctx, "203.0.113.7") == nil && eval(t, v, a).Score == 50, "the email still counts")
	check(t, v.Reset(ctx, "ada@example.com") == nil && eval(t, v, a).Score == 0, "cleared")
	check(t, eval(t, v, Attempt{Kind: SignUp}).Score == 0, "nothing to count")
}

func TestTheCounterStoreWindowsRollWithTheClock(t *testing.T) {
	ctx := context.Background()
	c, _, clk := counters()
	n1, _ := c.Increment(ctx, "k", time.Minute)
	n2, _ := c.Increment(ctx, "k", time.Minute)
	n, _ := c.Count(ctx, "k", time.Minute)
	check(t, n1 == 1 && n2 == 2 && n == 2, "%d %d %d", n1, n2, n)
	clk.Advance(2 * time.Minute)
	n, _ = c.Count(ctx, "k", time.Minute)
	check(t, n == 0, "a new window")
	n, _ = c.Increment(ctx, "k", time.Minute)
	check(t, n == 1 && c.Reset(ctx, "k", time.Minute) == nil, "reset")
	n, _ = c.Count(ctx, "k", time.Minute)
	check(t, n == 0, "after reset")
	check(t, NewCacheCounters(cache.NewMemory(nil), nil) != nil, "nil clock")
}

func TestCredentialStuffingSeesManyAccountsAndFailuresFromOneAddress(t *testing.T) {
	ctx := context.Background()
	c, mem, _ := counters()
	s := &stuffing{counters: c, seen: &seenSet{cache: mem}, window: 10 * time.Minute, distinctEmails: 3, minAttempts: 4, failureRatio: 0.75, score: 60}
	addr := "203.0.113.7"

	check(t, eval(t, s, Attempt{Kind: SignUp, Email: "a@example.com", IP: addr}).Score == 0, "sign-ins only")
	check(t, eval(t, s, Attempt{Kind: SignIn, Email: "a@example.com"}).Score == 0, "no address, nothing to key on")
	check(t, eval(t, s, Attempt{Kind: SignIn, Email: "a@example.com", IP: addr}).Score == 0, "one")
	check(t, eval(t, s, Attempt{Kind: SignIn, Email: "b@example.com", IP: addr}).Score == 0, "two")
	third := eval(t, s, Attempt{Kind: SignIn, Email: "c@example.com", IP: addr})
	check(t, third.Score == 60 && slices.Equal(third.Reasons, []string{"3 distinct accounts from one address in 600 s"}), "%+v", third)

	for range 3 {
		check(t, s.failed(ctx, addr) == nil, "failed")
	}
	check(t, s.failed(ctx, "") == nil, "no address")
	fourth := eval(t, s, Attempt{Kind: SignIn, Email: "a@example.com", IP: addr})
	check(t, fourth.Score == 120 && fourth.Reasons[1] == "3 of 4 sign-ins from the address failed", "both reasons (the policy caps the sum): %+v", fourth)
	check(t, s.Reset(ctx, addr) == nil && eval(t, s, Attempt{Kind: SignIn, Email: "a@example.com", IP: addr}).Score == 0, "reset")
}

func TestTheDistinctEmailSetIsBounded(t *testing.T) {
	ctx := context.Background()
	set := &seenSet{cache: cache.NewMemory(clock.NewFrozen(at))}
	for i := range maxTrackedEmails + 5 {
		n, err := set.add(ctx, "ip", strings.Repeat("x", i+1), time.Minute)
		check(t, err == nil && n == min(i+1, maxTrackedEmails), "%d: %d %v", i, n, err)
	}
	n, _ := set.add(ctx, "ip", "x", time.Minute)
	check(t, n == maxTrackedEmails, "a known member does not grow the set")
}

func TestDisposableEmailUsesTheBundledListPlusTheApplicationsOnSignUp(t *testing.T) {
	extra, _ := ParseDomains(strings.NewReader(""), "Trash.Example")
	s := disposable{domains: withExtra{base: BundledDomains(), extra: extra}, kinds: []string{SignUp}, score: 60}
	check(t, eval(t, s, Attempt{Kind: SignUp, Email: "x@mailinator.com"}).Score == 60, "bundled")
	check(t, eval(t, s, Attempt{Kind: SignUp, Email: "x@trash.example"}).Score == 60, "extra")
	check(t, eval(t, s, Attempt{Kind: SignUp, Email: "x@example.com"}).Score == 0, "clean")
	check(t, eval(t, s, Attempt{Kind: SignIn, Email: "x@mailinator.com"}).Score == 0, "sign-ups only by default")
	check(t, eval(t, s, Attempt{Kind: SignUp, Email: "not-an-email"}).Score == 0, "not an email")
	check(t, eval(t, s, Attempt{Kind: SignUp}).Score == 0, "no email")
}

type tokenVerifier string

func (v tokenVerifier) Verify(_ context.Context, token, _ string) bool { return token == string(v) }

func TestBotIsSilentWithoutATokenProvesAPassedChallengeOrScoresAGuess(t *testing.T) {
	s := bot{verifier: tokenVerifier("good"), score: 80}
	check(t, eval(t, s, Attempt{Kind: SignUp}).Score == 0, "silent")
	passed := eval(t, s, Attempt{Kind: SignUp, CaptchaToken: "good"})
	check(t, passed.Score == 0 && passed.PassedChallenge, "%+v", passed)
	guess := eval(t, s, Attempt{Kind: SignUp, CaptchaToken: "bad"})
	check(t, guess.Score == 80 && !guess.PassedChallenge && slices.Equal(guess.Reasons, []string{"captcha token invalid"}), "%+v", guess)
}

type onlyBreached string

func (b onlyBreached) IsBreached(_ context.Context, pw string) bool { return pw == string(b) }

func TestBreachedPasswordChecksNewPasswordsOnly(t *testing.T) {
	s := breached{checker: onlyBreached("password1"), kinds: []string{SignUp, PasswordReset}, score: 50}
	check(t, eval(t, s, Attempt{Kind: SignUp, Password: "password1"}).Score == 50, "breached")
	check(t, eval(t, s, Attempt{Kind: SignUp, Password: "correct horse battery staple"}).Score == 0, "clean")
	check(t, eval(t, s, Attempt{Kind: SignIn, Password: "password1"}).Score == 0, "a sign-in is not a new password")
	check(t, eval(t, s, Attempt{Kind: SignUp}).Score == 0, "no password")
}

func TestThePolicySumsCapsAndMapsTheScore(t *testing.T) {
	p := Policy{}
	quiet := p.Decide([]Verdict{silent("a"), silent("b")}, true)
	check(t, quiet.Action == Allow && quiet.Score == 0 && len(quiet.Verdicts) == 0 && quiet.Enforced && len(quiet.Reasons()) == 0, "%+v", quiet)

	ch := p.Decide([]Verdict{{Signal: "a", Score: 30, Reasons: []string{"x"}}, {Signal: "b", Score: 10, Reasons: []string{"y"}}}, false)
	check(t, ch.Action == Challenge && ch.Score == 40 && slices.Equal(ch.Signals(), []string{"a", "b"}) && slices.Equal(ch.Reasons(), []string{"x", "y"}) && !ch.Enforced, "%+v", ch)
	block := p.Decide([]Verdict{{Signal: "a", Score: 70}, {Signal: "b", Score: 70}}, true)
	check(t, block.Action == Block && block.Score == 100, "%+v", block)
	cleared := p.Decide([]Verdict{{Signal: "ip_list", Score: -100, Reasons: []string{"allowed"}}, {Signal: "a", Score: 70}}, true)
	check(t, cleared.Action == Allow && cleared.Score == 0 && slices.Equal(cleared.Signals(), []string{"ip_list", "a"}), "%+v", cleared)
	passed := p.Decide([]Verdict{{Signal: "a", Score: 60}, {Signal: "bot", Reasons: []string{"captcha passed"}, PassedChallenge: true}}, true)
	check(t, passed.Action == Allow && passed.Score == 60 && slices.Equal(passed.Signals(), []string{"a", "bot"}), "a passed challenge allows: %+v", passed)
	check(t, p.Decide([]Verdict{{Signal: "a", Score: 90}, {Signal: "bot", PassedChallenge: true}}, true).Action == Block, "a block stays a block")
	custom := Policy{ChallengeAt: 20, BlockAt: 50}
	check(t, custom.Decide([]Verdict{{Signal: "a", Score: 20}}, true).Action == Challenge && custom.Decide([]Verdict{{Signal: "a", Score: 50}}, true).Action == Block, "custom")
}

func TestTheSiteVerifiersPostTheSecretTheTokenAndTheAddress(t *testing.T) {
	var form url.Values
	var ctype string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ = url.ParseQuery(string(raw))
		ctype = r.Header.Get("Content-Type")
		switch form.Get("response") {
		case "tok":
			_, _ = io.WriteString(w, `{"success": true}`)
		case "500":
			w.WriteHeader(500)
		default:
			_, _ = io.WriteString(w, `{"success": false, "error-codes": ["invalid-input-response"]}`)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	v := Turnstile("secret-1")
	check(t, v.Endpoint == TurnstileEndpoint && HCaptcha("s").Endpoint == HCaptchaEndpoint, "endpoints")
	v.Endpoint = srv.URL
	check(t, v.Verify(ctx, "tok", "203.0.113.7"), "verified")
	check(t, form.Encode() == "remoteip=203.0.113.7&response=tok&secret=secret-1" && ctype == "application/x-www-form-urlencoded", "form %v %s", form, ctype)
	check(t, !v.Verify(ctx, "nope", "") && form.Get("remoteip") == "", "a refused token; no address sent when unknown")
	check(t, !v.Verify(ctx, "500", ""), "a server error fails")
	check(t, !(&SiteVerifier{Endpoint: "http://127.0.0.1:1"}).Verify(ctx, "tok", ""), "a transport failure fails the verification")
	check(t, !(&SiteVerifier{Endpoint: "::"}).Verify(ctx, "tok", ""), "a bad endpoint fails")
}

func TestTheDomainListReadsAFileWithCommentsAndTheExtras(t *testing.T) {
	file := filepath.Join(t.TempDir(), "list.txt")
	if err := os.WriteFile(file, []byte("# a comment\nTrash.Example\n\n  other.example  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	list, err := Config{DisposableListFile: file, DisposableDomains: []string{"Third.Example"}}.domains()
	check(t, err == nil, "%v", err)
	check(t, list.Contains("trash.example") && list.Contains("OTHER.example") && list.Contains("third.example"), "listed")
	check(t, !list.Contains("example.com") && !list.Contains("mailinator.com"), "the bundled list is not read when a file is given")
	own := Domains{"x.example": {}}
	got, _ := Config{Domains: own}.domains()
	check(t, got.Contains("x.example") && !got.Contains("mailinator.com"), "a host's list replaces everything")
	check(t, BundledDomains().Contains("mailinator.com"), "the bundled list")
}

func TestGeometryAndTheResolverWithoutADatabase(t *testing.T) {
	paris, newYork := GeoPoint{48.8566, 2.3522}, GeoPoint{40.7128, -74.0060}
	check(t, math.Abs(paris.DistanceTo(newYork)-5837) < 5, "%f", paris.DistanceTo(newYork))
	check(t, paris.DistanceTo(paris) == 0, "zero")
	_, ok := NoGeo{}.Resolve(context.Background(), "203.0.113.7")
	check(t, !ok, "no database")
}
