package contracttest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// echo answers every request with what it received.
var echo = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Date", "Tue, 10 Sep 2026 12:00:00 GMT")
	if r.URL.Path == "/created" {
		w.WriteHeader(http.StatusCreated)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"method":        r.Method,
		"path":          r.URL.Path,
		"query":         r.URL.RawQuery,
		"host":          r.Host,
		"remote":        r.RemoteAddr,
		"tls":           r.TLS != nil,
		"authorization": r.Header.Get("Authorization"),
		"content_type":  r.Header.Get("Content-Type"),
		"cookie":        r.Header.Get("Cookie"),
		"csrf":          r.Header.Get("X-Polaris-CSRF"),
		"body":          string(body),
		"id":            "0190a8b2-1234-7abc-8def-0123456789ab",
	})
})

type echoed struct {
	Method, Path, Query, Host, Remote, Authorization, Cookie, CSRF, Body string
	ContentType                                                          string `json:"content_type"`
	TLS                                                                  bool
}

func TestClientBuildsRequestsLikeThePHPHarness(t *testing.T) {
	c := NewClient(t, echo, nil)

	got := Decode[echoed](t, c.Get("/auth/me?x=1", Bearer("tok")))
	want := echoed{Method: "GET", Path: "/auth/me", Query: "x=1", Authorization: "Bearer tok"}
	if got != want {
		t.Errorf("Get: %+v", got)
	}

	got = Decode[echoed](t, c.Post("https://localhost/auth/token/refresh", nil,
		Cookie("__Secure-polaris_refresh", "r1"), Header("X-Polaris-CSRF", "1"), RemoteAddr("203.0.113.7:1234")))
	want = echoed{Method: "POST", Path: "/auth/token/refresh", Host: "localhost", Remote: "203.0.113.7:1234", TLS: true,
		Cookie: "__Secure-polaris_refresh=r1", CSRF: "1", Body: "{}", ContentType: "application/json"}
	if got != want {
		t.Errorf("Post: %+v", got)
	}

	got = Decode[echoed](t, c.Patch("/orgs/1", map[string]string{"name": "Acme"}))
	if got.Method != "PATCH" || got.Body != `{"name":"Acme"}` {
		t.Errorf("Patch: %+v", got)
	}
	got = Decode[echoed](t, c.Delete("/orgs/1"))
	if got.Method != "DELETE" || got.Body != "" || got.ContentType != "" {
		t.Errorf("Delete: %+v", got)
	}
	got = Decode[echoed](t, c.Form("/oauth2/token", url.Values{"grant_type": {"client_credentials"}}))
	if got.Body != "grant_type=client_credentials" || got.ContentType != "application/x-www-form-urlencoded" {
		t.Errorf("Form: %+v", got)
	}
	got = Decode[echoed](t, c.JSONRequest(http.MethodPut, "/scim/v2/Users/1", []int{1}))
	if got.Method != "PUT" || got.Body != "[1]" {
		t.Errorf("JSONRequest: %+v", got)
	}
}

func TestJSONHelpers(t *testing.T) {
	c := NewClient(t, echo, nil)
	resp := c.Get("/x")
	if JSON(t, resp)["method"] != "GET" {
		t.Fatal("JSON")
	}
	if JSON(t, resp)["path"] != "/x" {
		t.Fatal("the body is not readable twice")
	}
	text := NewClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[1]")) }), nil)
	if m := JSON(t, text.Get("/")); m == nil || len(m) != 0 {
		t.Fatalf("a non-object body gave %#v", m)
	}
}

func TestClientRejectsUnencodableBodies(t *testing.T) {
	ft := &fatalTB{TB: t}
	runFatal(func() { NewClient(ft, echo, nil).Post("/x", func() {}) })
	if !ft.failed {
		t.Fatal("an unencodable body was sent")
	}
	text := NewClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("nope")) }), nil)
	ft = &fatalTB{TB: t}
	runFatal(func() { Decode[echoed](ft, text.Get("/x")) })
	if !ft.failed {
		t.Fatal("Decode accepted a non-JSON body")
	}
}

// TestRecordThenReplay records a test's steps, then replays the written fixture.
func TestRecordThenReplay(t *testing.T) {
	dir := t.TempDir()
	const class, method = `Polaris\Tests\Functional\EchoTest`, "testEcho"
	issue := func(c *Client) {
		c.Post("/created", map[string]any{"email": "ada@example.com", "n": 1.5})
		c.Get("https://auth.polaris.test/orgs/0190a8b2-0000-7000-8000-000000000000?code=abc", Bearer("t"))
		c.Delete("/x")
	}
	t.Run("record", func(t *testing.T) {
		t.Setenv(RecordEnv, "1")
		issue(NewClient(t, echo, For(t, dir, class, method)))
	})
	raw, err := os.ReadFile(filepath.Join(dir, "Polaris.Tests.Functional.EchoTest.testEcho.json"))
	if err != nil {
		t.Fatal(err)
	}
	var steps []map[string]map[string]any
	if err := json.Unmarshal(raw, &steps); err != nil || len(steps) != 3 {
		t.Fatalf("%d steps, %v\n%s", len(steps), err, raw)
	}
	if !strings.Contains(string(raw), "\n    {\n        \"request\": {\n            \"method\": \"POST\",\n            \"uri\": \"/created\",") {
		t.Errorf("not PHP's pretty-printed shape:\n%s", raw[:200])
	}
	first := steps[0]
	if !reflect.DeepEqual(first["request"]["body"], map[string]any{"email": "ada@example.com", "n": 1.5}) ||
		first["response"]["status"] != 201.0 {
		t.Errorf("step 1: %v", first)
	}
	if steps[2]["request"]["body"] != "" || !reflect.DeepEqual(steps[2]["request"]["headers"], []any{}) {
		t.Errorf("step 3: %v", steps[2])
	}
	t.Run("replay", func(t *testing.T) {
		issue(NewClient(t, echo, For(t, dir, class, method)))
	})
}

func TestFailedRecordingIsNotWritten(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(RecordEnv, "1")
	ft := &fatalTB{TB: t}
	runFatal(func() {
		f := For(ft, dir, `A\T`, "test")
		NewClient(ft, echo, f).Get("/x")
		ft.Errorf("the test fails")
	})
	ft.cleanup()
	if _, err := os.Stat(filepath.Join(dir, "A.T.test.json")); !os.IsNotExist(err) {
		t.Fatal("a failed test's recording was written")
	}
}

func TestForFailsWithoutAFixture(t *testing.T) {
	ft := &fatalTB{TB: t}
	runFatal(func() { For(ft, t.TempDir(), `A\T`, "test") })
	if !ft.failed || !strings.Contains(ft.msg, RecordEnv) {
		t.Fatalf("For: failed=%v %q", ft.failed, ft.msg)
	}
}

func TestReplayMismatchFailsTheTest(t *testing.T) {
	dir := Fixtures(t, "core")
	ft := &fatalTB{TB: t}
	runFatal(func() {
		c := NewClient(ft, echo, For(ft, dir, `Polaris\Tests\Functional\JwksEndpointTest`, "testServesTheJwkSetOverHttp"))
		c.Get("/auth/.well-known/jwks.json")
	})
	if !ft.failed || !strings.Contains(ft.msg, "step 1 GET /auth/.well-known/jwks.json") {
		t.Fatalf("mismatch: failed=%v %q", ft.failed, ft.msg)
	}
	var nilFixture *Fixture
	nilFixture.AssertConsumed(t)
	unconsumed := &fatalTB{TB: t}
	loadFixture(t, dir, loginTest).AssertConsumed(unconsumed)
	if !unconsumed.failed {
		t.Fatal("an unconsumed fixture passed")
	}
}

func TestCompareReadsBodylessResponses(t *testing.T) {
	f := &Fixture{test: "x", steps: []step{{method: "GET", uri: "/", status: 204, headers: map[string][]string{}, body: ""}}}
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	f.Compare(t, req, &http.Response{StatusCode: 204, Header: http.Header{}})
	if err := f.consumed(); err != nil {
		t.Fatal(err)
	}
}

// fatalTB records failures instead of reporting them; Fatal ends the goroutine, as testing does.
type fatalTB struct {
	testing.TB
	failed   bool
	msg      string
	cleanups []func()
}

func (f *fatalTB) Helper()           {}
func (f *fatalTB) Failed() bool      { return f.failed }
func (f *fatalTB) Cleanup(fn func()) { f.cleanups = append(f.cleanups, fn) }
func (f *fatalTB) Error(args ...any) {
	f.failed, f.msg = true, strings.TrimSpace(fmt.Sprintln(args...))
}
func (f *fatalTB) Errorf(s string, a ...any) { f.Error(fmt.Sprintf(s, a...)) }
func (f *fatalTB) Fatal(args ...any)         { f.Error(args...); runtime.Goexit() }
func (f *fatalTB) Fatalf(s string, a ...any) { f.Errorf(s, a...); runtime.Goexit() }
func (f *fatalTB) cleanup() {
	for i := len(f.cleanups) - 1; i >= 0; i-- {
		f.cleanups[i]()
	}
}

// runFatal runs fn on its own goroutine, so a Fatal in it ends only fn.
func runFatal(fn func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	<-done
}
