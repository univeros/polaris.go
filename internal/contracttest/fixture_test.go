package contracttest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const loginTest = `Polaris\Tests\Functional\LoginEndpointTest::testSuccessfulLoginStampsLastLoginAndClearsFailures`

// phpName turns a fixture file name back into the PHP test name.
func phpName(file string) string {
	name := strings.TrimSuffix(filepath.Base(file), ".json")
	dot := strings.LastIndex(name, ".")
	return strings.ReplaceAll(name[:dot], ".", `\`) + "::" + name[dot+1:]
}

// encode writes a decoded value back as JSON, keeping an integral float a float ("5.0").
func encode(v any) []byte {
	var b bytes.Buffer
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case object:
			b.WriteByte('{')
			for i, m := range x {
				if i > 0 {
					b.WriteByte(',')
				}
				k, _ := json.Marshal(m.key)
				b.Write(k)
				b.WriteByte(':')
				walk(m.value)
			}
			b.WriteByte('}')
		case []any:
			b.WriteByte('[')
			for i, item := range x {
				if i > 0 {
					b.WriteByte(',')
				}
				walk(item)
			}
			b.WriteByte(']')
		case float64:
			s := strconv.FormatFloat(x, 'g', -1, 64)
			if !strings.ContainsAny(s, ".eE") {
				s += ".0"
			}
			b.WriteString(s)
		default:
			raw, _ := json.Marshal(x)
			b.Write(raw)
		}
	}
	walk(v)
	return b.Bytes()
}

// recordedReply is a step's recorded response as a handler would write it.
func recordedReply(s step) (http.Header, []byte) {
	h := http.Header{}
	for name, values := range s.headers {
		h[http.CanonicalHeaderKey(name)] = values
	}
	if body, ok := s.body.(string); ok {
		return h, []byte(body)
	}
	return h, encode(s.body)
}

func loadFixture(t *testing.T, dir, test string) *Fixture {
	t.Helper()
	f, err := load(dir, test, false)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestEveryFixtureReplaysItsOwnRecording feeds each recorded response back as the actual one:
// all 239 fixtures must match, which exercises the normalizer over every shape they hold.
func TestEveryFixtureReplaysItsOwnRecording(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(Fixtures(t, ""), "*", "*.json"))
	if len(files) < 239 {
		t.Fatalf("found %d fixtures, want at least 239", len(files))
	}
	steps := 0
	for _, file := range files {
		test := phpName(file)
		f := loadFixture(t, filepath.Dir(file), test)
		for i, s := range f.steps {
			req := httptest.NewRequest(s.method, s.uri, nil)
			h, body := recordedReply(s)
			status := s.status
			if change, ok := knownChanges[test][i+1]; ok {
				status, h, body = change.Status, change.Headers, encode(change.Body)
			}
			for name, values := range knownHeaders[test][i+1] {
				h[name] = values // as Go answers it, already normalized
			}
			if err := f.check(req, status, h, body); err != nil {
				t.Fatal(err)
			}
			steps++
		}
		if err := f.consumed(); err != nil {
			t.Fatal(err)
		}
	}
	if steps < 2000 {
		t.Fatalf("replayed %d steps", steps)
	}
}

func TestKnownChangeReplacesTheRecording(t *testing.T) {
	test := `Polaris\Tests\Functional\MfaLoginGateEndpointsTest::testTheTicketPrincipalCannotBeSpoofedViaTheBody`
	f := loadFixture(t, Fixtures(t, "core"), test)
	for _, s := range f.steps[:6] {
		h, body := recordedReply(s)
		if err := f.check(httptest.NewRequest(s.method, s.uri, nil), s.status, h, body); err != nil {
			t.Fatal(err)
		}
	}
	s := f.steps[6]
	h, body := recordedReply(s)
	if err := f.check(httptest.NewRequest(s.method, s.uri, nil), s.status, h, body); err == nil {
		t.Fatal("the 1.0 response of a known change was accepted")
	}
}

func TestCompareRejectsDifferences(t *testing.T) {
	dir := Fixtures(t, "core")
	base := loadFixture(t, dir, loginTest).steps[0]
	cases := map[string]func(req *http.Request, status *int, h http.Header, body *[]byte){
		"status":         func(_ *http.Request, status *int, _ http.Header, _ *[]byte) { *status = 200 },
		"missing header": func(_ *http.Request, _ *int, h http.Header, _ *[]byte) { h.Del("Content-Type") },
		"extra header":   func(_ *http.Request, _ *int, h http.Header, _ *[]byte) { h.Set("Cache-Control", "no-store") },
		"header value":   func(_ *http.Request, _ *int, h http.Header, _ *[]byte) { h.Set("X-RateLimit-Limit", "6") },
		"body text":      func(_ *http.Request, _ *int, _ http.Header, b *[]byte) { *b = []byte(`{"message":"Registered."}`) },
		"extra key": func(_ *http.Request, _ *int, _ http.Header, b *[]byte) {
			*b = append((*b)[:len(*b)-1], []byte(`,"x":1}`)...)
		},
		"not JSON": func(_ *http.Request, _ *int, _ http.Header, b *[]byte) { *b = []byte("oops") },
		"method":   func(r *http.Request, _ *int, _ http.Header, _ *[]byte) { r.Method = http.MethodPut },
		"path":     func(r *http.Request, _ *int, _ http.Header, _ *[]byte) { r.URL.Path = "/auth/signup" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := loadFixture(t, dir, loginTest)
			req := httptest.NewRequest(base.method, base.uri, nil)
			h, body := recordedReply(base)
			status := base.status
			mutate(req, &status, h, &body)
			if err := f.check(req, status, h, body); err == nil {
				t.Fatal("difference accepted")
			}
			if f.cursor != 0 {
				t.Fatal("cursor advanced on a mismatch")
			}
		})
	}
}

func TestCompareReportsTheFirstDifferingPath(t *testing.T) {
	f := loadFixture(t, Fixtures(t, "core"), loginTest)
	s := f.steps[0]
	h, _ := recordedReply(s)
	err := f.check(httptest.NewRequest(s.method, s.uri, nil), s.status, h, []byte(`{"message":"other"}`))
	if err == nil || !strings.Contains(err.Error(), "$.body.message") || !strings.Contains(err.Error(), "step 1 POST /auth/register") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStepsBeyondTheRecordingAndUnconsumedSteps(t *testing.T) {
	f := loadFixture(t, Fixtures(t, "core"), `Polaris\Tests\Functional\JwksEndpointTest::testUnknownRouteIsNotFound`)
	if err := f.consumed(); err == nil {
		t.Fatal("an unreplayed fixture passed")
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/does-not-exist", nil)
	if err := f.check(req, http.StatusOK, http.Header{}, nil); err == nil {
		t.Fatal("a bare 404 accepted status 200")
	}
	// Only the status of a bare 404 is contractual: the envelope body is accepted.
	envelope := []byte(`{"error":"not_found","message":"Not found."}`)
	if err := f.check(req, http.StatusNotFound, http.Header{"Content-Type": {"application/json"}}, envelope); err != nil {
		t.Fatal(err)
	}
	if err := f.check(req, http.StatusNotFound, http.Header{}, nil); err == nil || !strings.Contains(err.Error(), "more requests") {
		t.Fatalf("extra step: %v", err)
	}
	if err := f.consumed(); err != nil {
		t.Fatal(err)
	}
}

func TestPathUUIDsAreMasked(t *testing.T) {
	dir := t.TempDir()
	steps := `[{"request":{"method":"GET","uri":"https://auth.polaris.test/orgs/` + testUUID + `?x=1","headers":[],"body":null},
		"response":{"status":204,"headers":[],"body":""}}]`
	if err := os.WriteFile(filepath.Join(dir, "A.T.test.json"), []byte(steps), 0o644); err != nil {
		t.Fatal(err)
	}
	f := loadFixture(t, dir, `A\T::test`)
	req := httptest.NewRequest(http.MethodGet, "/orgs/01a0926f-2801-7c2f-9c74-53c20a0d7ab8", nil)
	if err := f.check(req, http.StatusNoContent, http.Header{}, nil); err != nil {
		t.Fatal(err)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := load(dir, `A\T::missing`, false); err == nil || !strings.Contains(err.Error(), RecordEnv) {
		t.Fatalf("missing fixture: %v", err)
	}
	if f, err := load(dir, `A\T::missing`, true); err != nil || !f.recording {
		t.Fatalf("recording: %v", err)
	}
	for name, content := range map[string]string{
		"A.T.notList.json":    `{"a":1}`,
		"A.T.broken.json":     `[`,
		"A.T.noStatus.json":   `[{"request":{"method":"GET","uri":"/"},"response":{}}]`,
		"A.T.statusText.json": `[{"request":{"method":"GET","uri":"/"},"response":{"status":"200"}}]`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		test := phpName(name)
		if _, err := load(dir, test, false); err == nil {
			t.Errorf("%s loaded", name)
		}
	}
	if _, err := Requests(dir); err == nil {
		t.Error("Requests read a broken fixture")
	}
}

func TestFileName(t *testing.T) {
	for in, want := range map[string]string{
		`Polaris\Tests\Functional\LoginEndpointTest::testFoo`: "Polaris.Tests.Functional.LoginEndpointTest.testFoo.json",
		"Polaris.Tests.Functional.LoginEndpointTest.testFoo":  "Polaris.Tests.Functional.LoginEndpointTest.testFoo.json",
	} {
		if got := FileName(in); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func TestUncovered(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"P.A.one.json", "P.A.two.json", "P.B.three.json", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("[]"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "sub.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := Uncovered(dir, []string{`P\A::one`, "P.B.three"})
	if err != nil || len(got) != 1 || got[0] != "P.A.two" {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := Uncovered(filepath.Join(dir, "absent"), nil); err == nil {
		t.Fatal("a missing directory is not an error")
	}
}

func TestRequests(t *testing.T) {
	reqs, err := Requests(Fixtures(t, "core"))
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) < 1000 {
		t.Fatalf("%d recorded requests", len(reqs))
	}
	for _, r := range reqs {
		if r.Method == "" || !strings.HasPrefix(r.Path, "/") || strings.Contains(r.Path, "?") {
			t.Fatalf("bad request %+v", r)
		}
	}
}

func TestFirstDiff(t *testing.T) {
	a := map[string]any{"a": []any{1.0, map[string]any{"b": "x"}}}
	cases := map[string]any{
		"$.a[1].b": map[string]any{"a": []any{1.0, map[string]any{"b": "y"}}},
		"$.a":      map[string]any{"a": []any{1.0}},
		"$":        []any{},
	}
	for want, b := range cases {
		if got := firstDiff(a, b, "$"); got != want {
			t.Errorf("got %s, want %s", got, want)
		}
	}
}
