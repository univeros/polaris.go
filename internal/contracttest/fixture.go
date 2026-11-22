package contracttest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// RecordEnv is the environment variable that turns recording on: when it is set (to any value)
// and a test's fixture file does not exist, For records the test's steps and writes the file
// when the test ends.
const RecordEnv = "POLARIS_RECORD_FIXTURES"

// Fixture is the recorded request/response steps of one functional test. Each response
// the Go test produces is compared, normalized, with the step at the cursor. A Fixture is not safe
// for concurrent use: the recorded steps are a sequence.
type Fixture struct {
	test      string // the recorded test name, `Class::method`
	file      string
	steps     []step
	cursor    int
	recording bool
	recorded  []recordedStep
}

// step is one recorded step, decoded by decodeJSON.
type step struct {
	method   string
	uri      string
	status   int
	headers  map[string][]string
	body     any
	bareBody bool // a 404 recorded with an empty body: only the status is contractual
}

// FileName maps a recorded test name (`Polaris\Tests\Functional\LoginEndpointTest::testFoo`) to its
// fixture file name (`Polaris.Tests.Functional.LoginEndpointTest.testFoo.json`). A name already in
// dotted form is returned with the extension.
func FileName(test string) string {
	return strings.NewReplacer(`\`, ".", "::", ".").Replace(test) + ".json"
}

// For returns the fixture of the recorded test class::method in dir, and checks at the end of t
// that every recorded step was replayed. It fails t when the file is missing, unless RecordEnv is
// set, in which case the steps t issues are recorded into that file when t ends (only if t passed).
func For(t testing.TB, dir, class, method string) *Fixture {
	t.Helper()
	f, err := load(dir, class+"::"+method, os.Getenv(RecordEnv) != "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if t.Failed() {
			return // the failure is already reported; a partial replay or recording adds noise
		}
		f.AssertConsumed(t)
	})
	return f
}

func load(dir, test string, record bool) (*Fixture, error) {
	file := filepath.Join(dir, FileName(test))
	data, err := os.ReadFile(file)
	if errors.Is(err, fs.ErrNotExist) && record {
		return &Fixture{test: test, file: file, recording: true}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("contracttest: %s has no fixture (%w); set %s=1 to record one", test, err, RecordEnv)
	}
	steps, err := parseSteps(data)
	if err != nil {
		return nil, fmt.Errorf("contracttest: %s: %w", file, err)
	}
	return &Fixture{test: test, file: file, steps: steps}, nil
}

func parseSteps(data []byte) ([]step, error) {
	decoded, ok := decodeJSON(data)
	list, isList := decoded.([]any)
	if !ok || !isList {
		return nil, errors.New("not a JSON list of steps")
	}
	steps := make([]step, len(list))
	for i, raw := range list {
		s, err := parseStep(raw)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", i+1, err)
		}
		steps[i] = s
	}
	return steps, nil
}

func parseStep(raw any) (step, error) {
	request, response := field(raw, "request"), field(raw, "response")
	method, _ := field(request, "method").(string)
	uri, _ := field(request, "uri").(string)
	status, ok := field(response, "status").(int64)
	if method == "" || !ok {
		return step{}, errors.New("missing request.method or response.status")
	}
	body := field(response, "body")
	bodyString, isString := body.(string)
	return step{
		method:   method,
		uri:      uri,
		status:   int(status),
		headers:  headerValues(field(response, "headers")),
		body:     body,
		bareBody: status == http.StatusNotFound && (body == nil || isString && bodyString == ""),
	}, nil
}

// field reads a member of a decoded object; nil when v is not an object or has no such member.
func field(v any, name string) any {
	obj, _ := v.(object)
	for _, m := range obj {
		if m.key == name {
			return m.value
		}
	}
	return nil
}

// Compare checks resp, the answer to req, against the next recorded step and advances the cursor;
// in recording mode it records the step instead. It fails t at the first difference, naming the
// step and the first differing JSON path. resp.Body is read and replaced, so the caller can still
// read it. A nil Fixture compares nothing, so a test without a fixture can share helpers.
func (f *Fixture) Compare(t testing.TB, req *http.Request, resp *http.Response) {
	t.Helper()
	if f == nil {
		return
	}
	body, err := readBody(resp)
	if err != nil {
		t.Fatalf("contracttest: %s: reading the response: %v", f.test, err)
	}
	if f.recording {
		f.record(req, resp, body)
		return
	}
	if err := f.check(req, resp.StatusCode, resp.Header, body); err != nil {
		t.Fatal(err)
	}
}

func (f *Fixture) check(req *http.Request, status int, header http.Header, body []byte) error {
	n := f.cursor + 1
	if f.cursor >= len(f.steps) {
		return fmt.Errorf("%s: step %d was not recorded from 1.0 (the test issues more requests than before)", f.test, n)
	}
	s := f.steps[f.cursor]
	path := req.URL.EscapedPath()
	label := fmt.Sprintf("%s: step %d %s %s", f.test, n, req.Method, path)
	if s.method != req.Method {
		return fmt.Errorf("%s (method): recorded %s", label, s.method)
	}
	if want := maskPath(uriPath(s.uri)); want != maskPath(path) {
		return fmt.Errorf("%s (path): recorded %s", label, want)
	}
	if s.bareBody {
		// The 1.0 harness answered unknown routes with a bare 404; the handler uses the error
		// envelope. Only the status is contractual here.
		if status != http.StatusNotFound {
			return fmt.Errorf("%s: status %d, recorded 404", label, status)
		}
		f.cursor++
		return nil
	}
	actual := normalizeResponse(status, header, decodeBody(body))
	expected, changed := knownChanges[f.test][n]
	if !changed {
		expected = normalizeResponse(s.status, s.headers, s.body)
	}
	for name, values := range knownHeaders[f.test][n] {
		expected.Headers[name] = values
	}
	if !reflect.DeepEqual(expected, actual) {
		return fmt.Errorf("%s: response differs at %s\nexpected: %s\nactual:   %s",
			label, firstDiff(toJSON(expected), toJSON(actual), "$"), pretty(expected), pretty(actual))
	}
	f.cursor++
	return nil
}

// uriPath is the escaped path of a recorded URI (the URI itself when it does not parse).
func uriPath(uri string) string {
	if u, err := url.Parse(uri); err == nil {
		return u.EscapedPath()
	}
	return uri
}

// AssertConsumed fails t unless every recorded step was replayed; in recording mode it writes the
// fixture file instead. For calls it when the test ends.
func (f *Fixture) AssertConsumed(t testing.TB) {
	t.Helper()
	if f == nil {
		return
	}
	if err := f.consumed(); err != nil {
		t.Error(err)
	}
}

func (f *Fixture) consumed() error {
	if f.recording {
		return f.write()
	}
	if f.cursor != len(f.steps) {
		return fmt.Errorf("%s: 1.0 recorded %d requests, the replay issued %d", f.test, len(f.steps), f.cursor)
	}
	return nil
}

func readBody(resp *http.Response) ([]byte, error) {
	if resp.Body == nil {
		return nil, nil
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return body, err
}

func toJSON(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

func pretty(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%#v", v)
	}
	return string(b)
}

// firstDiff names the first JSON path where a and b (plain decoded JSON) differ.
func firstDiff(a, b any, path string) string {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return path
		}
		keys := make([]string, 0, len(av)+len(bv))
		for k := range av {
			keys = append(keys, k)
		}
		for k := range bv {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range slices.Compact(keys) {
			if !reflect.DeepEqual(av[k], bv[k]) {
				return firstDiff(av[k], bv[k], path+"."+k)
			}
		}
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return path
		}
		for i := range av {
			if !reflect.DeepEqual(av[i], bv[i]) {
				return firstDiff(av[i], bv[i], fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	return path
}

// Uncovered lists the fixtures in dir that no Go test claims: the names (dotted, without the
// extension) of the *.json files whose test is not in covered. covered holds recorded test names in
// either form (`Polaris\Tests\Functional\LoginEndpointTest::testFoo` or the dotted one). A
// package's coverage test asserts it returns nothing.
func Uncovered(dir string, covered []string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("contracttest: reading fixtures: %w", err)
	}
	claimed := make(map[string]bool, len(covered))
	for _, test := range covered {
		claimed[FileName(test)] = true
	}
	var missing []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && !claimed[e.Name()] {
			missing = append(missing, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	return missing, nil
}

// RecordedRequest is the method and path of one recorded step.
type RecordedRequest struct {
	Method string
	Path   string
}

// Requests lists the requests of every fixture in dir, for the route coverage
// check: the package owning the router asserts every manifest route is matched by one.
func Requests(dir string) ([]RecordedRequest, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []RecordedRequest
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		steps, err := parseSteps(data)
		if err != nil {
			return nil, fmt.Errorf("contracttest: %s: %w", file, err)
		}
		for _, s := range steps {
			out = append(out, RecordedRequest{Method: s.method, Path: uriPath(s.uri)})
		}
	}
	return out, nil
}

// Fixtures returns the directory of a package's recorded fixtures,
// `<module root>/internal/apispec/fixtures/<pkg>` (pkg as the fixture directories name it: "core",
// "api-keys", …), found from the test's working directory.
func Fixtures(t testing.TB, pkg string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "internal", "apispec", "fixtures", pkg)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("contracttest: no go.mod above the working directory")
		}
		dir = parent
	}
}
