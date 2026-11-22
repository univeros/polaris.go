package contracttest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// Client issues requests to an http.Handler in-process (httptest) and compares each response with
// the next step of its Fixture. It fails the test on a transport-level problem, so call sites stay
// one line:
//
//	c := contracttest.NewClient(t, handler, contracttest.For(t, dir, `Polaris\Tests\Functional\LoginEndpointTest`, "testLoginReturnsTokens"))
//	resp := c.Post("/auth/login", map[string]any{"email": "ada@example.com", "password": pw})
//	access := contracttest.JSON(t, resp)["data"].(map[string]any)["access_token"].(string)
//	c.Get("/auth/me", contracttest.Bearer(access))
//
// Requests are built as the recorded ones were: no remote address (the client IP is
// "unknown") and no Host for a relative path; a full URL (`https://localhost/…`) sets the host and,
// for https, req.TLS.
type Client struct {
	t       testing.TB
	handler http.Handler
	fixture *Fixture
	jar     map[string]string // nil unless KeepCookies
}

// KeepCookies makes the Client behave like one browser: every cookie a response sets is sent with
// the following requests (a Max-Age of 0 or less removes it). Off by default, so explicit Cookie
// options stay the only cookies sent.
func (c *Client) KeepCookies() *Client {
	c.jar = map[string]string{}
	return c
}

// ForgetCookies empties the jar, so the next request comes from another browser, and returns what
// the jar held.
func (c *Client) ForgetCookies() map[string]string {
	held := c.jar
	c.jar = map[string]string{}
	return held
}

// NewClient returns a Client for handler. fixture may be nil: the requests are then not compared.
func NewClient(t testing.TB, handler http.Handler, fixture *Fixture) *Client {
	return &Client{t: t, handler: handler, fixture: fixture}
}

// Option adjusts a request before it is sent.
type Option func(*http.Request)

// Bearer sets `Authorization: Bearer <token>`.
func Bearer(token string) Option {
	return Header("Authorization", "Bearer "+token)
}

// Header adds a request header.
func Header(name, value string) Option {
	return func(r *http.Request) { r.Header.Add(name, value) }
}

// Cookie adds a cookie to the request's Cookie header.
func Cookie(name, value string) Option {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: name, Value: value}) }
}

// RemoteAddr sets the request's remote address (`203.0.113.7:1234`), for the tests where the
// client IP matters.
func RemoteAddr(addr string) Option {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

// Get sends GET path.
func (c *Client) Get(path string, opts ...Option) *http.Response {
	c.t.Helper()
	return c.Do(c.NewRequest(http.MethodGet, path, nil, opts...))
}

// Delete sends DELETE path.
func (c *Client) Delete(path string, opts ...Option) *http.Response {
	c.t.Helper()
	return c.Do(c.NewRequest(http.MethodDelete, path, nil, opts...))
}

// Post sends body as JSON to path; a nil body is sent as `{}`.
func (c *Client) Post(path string, body any, opts ...Option) *http.Response {
	c.t.Helper()
	return c.JSONRequest(http.MethodPost, path, body, opts...)
}

// Patch sends body as JSON to path with PATCH; a nil body is sent as `{}`.
func (c *Client) Patch(path string, body any, opts ...Option) *http.Response {
	c.t.Helper()
	return c.JSONRequest(http.MethodPatch, path, body, opts...)
}

// JSONRequest sends body, encoded as JSON (`{}` when nil), with `Content-Type: application/json`.
func (c *Client) JSONRequest(method, path string, body any, opts ...Option) *http.Response {
	c.t.Helper()
	if body == nil {
		body = struct{}{}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		c.t.Fatalf("contracttest: encoding the %s %s body: %v", method, path, err)
	}
	opts = append([]Option{Header("Content-Type", "application/json")}, opts...)
	return c.Do(c.NewRequest(method, path, raw, opts...))
}

// Form sends fields form-encoded with POST.
func (c *Client) Form(path string, fields url.Values, opts ...Option) *http.Response {
	c.t.Helper()
	opts = append([]Option{Header("Content-Type", "application/x-www-form-urlencoded")}, opts...)
	return c.Do(c.NewRequest(http.MethodPost, path, []byte(fields.Encode()), opts...))
}

// NewRequest builds a request as Do expects it, for a body or headers the helpers do not cover
// (a signed request, a raw JSON-RPC body). target is a path or a full URL.
func (c *Client) NewRequest(method, target string, body []byte, opts ...Option) *http.Request {
	c.t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	req.RemoteAddr = ""
	if !strings.Contains(target, "://") {
		req.Host = ""
	}
	if body == nil {
		req.Body = http.NoBody
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	for name, value := range c.jar {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	for _, opt := range opts {
		opt(req)
	}
	return req
}

// Do sends req to the handler and compares the response with the fixture's next step.
func (c *Client) Do(req *http.Request) *http.Response {
	c.t.Helper()
	rec := httptest.NewRecorder()
	c.handler.ServeHTTP(rec, req)
	resp := rec.Result()
	resp.Request = req
	if c.jar != nil {
		for _, ck := range resp.Cookies() {
			if ck.MaxAge < 0 {
				delete(c.jar, ck.Name)
			} else {
				c.jar[ck.Name] = ck.Value
			}
		}
	}
	c.fixture.Compare(c.t, req, resp)
	return resp
}

// JSON decodes resp's body as a JSON object: an empty map
// when the body is not an object. The body stays readable.
func JSON(t testing.TB, resp *http.Response) map[string]any {
	t.Helper()
	out, _ := decode[map[string]any](t, resp)
	if out == nil {
		out = map[string]any{}
	}
	return out
}

// Decode decodes resp's body into a T and fails t when it cannot. The body stays readable.
func Decode[T any](t testing.TB, resp *http.Response) T {
	t.Helper()
	out, err := decode[T](t, resp)
	if err != nil {
		t.Fatalf("contracttest: decoding the response body: %v", err)
	}
	return out
}

func decode[T any](t testing.TB, resp *http.Response) (T, error) {
	t.Helper()
	var out T
	body, err := readBody(resp)
	if err != nil {
		t.Fatalf("contracttest: reading the response body: %v", err)
	}
	return out, json.Unmarshal(body, &out)
}
