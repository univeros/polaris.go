package ui

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/univeros/polaris.go/internal/httpapi"
	"github.com/univeros/polaris.go/wiring"
)

// dispatcher builds, once, the pipeline the pages run the JSON routes through: every endpoint
// (core's and the plugins') behind the whole middleware stack, with body token delivery (the pages
// set their own cookies). It shares the graph's rate-limit store, plugin middleware (sentinel) and
// services with p.Handler(), so a page is limited, judged and recorded exactly as the route.
func (p *Plugin) dispatcher() (http.Handler, error) {
	p.once.Do(func() {
		endpoints, err := p.g.PluginEndpoints()
		if err != nil {
			p.innerErr = err
			return
		}
		for name, e := range httpapi.Endpoints(p.g) {
			endpoints[name] = e
		}
		pl, err := p.g.Pipeline(endpoints, wiring.WithBodyDelivery())
		if err != nil {
			p.innerErr = err
			return
		}
		p.inner = pl.Handler()
	})
	return p.inner, p.innerErr
}

// reply is a route's answer.
type reply struct {
	status int
	header http.Header
	body   map[string]any
}

func (r reply) data() map[string]any {
	d, _ := r.body["data"].(map[string]any)
	return d
}

func (r reply) ok() bool { return r.status/100 == 2 }

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// call runs the route at path (under Config.PathPrefix, query included) for the browser's request
// r, in process: the same client (remote address, User-Agent, Accept-Language, cookies such as
// sentinel's device id) and transport, a JSON body, bearer as the credential when given. Cookies
// the route sets (sentinel's) are passed on to w.
func (p *Plugin) call(w http.ResponseWriter, r *http.Request, method, path string, body map[string]any, bearer string) (reply, error) {
	handler, err := p.dispatcher()
	if err != nil {
		return reply{}, err
	}
	var payload io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return reply{}, err
		}
		payload = bytes.NewReader(raw)
	}
	target := strings.TrimRight(p.g.Config().PathPrefix, "/") + path
	in, err := http.NewRequestWithContext(r.Context(), method, target, payload) //nolint:gosec // served in process by Polaris's own handler below, never over the network
	if err != nil {
		return reply{}, err
	}
	in.Header = r.Header.Clone()
	for _, h := range []string{"Authorization", "X-Api-Key", "Content-Length", "Content-Type", "Origin"} {
		in.Header.Del(h)
	}
	in.Header.Set("Accept", "application/json")
	if body != nil {
		in.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		in.Header.Set("Authorization", "Bearer "+bearer)
	}
	in.Host, in.RemoteAddr, in.TLS = r.Host, r.RemoteAddr, r.TLS
	rec := &recorder{header: http.Header{}}
	handler.ServeHTTP(rec, in)
	for _, c := range rec.header.Values("Set-Cookie") {
		w.Header().Add("Set-Cookie", c)
	}
	out := reply{status: rec.code(), header: rec.header}
	_ = json.Unmarshal(rec.buf.Bytes(), &out.body) // a body that is not an object reads as empty
	return out, nil
}

// recorder buffers an in-process response.
type recorder struct {
	header http.Header
	status int
	buf    bytes.Buffer
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
}

func (r *recorder) Write(b []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	return r.buf.Write(b)
}

func (r *recorder) code() int {
	if r.status == 0 {
		return http.StatusOK
	}
	return r.status
}
