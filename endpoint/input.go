package endpoint

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Input is a request's data: the parsed body (JSON or form), then query parameters, a later
// source overriding an earlier one, and route parameters last: a body or query "id" can never
// replace the path's {id}. JSON numbers are json.Number. Cookies are not input (upstream merged
// them in, so a cookie tossed from a sibling subdomain could override a body field): an endpoint
// that needs a cookie reads it from Request.
type Input struct {
	Request *http.Request
	data    map[string]any
}

// NewInput builds the Input of r for the given route parameters. A body that is not valid JSON
// (or form data) contributes nothing, as upstream's parsed body would be empty.
func NewInput(r *http.Request, params map[string]string) *Input {
	data := map[string]any{}
	for k, v := range parseBody(r) {
		data[k] = v
	}
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			data[k] = vs[len(vs)-1]
		}
	}
	for k, v := range params {
		data[k] = v
	}
	return &Input{Request: r, data: data}
}

// FromData builds an Input over already-decoded data (tests, MCP tool calls).
func FromData(r *http.Request, data map[string]any) *Input {
	cp := make(map[string]any, len(data))
	for k, v := range data {
		cp[k] = v
	}
	return &Input{Request: r, data: cp}
}

// All returns a copy of the merged data.
func (in *Input) All() map[string]any {
	cp := make(map[string]any, len(in.data))
	for k, v := range in.data {
		cp[k] = v
	}
	return cp
}

// Has reports whether key is present (even when null).
func (in *Input) Has(key string) bool { _, ok := in.data[key]; return ok }

// Value returns the raw value of key, nil when absent.
func (in *Input) Value(key string) any { return in.data[key] }

// String returns key as a string; "" when absent or not a string.
func (in *Input) String(key string) string {
	s, _ := in.data[key].(string)
	return s
}

// Strings returns key as a list of strings; non-string items are skipped.
func (in *Input) Strings(key string) []string {
	list, _ := in.data[key].([]any)
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Bool returns key as a bool (JSON true/false only).
func (in *Input) Bool(key string) bool {
	b, _ := in.data[key].(bool)
	return b
}

// Map returns key as a JSON object, nil otherwise.
func (in *Input) Map(key string) map[string]any {
	m, _ := in.data[key].(map[string]any)
	return m
}

func parseBody(r *http.Request) map[string]any {
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	ct := strings.ToLower(r.Header.Get("Content-Type"))
	switch {
	case strings.Contains(ct, "application/x-www-form-urlencoded"), strings.Contains(ct, "multipart/form-data"):
		if err := r.ParseForm(); err != nil {
			return nil
		}
		out := map[string]any{}
		for k, vs := range r.PostForm {
			if len(vs) > 0 {
				out[k] = vs[len(vs)-1]
			}
		}
		return out
	default:
		dec := json.NewDecoder(r.Body)
		dec.UseNumber()
		var out map[string]any
		if err := dec.Decode(&out); err != nil {
			return nil
		}
		return out
	}
}
