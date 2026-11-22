package contracttest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// recordedStep is one step in the fixture file shape: the request's method, URI, headers and
// parsed body; the response's status, headers and decoded body, in that field order.
type recordedStep struct {
	Request struct {
		Method  string `json:"method"`
		URI     string `json:"uri"`
		Headers any    `json:"headers"`
		Body    any    `json:"body"`
	} `json:"request"`
	Response struct {
		Status  int `json:"status"`
		Headers any `json:"headers"`
		Body    any `json:"body"`
	} `json:"response"`
}

func (f *Fixture) record(req *http.Request, resp *http.Response, body []byte) {
	var s recordedStep
	s.Request.Method = req.Method
	s.Request.URI = req.URL.String()
	s.Request.Headers = recordedHeaders(req.Header)
	s.Request.Body = requestBody(req)
	s.Response.Status = resp.StatusCode
	s.Response.Headers = recordedHeaders(resp.Header)
	s.Response.Body = plainBody(body)
	f.recorded = append(f.recorded, s)
}

// recordedHeaders writes an empty header map as `[]`, as the fixture files hold it.
func recordedHeaders(h http.Header) any {
	if len(h) == 0 {
		return []any{}
	}
	return h
}

// requestBody is the parsed body when it is a JSON object or list with members, else the raw
// body. It reads the body through req.GetBody, which
// Client sets, because the handler has consumed req.Body.
func requestBody(req *http.Request) any {
	if req.GetBody == nil {
		return ""
	}
	rc, err := req.GetBody()
	if err != nil {
		return ""
	}
	defer func() { _ = rc.Close() }()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return ""
	}
	switch v := plainBody(raw).(type) {
	case map[string]any:
		if len(v) > 0 {
			return v
		}
	case []any:
		if len(v) > 0 {
			return v
		}
	}
	return string(raw)
}

// plainBody is `json_decode($body, true) ?? $body` with the numbers kept as written.
func plainBody(body []byte) any {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil || v == nil || dec.More() {
		return string(body)
	}
	return v
}

func (f *Fixture) write() error {
	if f.recorded == nil {
		f.recorded = []recordedStep{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)  // the fixture files escape neither slashes nor HTML
	enc.SetIndent("", "    ") // four-space indent, as the fixture files are written
	if err := enc.Encode(f.recorded); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.file), 0o755); err != nil {
		return err
	}
	return os.WriteFile(f.file, buf.Bytes(), 0o644)
}
