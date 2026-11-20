// Package endpoint is the contract between the request pipeline and the code that serves one
// route: an Endpoint receives the request's Input and returns a Result. Core's endpoints (httpapi)
// and every plugin's are written against it.
//
//	var Me endpoint.Func = func(ctx context.Context, in *endpoint.Input) endpoint.Result {
//		tok := endpoint.Token(ctx)
//		if tok == nil {
//			return endpoint.Unauthorized()
//		}
//		return endpoint.Data(200, map[string]any{"id": tok.Subject()})
//	}
package endpoint

import (
	"context"
	"net/http"
)

// Endpoint serves one route.
type Endpoint interface {
	Serve(ctx context.Context, in *Input) Result
}

// Func adapts a function to Endpoint.
type Func func(ctx context.Context, in *Input) Result

// Serve implements Endpoint.
func (f Func) Serve(ctx context.Context, in *Input) Result { return f(ctx, in) }

// Result is what an endpoint answers. The pipeline writes it with Write.
type Result struct {
	Status  int
	Body    any         // JSON-encoded; nil writes no body
	Header  http.Header // extra response headers
	Problem bool        // Content-Type application/problem+json instead of application/json
	Raw     []byte      // written verbatim instead of Body when non-nil
}

// WithHeader returns a copy of r with one more header value.
func (r Result) WithHeader(name, value string) Result {
	h := r.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Add(name, value)
	r.Header = h
	return r
}
