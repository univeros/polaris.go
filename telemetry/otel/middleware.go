package otel

import (
	"context"
	"net/http"
	"strings"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
	"go.opentelemetry.io/otel/trace"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/token"
)

// Middleware traces and measures every request next serves: one server span per request (W3C
// trace context extracted from the request with the global propagator) and the
// http.server.request.duration histogram, both from otelhttp. Wrap the Polaris handler with it,
// outermost (Config.Middleware), or any handler guarded by Protect.
//
// The span is named after the matched Polaris route (polaris.auth.login, …), or the HTTP method
// when no route matched, and carries polaris.route, http.response.status_code,
// polaris.principal.kind and, with WithUserIDHash, enduser.pseudo.id. The duration histogram is
// labelled with polaris.route and polaris.principal.kind (low cardinality: no ids).
//
//	handler := polarisotel.Middleware(p.Handler())
func Middleware(next http.Handler, opts ...Option) http.Handler {
	c := newConfig(opts)
	annotate := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		c.annotate(r)
	})
	traced := otelhttp.NewHandler(annotate, "polaris",
		otelhttp.WithTracerProvider(c.tracerProvider),
		otelhttp.WithMeterProvider(c.meterProvider),
		otelhttp.WithSpanNameFormatter(spanName),
	)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := &endpoint.Observed{}
		ctx := context.WithValue(endpoint.WithObserved(r.Context(), o), observedKey{}, o)
		traced.ServeHTTP(w, r.WithContext(ctx))
	})
}

// observedKey carries this middleware's endpoint.Observed so the span name formatter and annotate
// can read it back.
type observedKey struct{}

// spanName is the route name once the pipeline matched one, else the host ServeMux pattern
// ("GET /hello"), else the method.
func spanName(_ string, r *http.Request) string {
	switch o := observedOf(r); {
	case o != nil && o.Route != nil:
		return o.Route.Name
	case strings.Contains(r.Pattern, " "):
		return r.Pattern
	case r.Pattern != "":
		return r.Method + " " + r.Pattern
	}
	return r.Method
}

func observedOf(r *http.Request) *endpoint.Observed {
	o, _ := r.Context().Value(observedKey{}).(*endpoint.Observed)
	return o
}

// annotate copies what the pipeline resolved onto the request's span and metric labels. It runs
// after next returned, on the request's goroutine.
func (c config) annotate(r *http.Request) {
	o := observedOf(r)
	if o == nil {
		return
	}
	span := trace.SpanFromContext(r.Context())
	labeler, _ := otelhttp.LabelerFromContext(r.Context())
	var attrs []attribute.KeyValue
	if o.Route != nil {
		attrs = append(attrs, attribute.String(AttrRoute, o.Route.Name))
		span.SetName(o.Route.Name)
	}
	if kind := token.KindOf(o.Token); kind != "" {
		attrs = append(attrs, attribute.String(AttrPrincipalKind, string(kind)))
	}
	labeler.Add(attrs...)
	if id := c.pseudonym(subject(o.Token)); id != "" {
		attrs = append(attrs, semconv.EnduserPseudoID(id))
	}
	span.SetAttributes(attrs...)
}

func subject(t *token.Token) string {
	if t == nil {
		return ""
	}
	return t.Subject()
}
