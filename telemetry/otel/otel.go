// Package otel instruments Polaris with OpenTelemetry: a span and a duration measurement per HTTP
// request ([Middleware]), a span per database call ([Store]) and a counter of authentication
// outcomes ([Listener]). Only this package imports OpenTelemetry; a host that does not import it
// pays nothing.
//
// Import it under another name so it does not clash with go.opentelemetry.io/otel:
//
//	import polarisotel "github.com/univeros/polaris-go/telemetry/otel"
//
// Privacy: no attribute ever carries a token, a password, an email address, a request body or a
// stored value. The principal's user id is omitted unless [WithUserIDHash] is given, and then only
// its keyed hash is recorded.
//
// Every constructor uses the global providers (otel.GetTracerProvider, otel.GetMeterProvider)
// unless [WithTracerProvider] / [WithMeterProvider] say otherwise.
package otel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	gootel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// ScopeName is the instrumentation scope of every tracer and meter this package creates.
const ScopeName = "github.com/univeros/polaris-go/telemetry/otel"

// Attribute keys this package sets besides the OpenTelemetry semantic conventions.
const (
	AttrRoute         = "polaris.route"          // the manifest route name, e.g. polaris.auth.login
	AttrPrincipalKind = "polaris.principal.kind" // user, api_key, oauth_client, agent
	AttrOutcome       = "polaris.auth.outcome"   // see the Outcome* values
)

// Option configures Middleware, Store and Listener.
type Option func(*config)

type config struct {
	tracerProvider trace.TracerProvider
	meterProvider  metric.MeterProvider
	userIDKey      []byte
}

// WithTracerProvider sets the provider spans are created from; default otel.GetTracerProvider().
func WithTracerProvider(tp trace.TracerProvider) Option {
	return func(c *config) { c.tracerProvider = tp }
}

// WithMeterProvider sets the provider instruments are created from; default otel.GetMeterProvider().
func WithMeterProvider(mp metric.MeterProvider) Option {
	return func(c *config) { c.meterProvider = mp }
}

// WithUserIDHash records the authenticated user as enduser.pseudo.id: the first 16 bytes of
// HMAC-SHA256(key, user id), hex encoded, so traces of one user correlate without exposing the id.
// Use a secret key of at least 32 bytes, distinct from every other secret. Without this option no
// user identifier is recorded.
func WithUserIDHash(key []byte) Option {
	return func(c *config) { c.userIDKey = append([]byte(nil), key...) }
}

func newConfig(opts []Option) config {
	c := config{}
	for _, o := range opts {
		o(&c)
	}
	if c.tracerProvider == nil {
		c.tracerProvider = gootel.GetTracerProvider()
	}
	if c.meterProvider == nil {
		c.meterProvider = gootel.GetMeterProvider()
	}
	return c
}

func (c config) tracer() trace.Tracer { return c.tracerProvider.Tracer(ScopeName) }
func (c config) meter() metric.Meter  { return c.meterProvider.Meter(ScopeName) }

// pseudonym is the keyed hash of userID; "" when no key is configured or userID is empty.
func (c config) pseudonym(userID string) string {
	if len(c.userIDKey) == 0 || userID == "" {
		return ""
	}
	m := hmac.New(sha256.New, c.userIDKey)
	m.Write([]byte(userID))
	return hex.EncodeToString(m.Sum(nil)[:16])
}
