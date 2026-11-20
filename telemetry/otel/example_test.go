package otel_test

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
	polarisotel "github.com/univeros/polaris-go/telemetry/otel"
)

// A Polaris instance with its HTTP pipeline, its database and its authentication outcomes
// instrumented. In production, pass nothing to use the global providers your OpenTelemetry setup
// installed (otel.SetTracerProvider, otel.SetMeterProvider).
func Example() {
	spans := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(spans))
	mp := sdkmetric.NewMeterProvider()
	opts := []polarisotel.Option{polarisotel.WithTracerProvider(tp), polarisotel.WithMeterProvider(mp)}

	outcomes, err := polarisotel.Listener(opts...)
	if err != nil {
		log.Fatal(err)
	}
	p, err := polaris.New(polaris.Config{
		Secrets:   devSecrets(),
		Auth:      devAuth(),
		DB:        polarisotel.Store(memstore.New(schema.Core()...), opts...), // a span per query
		Listeners: []event.Listener{outcomes},                                 // login, MFA, agent outcomes
		Middleware: []func(http.Handler) http.Handler{ // a span per request, outermost
			func(h http.Handler) http.Handler { return polarisotel.Middleware(h, opts...) },
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	handler := p.Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/.well-known/jwks.json", nil))
	for _, s := range spans.GetSpans() {
		fmt.Println(s.Name, s.SpanKind)
	}
	// Output: polaris.auth.jwks server
}

// devSecrets are throwaway secrets for the example; production reads them with config.FromEnv.
func devSecrets() config.Secrets {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Fatal(err)
	}
	return config.Secrets{
		AppKey:        "example-app-key-at-least-32-bytes-long",
		JWTPrivateKey: string(private),
		JWTPublicKey:  string(public),
	}
}

func devAuth() config.Auth {
	auth := config.Defaults()
	auth.Issuer = "http://localhost"
	auth.AccessToken.Signer = config.SignerEdDSA
	return auth
}
