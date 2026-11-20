package pipeline_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing/fstest"
	"time"

	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/pipeline"
	"github.com/univeros/polaris-go/token"
)

func Example() {
	// The manifest: core's (and the plugins') api/ directories in production.
	m, err := manifest.Load(fstest.MapFS{"auth/me.yaml": {Data: []byte(`
endpoint: { method: GET, path: /auth/me, auth: bearer, effect: read }
input: { source: none }
domain: { class: MeEndpoint }
`)}})
	if err != nil {
		panic(err)
	}

	// AUTH_JWT_PRIVATE_KEY / AUTH_JWT_PUBLIC_KEY in production.
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	priv, _ := x509.MarshalPKCS8PrivateKey(key)
	codec, err := token.New(token.Config{
		PublicKey:  string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub})),
		PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: priv})),
		Issuer:     "https://auth.example.com",
		TTL:        15 * time.Minute,
	})
	if err != nil {
		panic(err)
	}

	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	p, err := pipeline.New(pipeline.Options{
		Manifest:   m,
		PathPrefix: "/api",
		Auth:       auth,
		Tokens:     codec,
		Endpoints: map[string]endpoint.Endpoint{
			"polaris.auth.me": endpoint.Func(func(ctx context.Context, _ *endpoint.Input) endpoint.Result {
				return endpoint.Data(200, map[string]any{"id": endpoint.Token(ctx).Subject()})
			}),
		},
	})
	if err != nil {
		panic(err) // names every missing endpoint and service
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", p.Handler())
	mux.Handle("/invoices", p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "invoices of %s", endpoint.Token(r.Context()).Subject())
	})))

	claims, _ := token.AccessClaims{Subject: "user-1", ID: "jti-1"}.Claims()
	jwt, _ := codec.Issue(claims)
	for _, path := range []string{"/api/auth/me", "/invoices", "/api/nope"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer "+jwt)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		fmt.Println(w.Code, w.Body)
	}
	// Output:
	// 200 {"data":{"id":"user-1"}}
	// 200 invoices of user-1
	// 404 {"error":"not_found","message":"No such endpoint."}
}
