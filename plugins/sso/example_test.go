package sso_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

func boot(cfg sso.Config) (*polaris.Polaris, error) {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://app.example.com"
	return polaris.New(polaris.Config{
		Secrets:    config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:       auth,
		DB:         memstore.New(slices.Concat(schema.Core(), sso.Models())...),
		PathPrefix: "/auth",
		Plugins:    []polaris.Plugin{sso.New(cfg)},
	})
}

// An organization's SAML identity provider: the IdP is configured from the SP metadata, and a
// sign-in starts with POST /sso/sign-in, which answers where to send the browser.
func Example() {
	ctx := context.Background()
	p, err := boot(sso.Config{}) // BaseURL defaults to the issuer + the path prefix
	if err != nil {
		fmt.Println(err)
		return
	}
	// What POST /orgs/{id}/sso/providers does for an organization admin:
	prov, err := sso.Of(p.Graph()).Providers().Create(ctx, sso.Provider{
		OrganizationID: "org-1", Type: sso.TypeSAML, Name: "Okta", Issuer: "http://www.okta.com/exk1",
		Config:       map[string]any{"sso_url": "https://acme.okta.com/app/sso/saml", "certificate": "MIIC..."},
		JIT:          sso.JIT{Enabled: true}, // unknown users are created, as members
		RedirectURIs: []string{"https://app.example.com/sso/done"}, Enabled: true,
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(sso.Of(p.Graph()).SP().ACSURL(prov.ID) == "https://app.example.com/auth/sso/callback/"+prov.ID)

	metadata := httptest.NewRecorder()
	p.Handler().ServeHTTP(metadata, httptest.NewRequest(http.MethodGet, "/auth/sso/metadata/"+prov.ID, nil))
	fmt.Println(metadata.Code, metadata.Header().Get("Content-Type"))

	req := httptest.NewRequest(http.MethodPost, "/auth/sso/sign-in", strings.NewReader(`{"provider_id": "`+prov.ID+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)
	var started struct {
		Data sso.Started `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &started)
	fmt.Println(rec.Code, strings.HasPrefix(started.Data.URL, "https://acme.okta.com/app/sso/saml?SAMLRequest="), started.Data.Type)
	// The IdP posts the SAMLResponse to the ACS URL; the browser lands on
	// https://app.example.com/sso/done?sso_code=…, which the application trades for the session at
	// POST /sso/exchange.

	// Output:
	// true
	// 200 application/samlmetadata+xml
	// 200 true saml
}

func TestTheConfigurationIsValidatedAtStartup(t *testing.T) {
	if _, err := boot(sso.Config{BaseURL: "app.example.com/auth"}); err == nil || !strings.Contains(err.Error(), "Config.BaseURL") {
		t.Fatalf("a relative BaseURL: %v", err)
	}
	if _, err := boot(sso.Config{SPCertificate: "nope"}); err == nil || !strings.Contains(err.Error(), "SPPrivateKey") {
		t.Fatalf("half a key pair: %v", err)
	}
}
