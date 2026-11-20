package scim_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/plugins/scim"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store/memstore"
)

func boot(cfg scim.Config) (*polaris.Polaris, error) {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://app.example.com"
	return polaris.New(polaris.Config{
		Secrets:    config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:       auth,
		DB:         memstore.New(slices.Concat(schema.Core(), scim.Models())...),
		PathPrefix: "/auth",
		Plugins:    []polaris.Plugin{scim.New(cfg)},
	})
}

// A directory (Okta, Entra ID, …) provisions a member with the token of a connection the
// organization created.
func Example() {
	ctx := context.Background()
	p, err := boot(scim.Config{}) // BaseURL defaults to the issuer + the path prefix
	if err != nil {
		fmt.Println(err)
		return
	}
	g := p.Graph()
	now := time.Now().UTC()
	owner := model.User{ID: "u-owner", Email: "owner@acme.example", Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	_ = g.Repos().Users.Insert(ctx, owner)
	org, _ := g.Orgs().CreateOrganization(ctx, "Acme", "", owner.ID)

	// What POST /orgs/{id}/scim/connections does for an organization admin:
	conn, token, err := scim.Of(g).Connections().Create(ctx, org.ID, "Okta", scim.DeprovisionDeactivate, "", owner.ID)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(scim.Of(g).BaseURL(conn.ID) == "https://app.example.com/auth/scim/v2/"+conn.ID)

	req := httptest.NewRequest(http.MethodPost, "/auth/scim/v2/"+conn.ID+"/Users",
		strings.NewReader(`{"userName": "Bob@Acme.example", "name": {"givenName": "Bob", "familyName": "Builder"}}`))
	req.Header.Set("Content-Type", scim.ContentType)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)
	var user map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &user)
	fmt.Println(rec.Code, rec.Header().Get("Content-Type"), user["userName"], user["displayName"])
	// Output:
	// true
	// 201 application/scim+json bob@acme.example Bob Builder
}

func TestTheBaseURLIsValidated(t *testing.T) {
	if _, err := boot(scim.Config{BaseURL: "app.example.com/auth"}); err == nil || !strings.Contains(err.Error(), "Config.BaseURL") {
		t.Fatalf("a relative BaseURL: %v", err)
	}
}
