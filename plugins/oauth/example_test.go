package oauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store/memstore"
)

// A service installs the provider, registers a machine client and gets a client-credentials
// token from POST /oauth2/token.
func Example() {
	ctx := context.Background()
	provider := oauth.New(oauth.Config{Scopes: map[string]string{"deploy": "Deploy the application"}})

	tables, _ := schema.Merge(schema.Core(), provider.Schema())
	db := memstore.New(tables...)
	_ = authz.Seed(ctx, db, authz.NewCatalog(), nil)
	private, public := contracttest.TestRSAKeyPEM() // use your AUTH_JWT_* keys
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: "an-application-key-of-32-bytes!!", JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: db, Plugins: []polaris.Plugin{provider},
	})
	if err != nil {
		panic(err)
	}

	// Other plugins reach the provider through the graph.
	oauthPlugin := p.Graph().Plugin(oauth.ID).(*oauth.Plugin)
	bot, err := oauthPlugin.CreateClient(ctx, oauth.ClientFields{
		"name": "Deploy bot", "grant_types": []string{oauth.GrantClientCredentials},
	}, "", "", false)
	if err != nil {
		panic(err)
	}

	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"deploy"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(bot.Client.ClientID, bot.Secret)
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)

	var tokens oauth.TokenResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &tokens)
	fmt.Println(rec.Code, tokens.TokenType, tokens.Scope, tokens.ExpiresIn)

	// The token opens the service's own routes: the principal is the client, acting for no user.
	api := p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := polaris.PrincipalFrom(r.Context())
		fmt.Printf("%s client=%v user=%q delegated=%v\n", who.Kind, who.ClientID == bot.Client.ClientID, who.UserID, who.Delegated)
	}))
	req = httptest.NewRequest(http.MethodGet, "/deployments", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	api.ServeHTTP(httptest.NewRecorder(), req)
	// Output:
	// 200 Bearer deploy 3600
	// oauth_client client=true user="" delegated=true
}
