package oauth_test

import (
	"context"
	"regexp"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/oauth"
)

// The registration fixtures: dynamic client registration when a host turns it on, and
// private_key_jwt client authentication with a registered JWK Set.
func TestOAuthRegistration(t *testing.T) {
	run(t, registrationFixtures, true, map[string]func(*oauthCase){
		"testAnyoneRegistersAClientAndAKeyedClientAuthenticatesWithAnAssertion": registrationAndAssertion,
	})
}

func registrationAndAssertion(o *oauthCase) {
	registered := o.c.Post("/oauth2/register", map[string]any{"client_name": "Acme bot", "redirect_uris": []string{"https://bot.acme.test/cb"},
		"grant_types": []string{oauth.GrantClientCredentials, oauth.GrantAuthorizationCode}, "scope": "org.read deploy"})
	o.status(registered, 201, "registered")
	client := o.json(registered)
	if !regexp.MustCompile(`^[0-9a-f-]{36}$`).MatchString(str(client["client_id"])) {
		o.t.Errorf("client id %v", client["client_id"])
	}
	o.equal([]any{client["client_secret_expires_at"], client["token_endpoint_auth_method"], client["scopes"]}, []any{0, "client_secret_basic", []string{"org.read", "deploy"}}, "registration")
	if _, ok := client["trusted"]; ok {
		o.t.Error("trusted is not a registration member")
	}
	auth := basic(str(client["client_id"]), str(client["client_secret"]))
	o.equal(o.json(o.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "scope": "deploy"}, auth))["scope"], "deploy", "client credentials")
	o.problem(o.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "scope": "members.read"}, auth), 400, "invalid_scope", "beyond what it registered")
	o.problem(o.c.Post("/oauth2/register", map[string]any{"client_name": "Bad", "redirect_uris": []string{"http://evil.example/cb"}}), 400, "invalid_client_metadata", "http redirect")
	o.problem(o.c.Post("/oauth2/register", map[string]any{"client_name": "Bad", "token_endpoint_auth_method": "none", "grant_types": []string{oauth.GrantClientCredentials}}), 400, "invalid_client_metadata", "a public client cannot use client_credentials")
	o.equal(o.json(o.c.Get("/.well-known/oauth-authorization-server"))["registration_endpoint"], base+"/oauth2/register", "advertised")

	keyed := o.json(o.c.Post("/oauth2/register", map[string]any{"client_name": "Keyed", "token_endpoint_auth_method": "private_key_jwt", "jwks": o.keys.clientJWKS(), "grant_types": []string{oauth.GrantClientCredentials}}))
	if _, ok := keyed["client_secret"]; ok {
		o.t.Error("a keyed client has no secret")
	}
	assertion := o.keys.clientAssertion(str(keyed["client_id"]), tokenURL)
	withAssertion := func(a string) map[string]string {
		return map[string]string{"grant_type": "client_credentials", "client_assertion_type": oauth.AssertionType, "client_assertion": a}
	}
	issued := o.form("/oauth2/token", withAssertion(assertion))
	o.status(issued, 200, "assertion")
	o.equal(claims(str(o.json(issued)["access_token"]))["client_id"], keyed["client_id"], "keyed client token")
	o.problem(o.form("/oauth2/token", withAssertion(assertion)), 401, "invalid_client", "the assertion was used")
	o.problem(o.form("/oauth2/token", withAssertion(o.keys.clientAssertion(str(keyed["client_id"]), "https://other.example/token"))), 401, "invalid_client", "for another audience")
	o.problem(o.form("/oauth2/token", withAssertion(o.otherKeys().clientAssertion(str(keyed["client_id"]), tokenURL))), 401, "invalid_client", "another key")
}

// Organization self-service beyond the fixtures: another organization is refused, a client is
// deleted with its tokens.
func TestOrganizationClientManagement(t *testing.T) {
	fake := &fakeHTTP{documents: map[string]any{}}
	srv := boot(t, fake, false)
	o := &oauthCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), http: fake, keys: newClientKeys(t), ctx: context.Background()}
	_, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	client := o.client(session, orgID, map[string]any{"grant_types": []string{oauth.GrantClientCredentials}})
	path := "/orgs/" + orgID + "/oauth/clients/" + str(client["id"])
	o.status(o.c.Get("/orgs/other-org/oauth/clients", contracttest.Bearer(session)), 403, "not the active organization")
	o.status(o.c.Get("/orgs/"+orgID+"/oauth/clients/nope", contracttest.Bearer(session)), 404, "unknown client")
	tokens := o.json(o.form("/oauth2/token", map[string]string{"grant_type": "client_credentials"}, basic(str(client["client_id"]), str(client["client_secret"]))))
	o.equal(o.data(o.c.Delete(path, contracttest.Bearer(session)))["status"], "deleted", "deleted")
	o.status(o.c.Get(path, contracttest.Bearer(session)), 404, "gone")
	o.equal(o.json(o.form("/oauth2/introspect", map[string]string{"token": str(tokens["access_token"])}, basic(str(client["client_id"]), str(client["client_secret"]))))["error"], "invalid_client", "the client is gone")
	o.status(o.c.Get("/admin/oauth/clients", contracttest.Bearer(session)), 401, "not an operator")
	o.status(o.c.Get("/oauth2/userinfo"), 401, "no bearer")
}
