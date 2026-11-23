package oauth_test

import (
	"testing"
	"time"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

// setUser changes a user's row.
func (o *oauthCase) setUser(userID string, data store.Data) {
	o.t.Helper()
	_, err := o.srv.Graph().DB().Update(o.ctx, "auth_users", store.Criteria{"id": userID}, data)
	o.must(err)
}

// A disabled account's grants issue nothing and its tokens are not active; enabled again, a refresh
// token that was refused meanwhile is unspent.
func TestADisabledAccountsGrantsIssueNothing(t *testing.T) {
	o := freeCase(t, false)
	_, operator := o.login("owner@example.com")
	orgID, operator := o.organization(operator, "Acme")
	userID, session := o.login("ada@example.com")
	client := o.client(operator, orgID, map[string]any{"grant_types": []string{oauth.GrantAuthorizationCode, oauth.GrantRefreshToken}})
	auth := basic(str(client["client_id"]), str(client["client_secret"]))
	tokens := o.codeTokens(session, client, "openid offline_access", "https://api.acme.test")
	introspect := func(kind string) any {
		return o.json(o.form("/oauth2/introspect", map[string]string{"token": str(tokens[kind])}, auth))["active"]
	}
	refresh := map[string]string{"grant_type": "refresh_token", "refresh_token": str(tokens["refresh_token"])}

	verifier, challenge := pkce()
	started := o.data(o.authorize(map[string]string{"response_type": "code", "client_id": str(client["client_id"]), "redirect_uri": redirectURI,
		"scope": "openid", "code_challenge": challenge, "code_challenge_method": "S256"}, true))
	decided := o.data(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": started["request"], "approve": true}, contracttest.Bearer(session)))

	identity := services.Of(o.srv.Graph()).Identity
	o.must(identity.DisableUser(o.ctx, "operator", userID))
	for _, kind := range []string{"access_token", "refresh_token"} {
		o.equal(introspect(kind), false, kind+" of a disabled account")
	}
	o.problem(o.form("/oauth2/token", refresh, auth), 400, "invalid_grant", "refresh")
	o.problem(o.form("/oauth2/token", map[string]string{"grant_type": "authorization_code", "code": param(str(decided["redirect_to"]), "code"),
		"redirect_uri": redirectURI, "code_verifier": verifier}, auth), 400, "invalid_grant", "a code approved before")

	o.must(identity.EnableUser(o.ctx, "operator", userID))
	o.equal(introspect("access_token"), true, "enabled again")
	o.status(o.form("/oauth2/token", refresh, auth), 200, "refresh, enabled again")
}

// A lock is the password sign-in's: what the user granted keeps working.
func TestALockedAccountsGrantsKeepWorking(t *testing.T) {
	o := freeCase(t, false)
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	o.grantOwner(userID)
	client := o.adminClient(session, map[string]any{"name": "CLI", "organization_id": orgID, "redirect_uris": []string{redirectURI},
		"grant_types": []string{oauth.GrantAuthorizationCode, oauth.GrantRefreshToken, oauth.GrantCIBA}})
	auth := basic(str(client["client_id"]), str(client["client_secret"]))
	tokens := o.codeTokens(session, client, "org.read offline_access", "")
	o.setUser(userID, store.Data{"status": model.UserStatusLocked, "locked_until": time.Now().Add(time.Hour)})
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(str(tokens["access_token"]))), 200, "its access token")
	o.status(o.form("/oauth2/token", map[string]string{"grant_type": "refresh_token", "refresh_token": str(tokens["refresh_token"])}, auth), 200, "its refresh token")
	o.status(o.form("/oauth2/ciba", map[string]string{"login_hint": "ada@example.com", "scope": "org.read"}, auth), 200, "a backchannel request")
}
