package oauth_test

import (
	"context"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

func freeCase(t *testing.T, dynamicRegistration bool) *oauthCase {
	fake := &fakeHTTP{documents: map[string]any{}}
	srv := boot(t, fake, dynamicRegistration)
	return &oauthCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), http: fake, keys: newClientKeys(t), ctx: context.Background()}
}

// A permission scope is in a token only when the token's subject holds the permission (decision
// 69): a client acting as itself holds none unless an operator trusted it and listed the scope.
func TestAClientHoldsNoPermissionScopeOfItsOwn(t *testing.T) {
	o := freeCase(t, true)
	registered := o.json(o.c.Post("/oauth2/register", map[string]any{"client_name": "Anyone",
		"grant_types": []string{oauth.GrantClientCredentials}}))
	auth := basic(str(registered["client_id"]), str(registered["client_secret"]))
	issued := o.json(o.form("/oauth2/token", map[string]string{"grant_type": "client_credentials",
		"scope": "users.manage deploy", "resource": "https://api.acme.test"}, auth))
	o.equal([]any{issued["scope"], claims(str(issued["access_token"]))["scope"]}, []any{"deploy", "deploy"},
		"a self-registered client is granted no permission scope")

	_, secret, err := admin.Of(o.srv.Graph()).Keys().Create(o.ctx, admin.Key{Name: "ci", Role: admin.RoleOwner})
	o.must(err)
	create := func(fields map[string]any) contracttest.Option {
		fields["name"], fields["grant_types"] = "Bot", []string{oauth.GrantClientCredentials}
		created := o.data(o.c.Post("/admin/oauth/clients", fields, contracttest.Bearer(secret)))
		return basic(str(created["client_id"]), str(created["client_secret"]))
	}
	scopeOf := func(auth contracttest.Option, scope string) any {
		return o.json(o.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "scope": scope}, auth))["scope"]
	}
	o.equal(scopeOf(create(map[string]any{}), "users.manage deploy"), "deploy", "an operator's client that is not trusted")
	o.equal(scopeOf(create(map[string]any{"trusted": true}), "users.manage deploy"), "deploy", "a trusted client that lists no scope")
	listed := create(map[string]any{"trusted": true, "scopes": []string{"users.manage", "deploy"}})
	o.equal(scopeOf(listed, "users.manage deploy"), "users.manage deploy", "a trusted client holds the permission scopes the operator listed")
}

// A user's token carries a permission scope only while the user holds the permission in the
// token's organization: at issue, on refresh and on exchange.
func TestAUsersPermissionScopesAreBoundedByTheirAuthority(t *testing.T) {
	o := freeCase(t, false)
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	_, outsider := o.login("eve@example.com")
	o.grantOwner(userID)
	client := o.data(o.c.Post("/admin/oauth/clients", map[string]any{"name": "Acme bot", "organization_id": orgID,
		"grant_types":                []string{oauth.GrantDeviceCode, oauth.GrantTokenExchange, oauth.GrantRefreshToken},
		"token_endpoint_auth_method": "client_secret_post"}, contracttest.Bearer(session)))
	auth := func(f map[string]string) map[string]string {
		f["client_id"], f["client_secret"] = str(client["client_id"]), str(client["client_secret"])
		return f
	}
	exchange := func(subject, scope string) map[string]any {
		return o.json(o.form("/oauth2/token", auth(map[string]string{"grant_type": oauth.GrantTokenExchange,
			"subject_token": subject, "subject_token_type": oauth.TokenTypeAccessToken, "scope": scope, "resource": "https://api.acme.test"})))
	}
	o.equal(exchange(outsider, "users.manage org.read deploy")["scope"], "deploy", "a user with no authority gets no permission scope")
	o.equal(exchange(session, "org.read deploy")["scope"], "org.read deploy", "a member gets what they hold")

	device := o.json(o.form("/oauth2/device/code", auth(map[string]string{"scope": "org.read deploy"})))
	o.c.Post("/oauth2/device/approve", map[string]any{"user_code": device["user_code"], "approve": true}, contracttest.Bearer(session))
	tokens := o.json(o.form("/oauth2/token", auth(map[string]string{"grant_type": oauth.GrantDeviceCode, "device_code": str(device["device_code"])})))
	o.equal(tokens["scope"], "org.read deploy", "issued with the permission the user holds")

	_, err := o.srv.DB.Update(o.ctx, "auth_memberships", store.Criteria{"user_id": userID}, store.Data{"status": model.MembershipStatusSuspended})
	o.must(err)
	refreshed := o.json(o.form("/oauth2/token", auth(map[string]string{"grant_type": "refresh_token", "refresh_token": str(tokens["refresh_token"])})))
	o.equal(refreshed["scope"], "deploy", "a refresh re-checks the user's authority")
	o.equal(exchange(str(tokens["access_token"]), "org.read deploy")["scope"], "deploy", "an exchange re-checks it too")
}
