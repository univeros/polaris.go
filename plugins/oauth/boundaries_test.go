package oauth_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// The regression tests of decision 75: what an organization may change on a client an operator
// trusted, whose tokens a client may exchange and read, which URL a DPoP proof is for, where a
// consent counts, and how long a token outlives the grant behind its scopes.

var exchangeGrants = []string{oauth.GrantAuthorizationCode, oauth.GrantRefreshToken, oauth.GrantTokenExchange}

// codeTokens runs the authorization code flow for client as the session's user, approving.
func (o *oauthCase) codeTokens(session string, client map[string]any, scope, resource string) map[string]any {
	o.t.Helper()
	verifier, challenge := pkce()
	query := map[string]string{"response_type": "code", "client_id": str(client["client_id"]), "redirect_uri": redirectURI,
		"scope": scope, "code_challenge": challenge, "code_challenge_method": "S256"}
	if resource != "" {
		query["resource"] = resource
	}
	started := o.data(o.authorize(query, true))
	decided := o.data(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": started["request"], "approve": true}, contracttest.Bearer(session)))
	issued := o.form("/oauth2/token", map[string]string{"grant_type": "authorization_code", "code": param(str(decided["redirect_to"]), "code"),
		"redirect_uri": redirectURI, "code_verifier": verifier}, basic(str(client["client_id"]), str(client["client_secret"])))
	if issued.StatusCode != 200 {
		o.t.Fatalf("code flow: %d %v", issued.StatusCode, o.json(issued))
	}
	return o.json(issued)
}

// exchange is a token exchange by client for subject.
func (o *oauthCase) exchange(client map[string]any, subject, resource string) *http.Response {
	fields := map[string]string{"grant_type": oauth.GrantTokenExchange, "subject_token": subject, "subject_token_type": oauth.TokenTypeAccessToken}
	if resource != "" {
		fields["resource"] = resource
	}
	return o.form("/oauth2/token", fields, basic(str(client["client_id"]), str(client["client_secret"])))
}

// adminClient registers a client as the operator behind session.
func (o *oauthCase) adminClient(session string, fields map[string]any) map[string]any {
	o.t.Helper()
	created := o.c.Post("/admin/oauth/clients", fields, contracttest.Bearer(session))
	if created.StatusCode != 201 {
		o.t.Fatalf("admin client: %d %v", created.StatusCode, o.json(created))
	}
	return o.data(created)
}

// firstKey names a request body in a failure message.
func firstKey(body map[string]any) string {
	keys := make([]string, 0, len(body))
	for k := range body {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return strings.Join(keys, "+")
}

// A client an operator trusted skips consent: where its codes go, how it authenticates and what
// it may ask for are the operator's to change, not its organization's.
func TestAnOrganizationCannotRepointATrustedClient(t *testing.T) {
	o := freeCase(t, false)
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	o.grantOwner(userID)
	trusted := o.adminClient(session, map[string]any{"name": "First party", "organization_id": orgID,
		"redirect_uris": []string{redirectURI}, "trusted": true})
	path := "/orgs/" + orgID + "/oauth/clients/" + str(trusted["id"])
	for _, body := range []map[string]any{
		{"type": "public", "token_endpoint_auth_method": "none", "redirect_uris": []string{"https://evil.test/cb"}},
		{"redirect_uris": []string{redirectURI, "https://evil.test/cb"}},
		{"type": "public", "token_endpoint_auth_method": "none"},
		{"token_endpoint_auth_method": "client_secret_post"},
		{"token_endpoint_auth_method": "private_key_jwt", "jwks": o.keys.clientJWKS(), "grant_types": []string{oauth.GrantClientCredentials}},
		{"jwks": o.keys.clientJWKS()},
		{"jwks_uri": "https://evil.test/jwks.json"},
		{"grant_types": []string{oauth.GrantAuthorizationCode, oauth.GrantClientCredentials}},
		{"scopes": []string{"users.manage"}},
		{"client_uri": "https://evil.test"},
		{"dpop_bound_access_tokens": true},
	} {
		o.problem(o.c.Patch(path, body, contracttest.Bearer(session)), 400, "invalid_client_metadata", "changing "+firstKey(body))
	}
	read := o.data(o.c.Get(path, contracttest.Bearer(session)))
	o.equal([]any{read["trusted"], read["type"], read["redirect_uris"], read["jwks"]},
		[]any{true, "confidential", []string{redirectURI}, nil}, "the client is as the operator registered it")

	same := o.c.Patch(path, map[string]any{"name": "First party app", "redirect_uris": []string{redirectURI}, "logo_uri": "https://acme.test/logo.png"}, contracttest.Bearer(session))
	o.status(same, 200, "what a consent screen would only show, and unchanged values")
	o.equal(o.data(o.c.Patch(path, map[string]any{"disabled": true}, contracttest.Bearer(session)))["disabled_at"] != nil, true, "an organization may still stop it")
}

// A token is exchanged by the client it was issued to (or one an operator trusted), and the new
// token is for the audience the subject was for: never this server unless the subject was.
func TestAnExchangeStaysWithinTheSubjectsClientAndAudience(t *testing.T) {
	o := freeCase(t, false)
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	o.grantOwner(userID)
	app := o.client(session, orgID, map[string]any{"grant_types": exchangeGrants})
	other := o.client(session, orgID, map[string]any{"name": "RS1", "grant_types": exchangeGrants})
	const rs1, rs2 = "https://rs1.acme.test", "https://rs2.acme.test"
	access := str(o.codeTokens(session, app, "org.read", rs1)["access_token"])
	o.equal(claims(access)["aud"], rs1, "issued for the resource")

	o.problem(o.exchange(other, access, ""), 400, "invalid_grant", "another client's token")
	actor := o.form("/oauth2/token", map[string]string{"grant_type": oauth.GrantTokenExchange, "subject_token": session,
		"subject_token_type": oauth.TokenTypeAccessToken, "actor_token": access, "actor_token_type": oauth.TokenTypeAccessToken},
		basic(str(other["client_id"]), str(other["client_secret"])))
	o.problem(actor, 400, "invalid_grant", "another client's token as the actor")

	kept := o.json(o.exchange(app, access, ""))
	o.equal(claims(str(kept["access_token"]))["aud"], rs1, "without a resource the audience stays the subject's")
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(str(kept["access_token"]))), 401, "so this server refuses it")
	o.problem(o.exchange(app, access, base), 400, "invalid_target", "asking for this server")
	o.problem(o.exchange(app, access, rs2), 400, "invalid_target", "asking for another resource")
	o.equal(claims(str(o.json(o.exchange(app, access, rs1))["access_token"]))["aud"], rs1, "asking for the same resource")

	own := str(o.codeTokens(session, app, "org.read", "")["access_token"])
	o.equal(claims(str(o.json(o.exchange(app, own, rs2))["access_token"]))["aud"], rs2, "a token for this server narrows to a resource")

	trusted := o.adminClient(session, map[string]any{"name": "Gateway", "grant_types": []string{oauth.GrantTokenExchange}, "trusted": true})
	o.equal(claims(str(o.json(o.exchange(trusted, access, ""))["access_token"]))["aud"], rs1, "an operator-trusted client exchanges it, same audience")
	o.equal(claims(str(o.json(o.exchange(trusted, access, rs2))["access_token"]))["aud"], rs2, "and may name another")
}

// An exchanged token is exchanged again within its own lifetime: it does not renew itself.
func TestAnExchangedTokenDoesNotOutliveItsSubject(t *testing.T) {
	o := freeCase(t, false)
	_, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	app := o.client(session, orgID, map[string]any{"grant_types": exchangeGrants})
	first := o.json(o.exchange(app, session, ""))
	ends := time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	_, err := o.srv.Graph().DB().Update(o.ctx, oauth.TableTokens, store.Criteria{"id": claims(str(first["access_token"]))["jti"]}, store.Data{"expires_at": ends})
	o.must(err)
	second := o.json(o.exchange(app, str(first["access_token"]), ""))
	if exp, _ := claims(str(second["access_token"]))["exp"].(float64); int64(exp) > ends.Unix() || int64(exp) < ends.Unix()-5 {
		t.Fatalf("exp %v, want the subject's %v", exp, ends.Unix())
	}
	if in, _ := second["expires_in"].(float64); in > 60 {
		t.Fatalf("expires_in %v", in)
	}
}

// A client assertion names its end within the hour: its jti is remembered until then.
func TestAClientAssertionEndsWithinTheHour(t *testing.T) {
	o := freeCase(t, false)
	_, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	id := str(o.client(session, orgID, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": o.keys.clientJWKS(),
		"grant_types": []string{oauth.GrantClientCredentials}, "redirect_uris": []string{}})["client_id"])
	for in, status := range map[time.Duration]int{50 * time.Minute: 200, 2 * time.Hour: 401} {
		now := time.Now()
		raw := o.keys.sign(map[string]any{"typ": "JWT", "alg": "RS256", "kid": "client-1"}, map[string]any{"iss": id, "sub": id, "aud": tokenURL,
			"jti": in.String(), "iat": now.Unix(), "exp": now.Add(in).Unix()})
		o.status(o.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "client_assertion_type": oauth.AssertionType, "client_assertion": raw}),
			status, in.String())
	}
}

// Trust counts in every organization: an operator of one does not give it.
func TestOnlyAnInstanceOwnerRegistersATrustedClient(t *testing.T) {
	o := freeCase(t, false)
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	_, err := admin.Of(o.srv.Graph()).Grants().Grant(o.ctx, admin.Grant{UserID: userID, Role: admin.RoleOwner, Scope: orgID})
	o.must(err)
	create := func(fields map[string]any) *http.Response {
		body := map[string]any{"name": "App", "organization_id": orgID, "redirect_uris": []string{redirectURI}}
		for k, v := range fields {
			body[k] = v
		}
		return o.c.Post("/admin/oauth/clients", body, contracttest.Bearer(session))
	}
	o.equal(o.data(create(nil))["trusted"], false, "an operator of the organization registers its clients")
	o.status(create(map[string]any{"trusted": true}), 403, "trusted")
	o.status(create(map[string]any{"grant_types": []string{oauth.GrantCIBA}}), 400, "the backchannel grant")
	o.grantOwner(userID)
	o.equal(o.data(create(map[string]any{"trusted": true, "grant_types": []string{oauth.GrantAuthorizationCode, oauth.GrantCIBA}}))["trusted"], true, "an owner of the instance")
}

// What a client holds for a user ends with the user's word, whether or not there is a consent to take
// back.
func TestRevokingAClientEndsItsTokensWithoutAConsent(t *testing.T) {
	o := freeCase(t, false)
	_, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	client := o.client(session, orgID, nil)
	tokens := o.codeTokens(session, client, "org.read offline_access", "")
	_, err := o.srv.Graph().DB().Delete(o.ctx, oauth.TableConsents, store.Criteria{"client_id": client["client_id"]}) // as a device grant leaves it
	o.must(err)
	revoke := func() *http.Response {
		return o.c.Delete("/oauth2/consents/"+str(client["client_id"]), contracttest.Bearer(session))
	}
	o.status(revoke(), 200, "revoking the client")
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(str(tokens["access_token"]))), 401, "its access token")
	o.problem(o.form("/oauth2/token", map[string]string{"grant_type": "refresh_token", "refresh_token": str(tokens["refresh_token"])},
		basic(str(client["client_id"]), str(client["client_secret"]))), 400, "invalid_grant", "its refresh token")
	o.status(revoke(), 404, "nothing is left")
}

// A session is a subject only while it is one: not after it ended, and not when it speaks for the
// user on someone else's word (an operator's impersonation, an organization's identity provider).
func TestAnExchangeRefusesASessionThatEndedOrIsNotTheUsersOwn(t *testing.T) {
	o := freeCase(t, false)
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	o.grantOwner(userID)
	client := o.adminClient(session, map[string]any{"name": "Bot", "organization_id": orgID, "grant_types": []string{oauth.GrantTokenExchange}})
	o.status(o.exchange(client, session, ""), 200, "a live session of the user")

	bobID, bob := o.login("bob@example.com")
	impersonated := o.c.Post("/admin/users/"+bobID+"/impersonate", map[string]any{}, contracttest.Bearer(session))
	o.status(impersonated, 201, "impersonation")
	o.problem(o.exchange(client, str(o.data(impersonated)["access_token"]), ""), 400, "invalid_grant", "an impersonation token")

	bound, err := o.srv.Graph().Sessions().Issue(o.ctx, token.SessionPrincipal{UserID: bobID, OrganizationID: orgID, AMR: []string{token.AMRSSO}}, token.ClientContext{})
	o.must(err)
	o.problem(o.exchange(client, bound.AccessToken, ""), 400, "invalid_grant", "a session an identity provider opened")

	o.status(o.exchange(client, bob, ""), 200, "bob's own session")
	o.status(o.c.Post("/auth/logout", map[string]any{}, contracttest.Bearer(bob)), 200, "logout")
	o.problem(o.exchange(client, bob, ""), 400, "invalid_grant", "a session that was logged out")

	_, carol := o.login("carol@example.com")
	second := o.data(o.c.Post("/auth/login", map[string]any{"email": "carol@example.com", "password": password}))
	o.status(o.c.Post("/auth/logout-all", map[string]any{}, contracttest.Bearer(str(second["access_token"]))), 200, "logout everywhere")
	o.problem(o.exchange(client, carol, ""), 400, "invalid_grant", "a session ended from another device")
}

// A DPoP proof names this server's URL (the configured base URL), whatever Host the request
// carries: a proof made for another server is not replayed here.
func TestADPoPProofIsForTheConfiguredOrigin(t *testing.T) {
	o := freeCase(t, false)
	_, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	client := o.client(session, orgID, map[string]any{"grant_types": []string{oauth.GrantClientCredentials, oauth.GrantAuthorizationCode}, "dpop_bound_access_tokens": true})
	auth := basic(str(client["client_id"]), str(client["client_secret"]))
	const elsewhere = "https://evil.test"
	grant := url.Values{"grant_type": {"client_credentials"}}
	o.problem(o.c.Form(elsewhere+"/oauth2/token", grant, auth, dpopHeader(o.keys.dpopProof("POST", elsewhere+"/oauth2/token", ""))),
		400, "invalid_dpop_proof", "a proof for another server, sent with that server's Host")
	o.status(o.c.Form("/oauth2/token", grant, auth, dpopHeader(o.keys.dpopProof("POST", tokenURL, ""))), 200, "a proof for this server, whatever the Host")

	verifier, challenge := pkce()
	started := o.data(o.authorize(map[string]string{"response_type": "code", "client_id": str(client["client_id"]), "redirect_uri": redirectURI,
		"scope": "org.read", "code_challenge": challenge, "code_challenge_method": "S256"}, true))
	redirect := str(o.data(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": started["request"], "approve": true}, contracttest.Bearer(session)))["redirect_to"])
	access := str(o.json(o.c.Form(tokenURL, url.Values{"grant_type": {"authorization_code"}, "code": {param(redirect, "code")},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier}}, auth, dpopHeader(o.keys.dpopProof("POST", tokenURL, ""))))["access_token"])
	as := func(target, htu string) *http.Response {
		return o.c.Get(target, contracttest.Header("Authorization", "DPoP "+access), dpopHeader(o.keys.dpopProof("GET", htu, access)))
	}
	o.status(as(elsewhere+"/orgs/"+orgID, elsewhere+"/orgs/"+orgID), 401, "a bound token with a proof for another server")
	o.status(as(base+"/orgs/"+orgID, base+"/orgs/"+orgID), 200, "with a proof for this one")
}

// Introspection answers the client the token was issued to, and a client an operator trusted;
// to anyone else the token is not active (RFC 7662 §4).
func TestIntrospectionAnswersTheTokensOwnClient(t *testing.T) {
	o := freeCase(t, false)
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	o.grantOwner(userID)
	app := o.client(session, orgID, nil)
	other := o.client(session, orgID, map[string]any{"name": "Other"})
	tokens := o.codeTokens(session, app, "org.read offline_access", "")
	introspect := func(client map[string]any, tok any) map[string]any {
		return o.json(o.form("/oauth2/introspect", map[string]string{"token": str(tok)}, basic(str(client["client_id"]), str(client["client_secret"]))))
	}
	for _, kind := range []string{"access_token", "refresh_token"} {
		o.equal(introspect(other, tokens[kind]), map[string]any{"active": false}, "another client's "+kind)
		o.equal(introspect(app, tokens[kind])["active"], true, "its own "+kind)
	}
	trusted := o.adminClient(session, map[string]any{"name": "Gateway", "grant_types": []string{oauth.GrantClientCredentials}, "trusted": true})
	o.equal(introspect(trusted, tokens["access_token"])["sub"], userID, "an operator-trusted client (a resource server)")
}

// A consent is the user's in one organization: the same client asking in another organization,
// or outside any, asks again.
func TestAConsentCountsInItsOrganizationOnly(t *testing.T) {
	o := freeCase(t, false)
	_, personal := o.login("ada@example.com")
	acme, inAcme := o.organization(personal, "Acme")
	client := o.client(inAcme, acme, nil)
	park := func() any {
		_, challenge := pkce()
		return o.data(o.authorize(map[string]string{"response_type": "code", "client_id": str(client["client_id"]), "redirect_uri": redirectURI,
			"scope": "org.read", "code_challenge": challenge, "code_challenge_method": "S256"}, true))["request"]
	}
	decide := func(session string, approve any) *http.Response {
		body := map[string]any{"request": park()}
		if approve != nil {
			body["approve"] = approve
		}
		return o.c.Post("/oauth2/authorize/decision", body, contracttest.Bearer(session))
	}
	o.status(decide(inAcme, true), 200, "approved in Acme")
	o.status(decide(inAcme, nil), 200, "remembered in Acme")
	other, inOther := o.organization(inAcme, "Other")
	o.problem(decide(inOther, nil), 409, "consent_required", "not in another organization")
	o.problem(decide(personal, nil), 409, "consent_required", "nor outside any")
	o.status(decide(inOther, true), 200, "approved in Other")
	o.status(decide(inOther, nil), 200, "remembered in Other")
	o.status(decide(inAcme, nil), 200, "and still in Acme")
	listed, _ := o.json(o.c.Get("/oauth2/consents", contracttest.Bearer(inAcme)))["data"].([]any)
	orgs := []any{}
	for _, c := range listed {
		orgs = append(orgs, c.(map[string]any)["organization_id"])
	}
	o.equal(orgs, []any{acme, other}, "one consent per organization")
	o.equal(o.data(o.c.Delete("/oauth2/consents/"+str(client["client_id"]), contracttest.Bearer(inAcme)))["status"], "revoked", "revoking the client")
	o.problem(decide(inOther, nil), 409, "consent_required", "revokes it everywhere")
}

// windowOwner is a plugin that owns one OAuth client and says until when it holds permissions.
type windowOwner struct {
	clientID string
	until    map[string]time.Time
}

func (w *windowOwner) ID() string { return "window-owner" }

func (w *windowOwner) ClientPermissions(_ context.Context, clientID string) ([]string, bool, error) {
	held := []string{}
	for name := range w.until {
		held = append(held, name)
	}
	return held, clientID == w.clientID, nil
}

func (w *windowOwner) ClientPermissionsUntil(_ context.Context, clientID string) (map[string]time.Time, bool, error) {
	return w.until, clientID == w.clientID, nil
}

// A permission scope a plugin's grant covers for a time (an agent's windowed grant) is in a token
// only while the grant lasts: the token expires with the grant, and none is issued after it.
func TestATokenEndsWithTheGrantBehindItsScopes(t *testing.T) {
	owner := &windowOwner{}
	fake := &fakeHTTP{documents: map[string]any{}}
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}), oauth.New(testConfig(fake, false)), owner))
	o := &oauthCase{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil), http: fake, keys: newClientKeys(t), ctx: context.Background()}
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	o.grantOwner(userID)
	client := o.adminClient(session, map[string]any{"name": "Agent", "organization_id": orgID,
		"grant_types": []string{oauth.GrantTokenExchange, oauth.GrantClientCredentials}})
	owner.clientID = str(client["client_id"])
	auth := basic(str(client["client_id"]), str(client["client_secret"]))
	delegated := func() map[string]any {
		return o.json(o.form("/oauth2/token", map[string]string{"grant_type": oauth.GrantTokenExchange, "subject_token": session,
			"subject_token_type": oauth.TokenTypeAccessToken, "scope": "org.read deploy", "resource": "https://api.acme.test"}, auth))
	}
	lifetime := func(issued map[string]any) float64 {
		c := claims(str(issued["access_token"]))
		exp, _ := c["exp"].(float64)
		iat, _ := c["iat"].(float64)
		return exp - iat
	}

	owner.until = map[string]time.Time{"org.read": {}}
	whole := delegated()
	o.equal([]any{whole["scope"], whole["expires_in"], lifetime(whole)}, []any{"org.read deploy", 3600, 3600}, "a grant without an end")

	owner.until = map[string]time.Time{"org.read": time.Now().Add(10 * time.Minute)}
	windowed := delegated()
	o.equal(windowed["scope"], "org.read deploy", "within the window")
	if in, _ := windowed["expires_in"].(float64); in < 590 || in > 600 || lifetime(windowed) > 600 {
		t.Errorf("the token must end with the grant's window (10 minutes): expires_in %v, lifetime %v", windowed["expires_in"], lifetime(windowed))
	}
	own := o.json(o.form("/oauth2/token", map[string]string{"grant_type": "client_credentials", "scope": "org.read"}, auth))
	if in, _ := own["expires_in"].(float64); own["scope"] != "org.read" || in > 600 {
		t.Errorf("the client's own token ends with the window too: %v", own)
	}

	owner.until = map[string]time.Time{}
	after := delegated()
	o.equal([]any{after["scope"], after["expires_in"]}, []any{"deploy", 3600}, "after the window the scope is not issued")
}
