package oauth_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/oauth"
)

// The flow fixtures: every grant against its fixture, DPoP binding and proof replay, the
// discovery documents, scopes as permissions, trusted clients and consent revocation.
func TestOAuthFlow(t *testing.T) {
	run(t, flowFixtures, false, map[string]func(*oauthCase){
		"testAuthorizationCodeWithPkceConsentRefreshRotationAndRevocation": authorizationCodeFlow,
		"testACodePresentedTwiceRevokesTheTokensItIssued":                  codePresentedTwice,
		"testClientCredentialsDeviceFlowBackchannelAndTokenExchange":       clientCredentialsDeviceCIBAExchange,
		"testDpopBindsTokensToTheClientsKeyAndRefusesAReplayedProof":       dpopBinding,
		"testDiscoveryTrustedClientsMetadataDocumentsAndAdministration":    discoveryTrustedMetadataAdmin,
	})
}

func names(list any) []string {
	out := []string{}
	items, _ := list.([]any)
	for _, item := range items {
		m, _ := item.(map[string]any)
		out = append(out, str(m["name"]))
	}
	return out
}

func authorizationCodeFlow(o *oauthCase) {
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	client := o.client(session, orgID, nil)
	clientID, secret := str(client["client_id"]), str(client["client_secret"])
	if !strings.HasPrefix(secret, "pcs_") {
		o.t.Fatalf("secret %q", secret)
	}
	listed, _ := o.json(o.c.Get("/orgs/"+orgID+"/oauth/clients", contracttest.Bearer(session)))["data"].([]any)
	o.equal(len(listed), 1, "listed clients")
	verifier, challenge := pkce()
	query := map[string]string{"response_type": "code", "client_id": clientID, "redirect_uri": redirectURI,
		"scope": "openid email org.read", "state": "xyz", "code_challenge": challenge, "code_challenge_method": "S256", "nonce": "n-1"}
	with := func(k, v string) map[string]string {
		q := map[string]string{}
		for kk, vv := range query {
			q[kk] = vv
		}
		q[k] = v
		return q
	}

	browser := o.authorize(query, false)
	o.status(browser, 302, "a browser is sent to the consent page")
	if !strings.HasPrefix(browser.Header.Get("Location"), consentURL+"?request=") {
		o.t.Errorf("location %q", browser.Header.Get("Location"))
	}
	started := o.data(o.authorize(query, true))
	o.equal(names(started["scopes"]), []string{"openid", "email", "org.read"}, "scopes")
	o.equal(started["client"].(map[string]any)["client_id"], clientID, "client")
	o.equal(o.data(o.authorize(map[string]string{"request": str(started["request"])}, true))["request"], started["request"], "re-read")
	o.problem(o.authorize(with("code_challenge_method", "plain"), true), 400, "invalid_request", "plain PKCE")
	o.problem(o.authorize(with("redirect_uri", "https://evil.example/cb"), true), 400, "invalid_request", "unregistered redirect")
	o.problem(o.authorize(with("scope", "users.manage nothing"), true), 400, "invalid_scope", "unknown scope")

	o.problem(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": started["request"]}, contracttest.Bearer(session)), 409, "consent_required", "first time")
	decided := o.data(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": started["request"], "approve": true}, contracttest.Bearer(session)))
	o.equal(decided["approved"], true, "approved")
	to := str(decided["redirect_to"])
	if !strings.HasPrefix(to, redirectURI+"?code=") {
		o.t.Errorf("redirect %q", to)
	}
	code := param(to, "code")
	o.equal([]string{param(to, "state"), param(to, "iss")}, []string{"xyz", base}, "state and iss")

	auth := basic(clientID, secret)
	o.problem(o.form("/oauth2/token", map[string]string{"grant_type": "authorization_code", "code": code, "redirect_uri": redirectURI, "code_verifier": strings.Repeat("x", 43)}, auth), 400, "invalid_grant", "wrong verifier")
	o.problem(o.form("/oauth2/token", map[string]string{"grant_type": "authorization_code", "code": code, "redirect_uri": redirectURI, "code_verifier": verifier, "client_id": clientID, "client_secret": "wrong"}), 401, "invalid_client", "wrong secret")
	issued := o.form("/oauth2/token", map[string]string{"grant_type": "authorization_code", "code": code, "redirect_uri": redirectURI, "code_verifier": verifier}, auth)
	o.status(issued, 200, "code redeemed")
	if !strings.Contains(issued.Header.Get("Cache-Control"), "no-store") {
		o.t.Error("token response must not be cached")
	}
	tokens := o.json(issued)
	o.equal([]any{tokens["token_type"], tokens["expires_in"], tokens["scope"]}, []any{"Bearer", 3600, "openid email org.read"}, "token response")
	access := str(tokens["access_token"])
	cl := claims(access)
	o.equal([]any{cl["sub"], cl["client_id"], cl["scope"], cl["aud"], cl["org"]}, []any{userID, clientID, "openid email org.read", base, orgID}, "access claims")
	id := claims(str(tokens["id_token"]))
	o.equal([]any{id["sub"], id["aud"], id["nonce"], id["email"], id["email_verified"]}, []any{userID, clientID, "n-1", "ada@example.com", true}, "id token")

	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(access)), 200, "org.read granted")
	o.status(o.c.Get("/orgs/"+orgID+"/members", contracttest.Bearer(access)), 403, "members.read not granted")
	o.status(o.c.Get("/orgs/"+orgID+"/members", contracttest.Bearer(session)), 200, "the session is untouched")
	o.equal(o.data(o.c.Get("/auth/me", contracttest.Bearer(access)))["id"], userID, "me")
	o.status(o.c.Post("/orgs", map[string]any{"name": "From a token"}, contracttest.Bearer(access)), 403, "a self-service write needs the session")
	o.status(o.c.Post("/auth/mfa/totp/enroll", map[string]any{}, contracttest.Bearer(access)), 403, "no credential added")
	o.status(o.c.Post("/auth/logout-all", map[string]any{}, contracttest.Bearer(access)), 403, "nor the person's sessions ended")
	o.status(o.c.Post("/auth/mfa/recovery-codes/regenerate", map[string]any{}, contracttest.Bearer(access)), 403, "a step-up route")
	_, probe := pkce()
	parked := o.data(o.authorize(with("code_challenge", probe), true))
	o.status(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": parked["request"], "approve": true}, contracttest.Bearer(access)), 403, "a token cannot consent for the user")
	o.status(o.c.Get("/auth/me", contracttest.Bearer(str(tokens["id_token"]))), 401, "an ID token is not a session")
	userinfo := o.json(o.c.Get("/oauth2/userinfo", contracttest.Bearer(access)))
	o.equal([]any{userinfo["sub"], userinfo["email"]}, []any{userID, "ada@example.com"}, "userinfo")
	if _, ok := userinfo["name"]; ok {
		o.t.Error("no profile scope, no name")
	}
	o.status(o.c.Get("/oauth2/userinfo", contracttest.Bearer(session)), 401, "a session is not an OAuth token")
	introspected := o.json(o.form("/oauth2/introspect", map[string]string{"token": access}, auth))
	o.equal([]any{introspected["active"], introspected["sub"], introspected["scope"]}, []any{true, userID, "openid email org.read"}, "introspection")

	verifier2, challenge2 := pkce()
	q2 := with("code_challenge", challenge2)
	q2["scope"] = "org.read"
	second := o.data(o.authorize(q2, true))
	redirect := str(o.data(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": second["request"]}, contracttest.Bearer(session)))["redirect_to"])
	secondTokens := o.json(o.form("/oauth2/token", map[string]string{"grant_type": "authorization_code", "code": param(redirect, "code"), "redirect_uri": redirectURI, "code_verifier": verifier2}, auth))
	if _, ok := secondTokens["id_token"]; ok {
		o.t.Error("no openid scope, no ID token")
	}
	refreshed := o.json(o.form("/oauth2/token", map[string]string{"grant_type": "refresh_token", "refresh_token": str(tokens["refresh_token"])}, auth))
	if str(refreshed["refresh_token"]) == "" || refreshed["refresh_token"] == tokens["refresh_token"] {
		o.t.Error("refresh rotates")
	}
	o.problem(o.form("/oauth2/token", map[string]string{"grant_type": "refresh_token", "refresh_token": str(refreshed["refresh_token"]), "scope": "openid email org.read members.read"}, auth), 400, "invalid_scope", "a refresh never widens")
	o.problem(o.form("/oauth2/token", map[string]string{"grant_type": "refresh_token", "refresh_token": str(tokens["refresh_token"])}, auth), 400, "invalid_grant", "the spent token presented again")
	o.problem(o.form("/oauth2/token", map[string]string{"grant_type": "refresh_token", "refresh_token": str(refreshed["refresh_token"])}, auth), 400, "invalid_grant", "its family is revoked")
	o.equal(o.json(o.form("/oauth2/introspect", map[string]string{"token": str(refreshed["access_token"])}, auth))["active"], false, "the family's access token too")

	o.equal(o.data(o.form("/oauth2/revoke", map[string]string{"token": str(secondTokens["access_token"])}, auth))["status"], "revoked", "revoke")
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(str(secondTokens["access_token"]))), 401, "revoked")
	consents, _ := o.json(o.c.Get("/oauth2/consents", contracttest.Bearer(session)))["data"].([]any)
	o.equal(len(consents), 1, "one consent")
	o.equal(consents[0].(map[string]any)["scopes"], []string{"openid", "email", "org.read"}, "consent scopes")
	o.equal(o.data(o.c.Delete("/oauth2/consents/"+clientID, contracttest.Bearer(session)))["status"], "revoked", "consent revoked")
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(access)), 401, "every token of the client went with the consent")
	o.status(o.c.Delete("/oauth2/consents/"+clientID, contracttest.Bearer(session)), 404, "already revoked")

	counts := map[string]int{}
	audited := []string{oauth.EventConsentGranted, oauth.EventTokenIssued, oauth.EventRefreshReused, oauth.EventTokenRevoked, oauth.EventConsentRevoked, oauth.EventClientCreated}
	page, err := audit.Of(o.srv.Graph()).Store().Read(o.ctx, audit.Query{Names: audited, Limit: 100})
	o.must(err)
	for _, e := range page.Events {
		counts[e.Name]++
	}
	o.equal(counts, map[string]int{oauth.EventClientCreated: 1, oauth.EventConsentGranted: 2, oauth.EventConsentRevoked: 1,
		oauth.EventRefreshReused: 2, oauth.EventTokenIssued: 3, oauth.EventTokenRevoked: 1}, "events")
}

func codePresentedTwice(o *oauthCase) {
	_, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	client := o.client(session, orgID, map[string]any{"token_endpoint_auth_method": "client_secret_post"})
	auth := func(f map[string]string) map[string]string {
		f["client_id"], f["client_secret"] = str(client["client_id"]), str(client["client_secret"])
		return f
	}
	verifier, challenge := pkce()
	started := o.data(o.authorize(map[string]string{"response_type": "code", "client_id": str(client["client_id"]), "redirect_uri": redirectURI, "scope": "org.read", "code_challenge": challenge, "code_challenge_method": "S256"}, true))
	code := param(str(o.data(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": started["request"], "approve": true}, contracttest.Bearer(session)))["redirect_to"]), "code")
	redeem := func() map[string]string {
		return auth(map[string]string{"grant_type": "authorization_code", "code": code, "redirect_uri": redirectURI, "code_verifier": verifier})
	}
	tokens := o.json(o.form("/oauth2/token", redeem()))
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(str(tokens["access_token"]))), 200, "the first redemption")
	o.problem(o.form("/oauth2/token", redeem()), 400, "invalid_grant", "the second redemption")
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(str(tokens["access_token"]))), 401, "the access token the first redemption issued")
	o.problem(o.form("/oauth2/token", auth(map[string]string{"grant_type": "refresh_token", "refresh_token": str(tokens["refresh_token"])})), 400, "invalid_grant", "and its refresh token")
}

func clientCredentialsDeviceCIBAExchange(o *oauthCase) {
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	o.problem(o.c.Post("/orgs/"+orgID+"/oauth/clients", map[string]any{"name": "Bot", "grant_types": []string{oauth.GrantCIBA}}, contracttest.Bearer(session)), 400, "invalid_client_metadata", "an organization cannot grant itself CIBA")
	o.grantOwner(userID)
	client := o.data(o.c.Post("/admin/oauth/clients", map[string]any{"name": "Acme bot", "organization_id": orgID,
		"grant_types":                []string{oauth.GrantClientCredentials, oauth.GrantDeviceCode, oauth.GrantCIBA, oauth.GrantTokenExchange, oauth.GrantRefreshToken},
		"token_endpoint_auth_method": "client_secret_post"}, contracttest.Bearer(session)))
	clientID := str(client["client_id"])
	auth := func(f map[string]string) map[string]string {
		f["client_id"], f["client_secret"] = clientID, str(client["client_secret"])
		return f
	}

	own := o.json(o.form("/oauth2/token", auth(map[string]string{"grant_type": "client_credentials", "scope": "deploy", "resource": "https://api.acme.test"})))
	cl := claims(str(own["access_token"]))
	o.equal([]any{cl["sub"], cl["aud"], own["scope"]}, []any{clientID, "https://api.acme.test", "deploy"}, "client credentials")
	if _, ok := own["refresh_token"]; ok {
		o.t.Error("no refresh token without a user")
	}
	o.status(o.c.Get("/auth/me", contracttest.Bearer(str(own["access_token"]))), 401, "meant for another resource")
	o.problem(o.form("/oauth2/token", auth(map[string]string{"grant_type": "client_credentials", "scope": "openid"})), 400, "invalid_scope", "openid needs a user")

	device := o.json(o.form("/oauth2/device/code", auth(map[string]string{"scope": "org.read"})))
	o.equal([]any{device["verification_uri"], device["expires_in"]}, []any{deviceURL, 1800}, "device codes")
	if !regexp.MustCompile(`^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$`).MatchString(str(device["user_code"])) {
		o.t.Errorf("user code %v", device["user_code"])
	}
	poll := func(code string) map[string]string {
		return auth(map[string]string{"grant_type": oauth.GrantDeviceCode, "device_code": code})
	}
	o.problem(o.form("/oauth2/token", poll(str(device["device_code"]))), 400, "authorization_pending", "pending")
	lower := strings.ToLower(str(device["user_code"]))
	shown := o.data(o.c.Get(base+"/oauth2/device/verify?user_code="+lower, contracttest.Bearer(session)))
	o.equal([]any{shown["client"].(map[string]any)["client_id"], names(shown["scopes"])}, []any{clientID, []string{"org.read"}}, "device page data")
	o.problem(o.c.Get("/oauth2/device/verify?user_code=ZZZZ-ZZZZ", contracttest.Bearer(session)), 404, "invalid_grant", "unknown user code")
	o.equal(o.data(o.c.Post("/oauth2/device/approve", map[string]any{"user_code": device["user_code"], "approve": true}, contracttest.Bearer(session)))["status"], "approved", "approved")
	deviceTokens := o.json(o.form("/oauth2/token", poll(str(device["device_code"]))))
	o.equal([]any{claims(str(deviceTokens["access_token"]))["sub"], deviceTokens["scope"]}, []any{userID, "org.read"}, "device tokens")
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(str(deviceTokens["access_token"]))), 200, "the device acts for Ada")
	o.problem(o.form("/oauth2/token", poll(str(device["device_code"]))), 400, "invalid_grant", "spent")
	denied := o.json(o.form("/oauth2/device/code", auth(map[string]string{})))
	o.c.Post("/oauth2/device/approve", map[string]any{"user_code": denied["user_code"], "approve": false}, contracttest.Bearer(session))
	o.problem(o.form("/oauth2/token", poll(str(denied["device_code"]))), 400, "access_denied", "denied")

	o.problem(o.form("/oauth2/ciba", auth(map[string]string{"login_hint": "nobody@example.com", "scope": "org.read"})), 400, "unknown_user_id", "unknown hint")
	backchannel := o.json(o.form("/oauth2/ciba", auth(map[string]string{"login_hint": "ada@example.com", "scope": "org.read", "binding_message": "Deploy 42?"})))
	o.equal(backchannel["expires_in"], 600, "ciba lifetime")
	cibaPoll := auth(map[string]string{"grant_type": oauth.GrantCIBA, "auth_req_id": str(backchannel["auth_req_id"])})
	o.problem(o.form("/oauth2/token", cibaPoll), 400, "authorization_pending", "ciba pending")
	pending, _ := o.json(o.c.Get("/oauth2/ciba/pending", contracttest.Bearer(session)))["data"].([]any)
	first := pending[0].(map[string]any)
	o.equal([]any{first["id"], first["binding_message"], first["client"].(map[string]any)["client_id"]}, []any{backchannel["auth_req_id"], "Deploy 42?", clientID}, "pending request")
	o.equal(o.data(o.c.Post("/oauth2/ciba/"+str(backchannel["auth_req_id"])+"/decide", map[string]any{"approve": true}, contracttest.Bearer(session)))["status"], "approved", "ciba approved")
	cibaTokens := o.json(o.form("/oauth2/token", cibaPoll))
	o.equal(claims(str(cibaTokens["access_token"]))["sub"], userID, "ciba tokens")
	o.equal(o.json(o.c.Get("/oauth2/ciba/pending", contracttest.Bearer(session)))["data"], []any{}, "nothing pending")

	exchange := func(subject, scope, resource string) map[string]string {
		f := auth(map[string]string{"grant_type": oauth.GrantTokenExchange, "subject_token": subject, "subject_token_type": oauth.TokenTypeAccessToken})
		if scope != "" {
			f["scope"] = scope
		}
		if resource != "" {
			f["resource"] = resource
		}
		return f
	}
	exchanged := o.json(o.form("/oauth2/token", exchange(session, "org.read members.read", "")))
	o.equal(exchanged["issued_token_type"], oauth.TokenTypeAccessToken, "issued token type")
	ec := claims(str(exchanged["access_token"]))
	o.equal([]any{ec["sub"], ec["org"], ec["act"]}, []any{userID, orgID, map[string]any{"sub": clientID, "client_id": clientID}}, "exchanged claims")
	o.status(o.c.Get("/orgs/"+orgID+"/members", contracttest.Bearer(str(exchanged["access_token"]))), 200, "within Ada's permissions")
	narrowed := o.json(o.form("/oauth2/token", exchange(str(exchanged["access_token"]), "org.read", "https://api.acme.test")))
	o.equal([]any{narrowed["scope"], claims(str(narrowed["access_token"]))["aud"]}, []any{"org.read", "https://api.acme.test"}, "narrowed")
	o.equal(claims(str(narrowed["access_token"]))["act"], map[string]any{"sub": clientID, "client_id": clientID, "act": map[string]any{"sub": clientID, "client_id": clientID}}, "the chain of actors")
	o.problem(o.form("/oauth2/token", exchange(str(exchanged["access_token"]), "org.read users.manage", "")), 400, "invalid_scope", "never wider than the subject")
	o.problem(o.form("/oauth2/token", exchange("garbage", "", "")), 400, "invalid_grant", "garbage")
}

func dpopBinding(o *oauthCase) {
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	client := o.client(session, orgID, map[string]any{"grant_types": []string{oauth.GrantClientCredentials, oauth.GrantAuthorizationCode, oauth.GrantRefreshToken}, "dpop_bound_access_tokens": true, "token_endpoint_auth_method": "client_secret_post"})
	auth := func(f map[string]string) map[string]string {
		f["client_id"], f["client_secret"] = str(client["client_id"]), str(client["client_secret"])
		return f
	}
	o.problem(o.form("/oauth2/token", auth(map[string]string{"grant_type": "client_credentials", "scope": "org.read"})), 400, "invalid_dpop_proof", "the client is registered for DPoP")
	o.problem(o.form("/oauth2/token", auth(map[string]string{"grant_type": "client_credentials"}), dpopHeader("not-a-proof")), 400, "invalid_dpop_proof", "not a proof")
	o.problem(o.form("/oauth2/token", auth(map[string]string{"grant_type": "client_credentials"}), dpopHeader(o.keys.dpopProof("POST", "https://other.example/token", ""))), 400, "invalid_dpop_proof", "bound to another URL")

	verifier, challenge := pkce()
	started := o.data(o.authorize(map[string]string{"response_type": "code", "client_id": str(client["client_id"]), "redirect_uri": redirectURI, "scope": "org.read", "code_challenge": challenge, "code_challenge_method": "S256", "dpop_jkt": o.keys.thumbprint()}, true))
	redirect := str(o.data(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": started["request"], "approve": true}, contracttest.Bearer(session)))["redirect_to"])
	issued := o.json(o.form("/oauth2/token", auth(map[string]string{"grant_type": "authorization_code", "code": param(redirect, "code"), "redirect_uri": redirectURI, "code_verifier": verifier}), dpopHeader(o.keys.dpopProof("POST", tokenURL, ""))))
	o.equal(issued["token_type"], "DPoP", "bound")
	access := str(issued["access_token"])
	o.equal(claims(access)["cnf"], map[string]any{"jkt": o.keys.thumbprint()}, "the token names the key")

	resource := base + "/orgs/" + orgID
	asDPoP := func(proof string) []contracttest.Option {
		return []contracttest.Option{contracttest.Header("Authorization", "DPoP "+access), dpopHeader(proof)}
	}
	proof := o.keys.dpopProof("GET", resource, access)
	o.status(o.c.Get(resource, asDPoP(proof)...), 200, "a proof for the request and the token")
	o.status(o.c.Get(resource, asDPoP(proof)...), 401, "the proof was used")
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(access)), 401, "a bound token is not a bearer")
	o.status(o.c.Get(resource, asDPoP(o.keys.dpopProof("GET", base+"/auth/me", access))...), 401, "bound to another URL")
	o.status(o.c.Get(resource, asDPoP(o.keys.dpopProof("GET", resource, ""))...), 401, "no ath")
	o.status(o.c.Get(resource, asDPoP(o.keys.dpopProof("GET", resource, access))...), 200, "a fresh proof")

	other := newClientKeys(o.t)
	o.problem(o.form("/oauth2/token", auth(map[string]string{"grant_type": "refresh_token", "refresh_token": str(issued["refresh_token"])}), dpopHeader(other.dpopProof("POST", tokenURL, ""))), 400, "invalid_dpop_proof", "another key")
	refreshed := o.json(o.form("/oauth2/token", auth(map[string]string{"grant_type": "refresh_token", "refresh_token": str(issued["refresh_token"])}), dpopHeader(o.keys.dpopProof("POST", tokenURL, ""))))
	o.equal(claims(str(refreshed["access_token"]))["cnf"], map[string]any{"jkt": o.keys.thumbprint()}, "refresh stays bound")
	o.equal(claims(str(refreshed["access_token"]))["sub"], userID, "refreshed subject")

	exchangeClient := o.client(session, orgID, map[string]any{"grant_types": []string{oauth.GrantTokenExchange}, "token_endpoint_auth_method": "client_secret_post"})
	exchange := func() map[string]string {
		return map[string]string{"client_id": str(exchangeClient["client_id"]), "client_secret": str(exchangeClient["client_secret"]),
			"grant_type": oauth.GrantTokenExchange, "subject_token": str(refreshed["access_token"]), "subject_token_type": oauth.TokenTypeAccessToken}
	}
	o.problem(o.form("/oauth2/token", exchange()), 400, "invalid_dpop_proof", "unbinding through an exchange")
	exchanged := o.json(o.form("/oauth2/token", exchange(), dpopHeader(o.keys.dpopProof("POST", tokenURL, ""))))
	o.equal(claims(str(exchanged["access_token"]))["cnf"], map[string]any{"jkt": o.keys.thumbprint()}, "the exchanged token stays bound")
}

func discoveryTrustedMetadataAdmin(o *oauthCase) {
	userID, session := o.login("ada@example.com")
	orgID, session := o.organization(session, "Acme")
	o.grantOwner(userID)

	openid := o.json(o.c.Get("/.well-known/openid-configuration"))
	o.equal([]any{openid["issuer"], openid["token_endpoint"], openid["jwks_uri"], openid["device_authorization_endpoint"]},
		[]any{base, base + "/oauth2/token", base + "/auth/.well-known/jwks.json", base + "/oauth2/device/code"}, "discovery")
	if _, ok := openid["registration_endpoint"]; ok {
		o.t.Error("registration is off")
	}
	supported, _ := openid["scopes_supported"].([]any)
	if !slices.Contains(supported, any("deploy")) || !slices.Contains(supported, any("org.read")) {
		o.t.Errorf("scopes %v", supported)
	}
	server := o.json(o.c.Get("/.well-known/oauth-authorization-server"))
	if _, ok := server["userinfo_endpoint"]; ok {
		o.t.Error("RFC 8414 has no userinfo")
	}
	o.problem(o.c.Post("/oauth2/register", map[string]any{"client_name": "Rogue", "redirect_uris": []string{"https://rogue.example/cb"}}), 403, "registration_disabled", "off by default")
	jwks, _ := o.json(o.c.Get("/auth/.well-known/jwks.json"))["keys"].([]any)
	o.equal(len(jwks), 2, "core's JWKS, reused unchanged: the key under its kid and its legacy kid (decision 73)")

	trustedResp := o.c.Post("/admin/oauth/clients", map[string]any{"name": "First party", "type": "public", "token_endpoint_auth_method": "none", "redirect_uris": []string{redirectURI}, "trusted": true}, contracttest.Bearer(session))
	o.status(trustedResp, 201, "an operator registers a trusted client")
	trusted := o.data(trustedResp)
	o.equal([]any{trusted["trusted"], trusted["client_secret"]}, []any{true, nil}, "trusted, no secret")
	verifier, challenge := pkce()
	started := o.data(o.authorize(map[string]string{"response_type": "code", "client_id": str(trusted["client_id"]), "redirect_uri": redirectURI, "scope": "openid profile org.read", "code_challenge": challenge, "code_challenge_method": "S256"}, true))
	o.equal(started["client"].(map[string]any)["trusted"], true, "shown as trusted")
	redirect := str(o.data(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": started["request"]}, contracttest.Bearer(session)))["redirect_to"])
	tokens := o.json(o.form("/oauth2/token", map[string]string{"grant_type": "authorization_code", "client_id": str(trusted["client_id"]), "code": param(redirect, "code"), "redirect_uri": redirectURI, "code_verifier": verifier}))
	o.equal(claims(str(tokens["access_token"]))["sub"], userID, "trusted tokens")
	o.equal(o.json(o.c.Get("/oauth2/consents", contracttest.Bearer(session)))["data"], []any{}, "nothing recorded for a trusted client")
	o.problem(o.form("/oauth2/introspect", map[string]string{"token": str(tokens["access_token"]), "client_id": str(trusted["client_id"])}), 401, "invalid_client", "a public client cannot introspect")
	if name, ok := claims(str(tokens["id_token"]))["name"]; ok && name != nil {
		o.t.Errorf("name %v", name)
	}

	cimd := "https://agent.example.com/.well-known/oauth-client"
	o.http.publish(cimd, map[string]any{"client_id": cimd, "client_name": "Agent", "redirect_uris": []string{"https://agent.example.com/cb"}, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}})
	o.http.publish("https://agent.example.com/bad", map[string]any{"client_id": "https://agent.example.com/other", "redirect_uris": []string{"https://agent.example.com/cb"}})
	verifier, challenge = pkce()
	agentQuery := map[string]string{"response_type": "code", "client_id": cimd, "redirect_uri": "https://agent.example.com/cb", "scope": "org.read", "code_challenge": challenge, "code_challenge_method": "S256"}
	started = o.data(o.authorize(agentQuery, true))
	o.equal([]any{started["client"].(map[string]any)["name"], started["client"].(map[string]any)["client_id"]}, []any{"Agent", cimd}, "metadata client")
	o.authorize(agentQuery, true)
	o.equal(o.http.fetches(cimd), 1, "cached")
	redirect = str(o.data(o.c.Post("/oauth2/authorize/decision", map[string]any{"request": started["request"], "approve": true}, contracttest.Bearer(session)))["redirect_to"])
	agentTokens := o.json(o.form("/oauth2/token", map[string]string{"grant_type": "authorization_code", "client_id": cimd, "code": param(redirect, "code"), "redirect_uri": "https://agent.example.com/cb", "code_verifier": verifier}))
	o.equal(claims(str(agentTokens["access_token"]))["client_id"], cimd, "metadata client tokens")
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(str(agentTokens["access_token"]))), 200, "metadata client token works")
	refused := func(clientID string) map[string]string {
		return map[string]string{"response_type": "code", "client_id": clientID, "redirect_uri": "https://agent.example.com/cb", "code_challenge": challenge, "code_challenge_method": "S256"}
	}
	o.problem(o.authorize(refused("https://agent.example.com/bad"), true), 400, "invalid_client_metadata", "a document naming another id")
	for _, special := range []string{"https://localhost/client", "https://10.0.0.8/client", "https://[::1]/client", "https://agent.internal/client", "https://169.254.169.254/latest", "http://agent.example.com/client"} {
		code := "invalid_client_metadata"
		if special == "http://agent.example.com/client" {
			code = "invalid_client"
		}
		o.problem(o.authorize(refused(special), true), 400, code, special)
	}
	if o.http.fetches("https://agent.example.com/bad") != 1 || len(o.http.fetched) != 2 {
		o.t.Errorf("only public documents were fetched: %v", o.http.fetched)
	}

	client := o.client(session, orgID, nil)
	updated := o.data(o.c.Patch("/orgs/"+orgID+"/oauth/clients/"+str(client["id"]), map[string]any{"name": "Acme CLI 2", "scopes": []string{"org.read"}, "trusted": true}, contracttest.Bearer(session)))
	o.equal([]any{updated["name"], updated["scopes"], updated["trusted"]}, []any{"Acme CLI 2", []string{"org.read"}, false}, "an organization cannot trust its own client")
	o.problem(o.c.Patch("/orgs/"+orgID+"/oauth/clients/"+str(client["id"]), map[string]any{"scopes": []string{"nothing"}}, contracttest.Bearer(session)), 400, "invalid_client_metadata", "unknown scope")
	all, _ := o.json(o.c.Get("/admin/oauth/clients", contracttest.Bearer(session)))["data"].([]any)
	o.equal(len(all), 2, "every client")
	o.equal(o.data(o.c.Delete("/admin/oauth/clients/"+str(client["id"]), contracttest.Bearer(session)))["status"], "deleted", "operator delete")
	o.status(o.c.Get("/orgs/"+orgID+"/oauth/clients/"+str(client["id"]), contracttest.Bearer(session)), 404, "gone")
	o.equal(o.data(o.c.Delete("/admin/oauth/clients/"+str(trusted["id"]), contracttest.Bearer(session)))["status"], "deleted", "trusted client deleted")
	o.status(o.c.Get("/orgs/"+orgID, contracttest.Bearer(str(tokens["access_token"]))), 401, "a deleted client's tokens are gone")
}
