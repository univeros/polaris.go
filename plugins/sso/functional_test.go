package sso_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/polaristest"
)

const (
	password = "correct horse battery staple"
	base     = "https://app.example/auth"
	done     = "https://app.example/done"
	classes  = `Polaris\Sso\Tests\Functional\`
)

// fakeOIDC is upstream's FakeOidc: the authorization URL names the provider only (the state and
// nonce are kept for the test to read), the code "good" is the identity of email.
type fakeOIDC struct {
	mu                   sync.Mutex
	email, name          string
	lastState, lastNonce string
	problems             []string
}

func (f *fakeOIDC) AuthorizationURL(_ context.Context, p sso.Provider, _, state, nonce, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastState, f.lastNonce = state, nonce
	return "https://idp.example/authorize?client_id=" + p.Setting("client_id"), nil
}

func (f *fakeOIDC) Exchange(_ context.Context, _ sso.Provider, _, code, _, _, nonce string) (sso.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if code != "good" || nonce != f.lastNonce {
		return sso.Identity{}, &sso.Error{Reason: sso.ReasonAssertionInvalid, Detail: "the code is not good"}
	}
	return sso.Identity{Subject: "subject-" + f.email, Email: f.email, Name: f.name, Attributes: map[string]any{"email": f.email}}, nil
}

func (f *fakeOIDC) EndSessionURL(_ context.Context, p sso.Provider, postLogout string) string {
	if p.Flag("no_logout") {
		return ""
	}
	return "https://idp.example/logout?post_logout_redirect_uri=" + postLogout
}

func (f *fakeOIDC) Check(context.Context, sso.Provider) []string { return f.problems }

func (f *fakeOIDC) state() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastState
}

// fakeSAML is upstream's FakeSaml: a response "good:<email>" is that email's identity (assertion
// id "assertion-<email>"), "unsolicited:<email>" the same without answering a request; a logout
// request "logout:<email>" names the email.
type fakeSAML struct {
	mu                       sync.Mutex
	lastRequestID, lastRelay string
}

func (f *fakeSAML) AuthnRequest(p sso.Provider, _ sso.SP, relayState string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastRequestID, f.lastRelay = "request-"+p.ID, relayState
	return f.lastRequestID, p.Setting("sso_url") + "?SAMLRequest=fake", nil
}

func (f *fakeSAML) Consume(_ sso.Provider, _ sso.SP, response, requestID string) (sso.Identity, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	kind, email, _ := strings.Cut(response, ":")
	if kind == "good" && requestID != f.lastRequestID {
		return sso.Identity{}, &sso.Error{Reason: sso.ReasonAssertionInvalid, Detail: "InResponseTo does not match"}
	}
	if (kind != "good" && kind != "unsolicited") || email == "" {
		return sso.Identity{}, &sso.Error{Reason: sso.ReasonAssertionInvalid, Detail: "the response is not good"}
	}
	return sso.Identity{Subject: email, Email: email, Attributes: map[string]any{"email": []string{email}},
		AssertionID: "assertion-" + email, NotOnOrAfter: time.Now().Add(5 * time.Minute), SessionIndex: "session-1"}, nil
}

func (f *fakeSAML) Metadata(sso.Provider, sso.SP) ([]byte, error) {
	return []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="fake"/>`), nil
}

func (f *fakeSAML) LogoutURL(p sso.Provider, _ sso.SP, _, _, _ string) (string, error) {
	if p.Setting("slo_url") == "" {
		return "", nil
	}
	return p.Setting("slo_url") + "?SAMLRequest=fake-logout", nil
}

func (f *fakeSAML) ConsumeLogoutRequest(_ sso.Provider, _ sso.SP, m sso.LogoutMessage) (sso.LogoutRequest, error) {
	kind, email, _ := strings.Cut(m.SAMLRequest, ":")
	if kind != "logout" || email == "" {
		return sso.LogoutRequest{}, &sso.Error{Reason: sso.ReasonAssertionInvalid, Detail: "the logout request is not good"}
	}
	return sso.LogoutRequest{ID: "logout-request-1", NameID: email, SessionIndexes: []string{"session-1"}}, nil
}

func (f *fakeSAML) LogoutResponseURL(p sso.Provider, _ sso.SP, inResponseTo, _ string) (string, error) {
	if p.Setting("slo_url") == "" {
		return "", nil
	}
	return p.Setting("slo_url") + "?SAMLResponse=fake-response&InResponseTo=" + inResponseTo, nil
}

func (f *fakeSAML) Check(p sso.Provider, _ sso.SP) []string {
	if p.Setting("certificate") == "broken" {
		return []string{"certificate does not parse as X.509"}
	}
	return []string{}
}

func (f *fakeSAML) relay() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRelay
}

// fakeVerifier verifies the domains listed, by DNS.
type fakeVerifier struct {
	mu         sync.Mutex
	verifiable []string
}

func (f *fakeVerifier) Verify(_ context.Context, domain, _ string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if slices.Contains(f.verifiable, domain) {
		return "dns"
	}
	return ""
}

func (f *fakeVerifier) allow(domain string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.verifiable = append(f.verifiable, domain)
}

// flow is upstream's SsoTestCase: audit, admin and sso (with the fakes) under the pipeline,
// replaying the recorded fixture of one PHP test.
type flow struct {
	t        *testing.T
	srv      *polaristest.Server
	c        *contracttest.Client
	admin    *admin.Plugin
	trail    *audit.Plugin
	oidc     *fakeOIDC
	saml     *fakeSAML
	verifier *fakeVerifier
}

func newFlow(t *testing.T, class, method string) *flow {
	t.Helper()
	f := &flow{t: t, admin: admin.New(admin.Config{}), trail: audit.New(audit.Config{}),
		oidc: &fakeOIDC{email: "ada@acme.example", name: "Ada Lovelace"}, saml: &fakeSAML{}, verifier: &fakeVerifier{}}
	plugin := sso.New(sso.Config{BaseURL: base, OIDC: f.oidc, SAML: f.saml, Domains: f.verifier})
	f.srv = polaristest.New(t, polaristest.WithPlugins(f.trail, f.admin, plugin))
	f.c = contracttest.NewClient(t, f.srv.Handler(), contracttest.For(t, contracttest.UpstreamFixtures(t, "sso"), classes+class, method))
	return f
}

func bearer(token string) contracttest.Option { return contracttest.Bearer(token) }

func doc(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	return contracttest.JSON(t, resp)
}

func data(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := doc(t, resp)["data"].(map[string]any)
	return d
}

func ids(v any) []any {
	list, _ := v.([]any)
	out := []any{}
	for _, item := range list {
		m, _ := item.(map[string]any)
		out = append(out, m["id"])
	}
	return out
}

func check(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func status(t *testing.T, resp *http.Response, want int) {
	t.Helper()
	check(t, resp.StatusCode == want, "%s %s: status %d, want %d", resp.Request.Method, resp.Request.URL, resp.StatusCode, want)
}

// problem asserts a problem document whose type matches its error code.
func problem(t *testing.T, resp *http.Response, want int, code string) map[string]any {
	t.Helper()
	status(t, resp, want)
	b := doc(t, resp)
	check(t, resp.Header.Get("Content-Type") == "application/problem+json" && b["error"] == code &&
		b["type"] == "https://polaris.univeros.io/problems/"+strings.Replace(code, "_", "/", 1), "problem %v, want %s", b, code)
	return b
}

// login registers (once), verifies and logs email in: its access token.
func (f *flow) login(email string) string {
	f.t.Helper()
	if f.c.Post("/auth/register", map[string]any{"email": email, "password": password}).StatusCode < 300 {
		var reg event.UserRegistered
		for _, e := range f.srv.Events.All() {
			if r, ok := e.(event.UserRegistered); ok {
				reg = r
			}
		}
		f.c.Post("/auth/email/verify", map[string]any{"token": reg.VerificationToken})
	}
	access, _ := data(f.t, f.c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return access
}

// organization creates an organization: its id and the access token switched to it.
func (f *flow) organization(name, access string) (string, string) {
	f.t.Helper()
	id, _ := data(f.t, f.c.Post("/orgs", map[string]any{"name": name}, bearer(access)))["id"].(string)
	switched, _ := data(f.t, f.c.Post("/auth/switch-org", map[string]any{"organization_id": id}, bearer(access)))["access_token"].(string)
	return id, switched
}

func oidcProvider() map[string]any {
	return map[string]any{"type": "oidc", "name": "Okta", "issuer": "https://acme.okta.example",
		"config": map[string]any{"client_id": "client-1", "client_secret": "shh"},
		"jit":    map[string]any{"enabled": true, "roles": []any{"member"}}, "redirect_uris": []any{done}}
}

func samlProvider() map[string]any {
	return map[string]any{"type": "saml", "name": "Acme IdP", "issuer": "https://idp.example/metadata",
		"config":     map[string]any{"sso_url": "https://idp.example/sso", "slo_url": "https://idp.example/slo", "certificate": "MIIC..."},
		"attributes": map[string]any{"email": "mail"}, "jit": map[string]any{"enabled": true, "roles": []any{"member"}},
		"redirect_uris": []any{done}}
}

func (f *flow) key(role admin.Role, scope string) string {
	f.t.Helper()
	_, secret, err := f.admin.Keys().Create(context.Background(), admin.Key{Name: "test", Role: role, Scope: scope, CreatedBy: "test"})
	if err != nil {
		f.t.Fatal(err)
	}
	return secret
}

// audited are the recorded events of names, newest first.
func (f *flow) audited(names ...string) []audit.Event {
	f.t.Helper()
	pg, err := f.trail.Store().Read(context.Background(), audit.Query{Names: names})
	if err != nil {
		f.t.Fatal(err)
	}
	return pg.Events
}

// code is the sso_code of a callback's Location.
func code(t *testing.T, resp *http.Response) string {
	t.Helper()
	status(t, resp, http.StatusFound)
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("sso_code")
}

func TestEverySsoFixtureHasAGoTest(t *testing.T) {
	missing, err := contracttest.Uncovered(contracttest.UpstreamFixtures(t, "sso"), []string{
		classes + "SsoFlowTest::testSignInThroughOidcAndSamlEndsOnTheApplicationWithACode",
		classes + "SsoOrganizationTest::testAnOrganizationManagesItsProvidersAndDomains",
		classes + "SsoOrganizationTest::testTheOperatorsSeeEveryOrganizationsProviders",
	})
	if err != nil || len(missing) > 0 {
		t.Fatalf("uncovered fixtures %v (%v)", missing, err)
	}
}

func TestSsoFlow(t *testing.T) {
	t.Run("testSignInThroughOidcAndSamlEndsOnTheApplicationWithACode", func(t *testing.T) {
		f := newFlow(t, "SsoFlowTest", "testSignInThroughOidcAndSamlEndsOnTheApplicationWithACode")
		ada := f.login("ada@acme.example")
		acme, owner := f.organization("Acme Rockets", ada)
		as := bearer(owner)
		oidc := data(t, f.c.Post("/orgs/"+acme+"/sso/providers", oidcProvider(), as))
		samlBody := samlProvider()
		samlBody["config"] = map[string]any{"sso_url": "https://idp.example/sso", "slo_url": "https://idp.example/slo", "certificate": "MIIC...", "idp_initiated": true}
		saml := data(t, f.c.Post("/orgs/"+acme+"/sso/providers", samlBody, as))
		oidcID, samlID := oidc["id"].(string), saml["id"].(string)
		domain := data(t, f.c.Post("/orgs/"+acme+"/sso/domains", map[string]any{"domain": "acme.example", "provider_id": oidcID}, as))

		problem(t, f.c.Post("/sso/sign-in", map[string]any{"email": "ada@acme.example"}), 404, "sso_provider_not_found") // not verified yet
		f.verifier.allow("acme.example")
		f.c.Post("/orgs/"+acme+"/sso/domains/"+domain["id"].(string)+"/verify", nil, as)
		problem(t, f.c.Post("/sso/sign-in", map[string]any{"email": "someone@elsewhere.example"}), 404, "sso_provider_not_found")
		problem(t, f.c.Post("/sso/sign-in", nil), 422, "sso_invalid_input")
		problem(t, f.c.Post("/sso/sign-in", map[string]any{"provider_id": oidcID, "redirect_uri": "https://evil.example/"}), 422, "sso_invalid_input")
		started := data(t, f.c.Post("/sso/sign-in", map[string]any{"email": "Ada@ACME.example"}))
		check(t, started["url"] == "https://idp.example/authorize?client_id=client-1" && started["provider_id"] == oidcID && started["type"] == "oidc", "started %v", started)

		callback := "/sso/callback/"
		problem(t, f.c.Get(callback+oidcID+"?code=good&state=unknown"), 403, "sso_assertion_invalid")
		f.c.Post("/sso/sign-in", map[string]any{"provider_id": oidcID})
		problem(t, f.c.Get(callback+oidcID+"?code=bad&state="+f.oidc.state()), 403, "sso_assertion_invalid")
		problem(t, f.c.Get(callback+samlID+"?code=good&state="+f.oidc.state()), 404, "sso_provider_not_found") // not an OIDC provider
		f.c.Post("/sso/sign-in", map[string]any{"provider_id": oidcID})
		resp := f.c.Get(callback + oidcID + "?code=good&state=" + f.oidc.state())
		check(t, strings.HasPrefix(resp.Header.Get("Location"), done+"?sso_code="), "location %q", resp.Header.Get("Location"))
		adaCode := code(t, resp)
		problem(t, f.c.Post("/sso/exchange", nil), 422, "sso_invalid_input")
		problem(t, f.c.Post("/sso/exchange", map[string]any{"code": "nope"}), 422, "sso_code_invalid")
		session := data(t, f.c.Post("/sso/exchange", map[string]any{"code": adaCode}))
		user, _ := session["user"].(map[string]any)
		check(t, session["token_type"] == "Bearer" && session["expires_in"] == 900.0 && user["email"] == "ada@acme.example" && user["email_verified"] == true, "session %v", session)
		problem(t, f.c.Post("/sso/exchange", map[string]any{"code": adaCode}), 422, "sso_code_invalid") // once
		status(t, f.c.Get("/auth/me", bearer(session["access_token"].(string))), 200)

		samlStart := data(t, f.c.Post("/sso/sign-in", map[string]any{"provider_id": samlID}))
		check(t, samlStart["url"] == "https://idp.example/sso?SAMLRequest=fake", "saml start %v", samlStart)
		problem(t, f.c.Post(callback+samlID, map[string]any{"SAMLResponse": "bad", "RelayState": f.saml.relay()}), 403, "sso_assertion_invalid")
		f.c.Post("/sso/sign-in", map[string]any{"provider_id": samlID})
		carol := data(t, f.c.Post("/sso/exchange", map[string]any{"code": code(t, f.c.Post(callback+samlID,
			map[string]any{"SAMLResponse": "good:carol@acme.example", "RelayState": f.saml.relay()}))}))
		check(t, carol["user"].(map[string]any)["email"] == "carol@acme.example", "provisioned just in time: %v", carol)
		f.c.Post("/sso/sign-in", map[string]any{"provider_id": samlID})
		problem(t, f.c.Post(callback+samlID, map[string]any{"SAMLResponse": "good:carol@acme.example", "RelayState": f.saml.relay()}), 403, "sso_assertion_invalid") // replayed
		status(t, f.c.Post(callback+samlID, map[string]any{"SAMLResponse": "unsolicited:dave@acme.example"}), 302)                                                   // IdP-initiated
		problem(t, f.c.Post(callback+samlID, nil), 403, "sso_assertion_invalid")

		logout := data(t, f.c.Post("/sso/logout", map[string]any{"provider_id": samlID}, bearer(carol["access_token"].(string))))
		check(t, logout["status"] == "logged_out" && logout["url"] == "https://idp.example/slo?SAMLRequest=fake-logout", "logout %v", logout)
		status(t, f.c.Post("/auth/token/refresh", map[string]any{"refresh_token": carol["refresh_token"]}), 401) // the session ended
		slo := f.c.Get("/sso/slo/" + samlID + "?SAMLRequest=logout:ada@acme.example&RelayState=rs")
		status(t, slo, 302)
		check(t, slo.Header.Get("Location") == "https://idp.example/slo?SAMLResponse=fake-response&InResponseTo=logout-request-1", "slo %q", slo.Header.Get("Location"))
		status(t, f.c.Post("/auth/token/refresh", map[string]any{"refresh_token": session["refresh_token"]}), 401) // the IdP ended ada's session
		problem(t, f.c.Post("/sso/slo/"+samlID, map[string]any{"SAMLRequest": "bogus"}), 403, "sso_assertion_invalid")
		check(t, data(t, f.c.Post("/sso/slo/"+samlID, map[string]any{"SAMLResponse": "fake"}))["status"] == "logged_out", "a LogoutResponse")
		problem(t, f.c.Post("/sso/slo/"+samlID, nil), 422, "sso_invalid_input")

		var reasons []any
		for _, e := range f.audited(sso.AuditAssertionRejected) {
			reasons = append(reasons, e.Data["reason"])
		}
		check(t, slices.Contains(reasons, any("the code is not good")) && slices.Contains(reasons, any("assertion assertion-carol@acme.example replayed")), "reasons %v", reasons)
		check(t, len(f.audited(sso.AuditSLOCompleted)) == 2, "the application's logout and the IdP's request")
		check(t, len(f.audited(sso.AuditSignedIn)) == 3, "ada, carol, dave")
	})
}

func TestSsoOrganization(t *testing.T) {
	t.Run("testAnOrganizationManagesItsProvidersAndDomains", func(t *testing.T) {
		f := newFlow(t, "SsoOrganizationTest", "testAnOrganizationManagesItsProvidersAndDomains")
		ada := f.login("ada@acme.example")
		acme, owner := f.organization("Acme Rockets", ada)
		bob := f.login("bob@example.com")
		as := bearer(owner)
		providers, domains := "/orgs/"+acme+"/sso/providers", "/orgs/"+acme+"/sso/domains"

		status(t, f.c.Get(providers, bearer(bob)), 403)
		status(t, f.c.Get(providers), 401)
		problem(t, f.c.Post(providers, map[string]any{"type": "ldap"}, as), 422, "sso_invalid_input")
		errs := problem(t, f.c.Post(providers, map[string]any{"type": "saml", "name": "x", "issuer": "https://idp", "config": map[string]any{"certificate": "c"}, "redirect_uris": []any{}}, as), 422, "sso_invalid_input")
		check(t, slices.Equal(errs["errors"].([]any), []any{"config.sso_url is required.", "redirect_uris needs at least one URL the sign-in may end on."}), "errors %v", errs)
		problem(t, f.c.Post(providers, map[string]any{"type": "oidc", "name": "x", "issuer": "https://idp", "config": map[string]any{"client_id": "c"}, "redirect_uris": []any{"javascript:alert(1)"}}, as), 422, "sso_invalid_input")

		oidc := data(t, f.c.Post(providers, oidcProvider(), as))
		config, _ := oidc["config"].(map[string]any)
		check(t, oidc["type"] == "oidc" && oidc["name"] == "Okta" && len(config) == 2 && config["client_id"] == "client-1" && config["client_secret_set"] == true && oidc["enabled"] == true, "oidc %v", oidc)
		saml := data(t, f.c.Post(providers, samlProvider(), as))
		oidcID, samlID := oidc["id"].(string), saml["id"].(string)
		check(t, slices.Equal(ids(doc(t, f.c.Get(providers, as))["data"]), []any{oidcID, samlID}), "listed")

		read := data(t, f.c.Get(providers+"/"+samlID, as))
		sp, _ := read["sp"].(map[string]any)
		check(t, sp["entity_id"] == base+"/sso/metadata/"+samlID && sp["acs_url"] == base+"/sso/callback/"+samlID && sp["slo_url"] == base+"/sso/slo/"+samlID, "sp %v", sp)
		problem(t, f.c.Get(providers+"/nope", as), 404, "sso_not_found")
		patched := data(t, f.c.Patch(providers+"/"+oidcID, map[string]any{"name": "Okta prod", "config": map[string]any{"client_id": "client-2"}, "enabled": false}, as))
		check(t, patched["name"] == "Okta prod" && patched["config"].(map[string]any)["client_secret_set"] == true && patched["enabled"] == false, "a config without the secret keeps it: %v", patched)
		problem(t, f.c.Patch(providers+"/"+oidcID, map[string]any{"redirect_uris": []any{}}, as), 422, "sso_invalid_input")
		tested := data(t, f.c.Post(providers+"/"+samlID+"/test", nil, as))
		check(t, tested["ok"] == true && len(tested["problems"].([]any)) == 0, "test %v", tested)
		f.oidc.problems = []string{"discovery answered 404"}
		tested = data(t, f.c.Post(providers+"/"+oidcID+"/test", nil, as))
		check(t, tested["ok"] == false, "test %v", tested)
		status(t, f.c.Get("/sso/metadata/"+samlID), 200)
		check(t, f.c.Get("/sso/metadata/"+samlID).Header.Get("Content-Type") == "application/samlmetadata+xml", "metadata content type")
		problem(t, f.c.Get("/sso/metadata/"+oidcID), 404, "sso_provider_not_found")

		problem(t, f.c.Post(domains, map[string]any{"domain": "not a domain", "provider_id": samlID}, as), 422, "sso_invalid_input")
		problem(t, f.c.Post(domains, map[string]any{"domain": "acme.example", "provider_id": "nope"}, as), 422, "sso_invalid_input")
		domain := data(t, f.c.Post(domains, map[string]any{"domain": "ACME.example", "provider_id": samlID}, as))
		verification, _ := domain["verification"].(map[string]any)
		check(t, domain["domain"] == "acme.example" && domain["verified"] == false && strings.HasPrefix(verification["token"].(string), "polaris-sso-"), "domain %v", domain)
		problem(t, f.c.Post(domains, map[string]any{"domain": "acme.example", "provider_id": samlID}, as), 409, "sso_conflict")
		domainID := domain["id"].(string)
		problem(t, f.c.Post(domains+"/"+domainID+"/verify", nil, as), 422, "sso_domain_unverified")
		f.verifier.allow("acme.example")
		check(t, data(t, f.c.Post(domains+"/"+domainID+"/verify", nil, as))["verified"] == true, "verified")
		check(t, data(t, f.c.Post(domains+"/"+domainID+"/verify", nil, as))["verified"] == true, "stays verified")
		check(t, slices.Equal(ids(doc(t, f.c.Get(domains, as))["data"]), []any{domainID}), "domains listed")
		problem(t, f.c.Delete(domains+"/nope", as), 404, "sso_not_found")
		check(t, data(t, f.c.Delete(domains+"/"+domainID, as))["status"] == "deleted", "domain deleted")
		data(t, f.c.Post(domains, map[string]any{"domain": "rockets.example", "provider_id": samlID}, as))
		check(t, data(t, f.c.Delete(providers+"/"+samlID, as))["status"] == "deleted", "provider deleted")
		check(t, len(ids(doc(t, f.c.Get(domains, as))["data"])) == 0, "the provider's domains went with it")
		check(t, slices.Equal(ids(doc(t, f.c.Get(providers, as))["data"]), []any{oidcID}), "one provider left")

		var names []string
		for _, e := range f.audited(sso.AuditProviderCreated, sso.AuditProviderUpdated, sso.AuditProviderDeleted, sso.AuditDomainAdded, sso.AuditDomainVerified, sso.AuditDomainDeleted) {
			names = append(names, e.Name)
			check(t, e.ActorType == audit.ActorUser && e.OrganizationID == acme, "actor %v", e)
		}
		check(t, slices.Equal(names, []string{sso.AuditProviderDeleted, sso.AuditDomainAdded, sso.AuditDomainDeleted, sso.AuditDomainVerified,
			sso.AuditDomainAdded, sso.AuditProviderUpdated, sso.AuditProviderCreated, sso.AuditProviderCreated}), "names %v", names)
	})

	t.Run("testTheOperatorsSeeEveryOrganizationsProviders", func(t *testing.T) {
		f := newFlow(t, "SsoOrganizationTest", "testTheOperatorsSeeEveryOrganizationsProviders")
		ada := f.login("ada@acme.example")
		acme, acmeOwner := f.organization("Acme Rockets", ada)
		globex, globexOwner := f.organization("Globex", ada)
		acmeProvider := data(t, f.c.Post("/orgs/"+acme+"/sso/providers", oidcProvider(), bearer(acmeOwner)))["id"].(string)
		globexProvider := data(t, f.c.Post("/orgs/"+globex+"/sso/providers", samlProvider(), bearer(globexOwner)))["id"].(string)
		viewer, globexViewer, owner := f.key(admin.RoleViewer, admin.ScopeInstance), f.key(admin.RoleViewer, globex), f.key(admin.RoleOwner, admin.ScopeInstance)

		problem(t, f.c.Get("/admin/sso/providers"), 401, "admin_unauthorized")
		problem(t, f.c.Get("/admin/sso/providers?limit=0", bearer(viewer)), 422, "admin_invalid_input")
		check(t, slices.Equal(ids(doc(t, f.c.Get("/admin/sso/providers", bearer(viewer)))["data"]), []any{acmeProvider, globexProvider}), "every provider")
		page := doc(t, f.c.Get("/admin/sso/providers?limit=1", bearer(viewer)))
		check(t, slices.Equal(ids(page["data"]), []any{acmeProvider}), "page one %v", page)
		check(t, slices.Equal(ids(doc(t, f.c.Get("/admin/sso/providers?limit=1&cursor="+page["next_cursor"].(string), bearer(viewer)))["data"]), []any{globexProvider}), "page two")
		check(t, slices.Equal(ids(doc(t, f.c.Get("/admin/sso/providers", bearer(globexViewer)))["data"]), []any{globexProvider}), "an organization-scoped operator sees their organization")
		problem(t, f.c.Get("/admin/sso/providers?organization_id="+acme, bearer(globexViewer)), 403, "admin_forbidden")
		listed := doc(t, f.c.Get("/admin/sso/providers?organization_id="+acme, bearer(viewer)))["data"].([]any)
		_, secret := listed[0].(map[string]any)["config"].(map[string]any)["client_secret"]
		check(t, !secret, "the secret is never listed")

		problem(t, f.c.Delete("/admin/sso/providers/"+acmeProvider, bearer(viewer)), 403, "admin_forbidden")
		problem(t, f.c.Delete("/admin/sso/providers/nope", bearer(owner)), 404, "admin_not_found")
		check(t, data(t, f.c.Delete("/admin/sso/providers/"+acmeProvider, bearer(owner)))["status"] == "deleted", "deleted")
		check(t, len(ids(doc(t, f.c.Get("/orgs/"+acme+"/sso/providers", bearer(acmeOwner)))["data"])) == 0, "gone")
		deleted := f.audited(sso.AuditProviderDeleted)[0]
		check(t, deleted.ActorType == audit.ActorAPIKey && deleted.SubjectID == acmeProvider && deleted.OrganizationID == acme && deleted.Data["actor_role"] == "owner", "deleted %v", deleted)
	})
}
