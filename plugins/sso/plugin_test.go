package sso_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/univeros/polaris.go/internal/services"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/storetest"
	"github.com/univeros/polaris.go/token"
)

// unit is the unit-level environment: the plugin wired through the graph, the flow through its methods
// with the fake protocols.
type unit struct {
	t      *testing.T
	ctx    context.Context
	srv    *polaristest.Server
	p      *sso.Plugin
	trail  *audit.Plugin
	oidc   *fakeOIDC
	saml   *fakeSAML
	client token.ClientContext
}

func newUnit(t *testing.T) *unit {
	t.Helper()
	u := &unit{t: t, ctx: context.Background(), trail: audit.New(audit.Config{}), oidc: &fakeOIDC{email: "ada@acme.example", name: "Ada Lovelace"},
		saml: &fakeSAML{}, client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}}
	u.p = sso.New(sso.Config{BaseURL: base, OIDC: u.oidc, SAML: u.saml, Domains: &fakeVerifier{}})
	u.srv = polaristest.New(t, polaristest.WithPlugins(u.trail, admin.New(admin.Config{}), u.p))
	return u
}

// organization is Acme, owned by a user with ownerEmail: its id.
func (u *unit) organization(ownerEmail string) string {
	u.t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	owner := model.User{ID: "u-owner", Email: ownerEmail, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := u.srv.Graph().Repos().Users.Insert(u.ctx, owner); err != nil {
		u.t.Fatal(err)
	}
	org, err := services.Of(u.srv.Graph()).Orgs.CreateOrganization(u.ctx, "Acme", "", owner.ID)
	if err != nil {
		u.t.Fatal(err)
	}
	return org.ID
}

func (u *unit) provider(p sso.Provider) sso.Provider {
	u.t.Helper()
	created, err := u.p.Providers().Create(u.ctx, p)
	if err != nil {
		u.t.Fatal(err)
	}
	return created
}

func (u *unit) update(p sso.Provider, change func(*sso.Provider)) sso.Provider {
	u.t.Helper()
	next := p
	change(&next)
	updated, err := u.p.Providers().Update(u.ctx, p, next)
	if err != nil {
		u.t.Fatal(err)
	}
	return updated
}

func (u *unit) reasons(names ...string) []any {
	u.t.Helper()
	var out []any
	for _, e := range (&flow{t: u.t, trail: u.trail}).audited(names...) {
		out = append(out, e.Data["reason"])
	}
	return out
}

func refused(t *testing.T, err error, reason, what string) {
	t.Helper()
	e, ok := errors.AsType[*sso.Error](err)
	if !ok || e.Reason != reason {
		t.Fatalf("%s: %v, want %s", what, err, reason)
	}
}

func TestEverythingIsWiredThroughTheGraph(t *testing.T) {
	u := newUnit(t)
	g := u.srv.Graph()
	var routes []string
	for _, r := range g.Manifest().Routes() {
		if !slices.Contains(r.Tags, "sso") {
			continue
		}
		routes = append(routes, r.Method+" "+r.Path)
		switch {
		case strings.HasPrefix(r.Path, "/orgs/"):
			check(t, r.Auth == manifest.AuthBearer && slices.Equal(r.RequiresPermissions, []string{"org.update"}), "%s", r.File)
		case strings.HasPrefix(r.Path, "/admin/"):
			check(t, r.Auth == manifest.AuthPublic && slices.Contains(r.Tags, "admin"), "%s", r.File)
		}
	}
	check(t, len(routes) == 20 && slices.Contains(routes, "POST /sso/sign-in") && slices.Contains(routes, "GET /sso/callback/{providerId}") &&
		slices.Contains(routes, "POST /sso/callback/{providerId}") && slices.Contains(routes, "DELETE /admin/sso/providers/{id}"), "routes %v", routes)
	for _, name := range []string{sso.AuditProviderCreated, sso.AuditSignedIn, sso.AuditAssertionRejected, sso.AuditSLOCompleted, sso.AuditDomainVerified} {
		check(t, u.trail.Catalog().Has(name), "catalog lacks %s", name)
	}
	sp := u.p.SP()
	check(t, sp.EntityID("p1") == base+"/sso/metadata/p1" && sp.ACSURL("p1") == base+"/sso/callback/p1" && sp.SLOURL("p1") == base+"/sso/slo/p1", "sp %v", sp)
	check(t, sso.Of(g) == u.p, "Of")
	check(t, len(sso.Models()) == 3 && sso.Models()[0].Table == sso.TableProviders && sso.Models()[2].Table == sso.TableAccounts, "models")
}

func TestProvidersKeepTheSecretEncryptedAndAreListed(t *testing.T) {
	u := newUnit(t)
	providers := u.p.Providers()
	p := u.provider(sso.Provider{OrganizationID: "org-1", Type: sso.TypeOIDC, Name: "Okta", Issuer: "https://acme.okta.com",
		Config: map[string]any{"client_id": "c1", "client_secret": "shh"}, Attributes: map[string]string{"email": "email"},
		JIT: sso.JIT{Enabled: true, Roles: []string{"member"}}, RedirectURIs: []string{"https://app.example/done"}, Enabled: true, CreatedBy: "u1"})
	row, err := u.srv.DB.FindOne(u.ctx, sso.TableProviders, store.Criteria{"id": p.ID})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	check(t, json.Unmarshal([]byte(row.String("config")), &config) == nil && config["client_id"] == "c1" &&
		config["client_secret"] != "shh" && !strings.Contains(row.String("config"), "shh"), "encrypted at rest: %s", row.String("config"))
	stored := func(col, want string) bool {
		if storetest.JSONNormalized(u.srv.DB.Dialect()) { // jsonb / MySQL JSON hand back their own form
			var g, w any
			return json.Unmarshal([]byte(row.String(col)), &g) == nil && json.Unmarshal([]byte(want), &w) == nil && reflect.DeepEqual(g, w)
		}
		return row.String(col) == want
	}
	if !storetest.JSONNormalized(u.srv.DB.Dialect()) {
		check(t, strings.HasPrefix(row.String("config"), `{"client_id":"c1","client_secret":"`), "stored bytes: %s", row.String("config"))
	}
	check(t, stored("redirect_uris", `["https:\/\/app.example\/done"]`) && stored("jit", `{"enabled":true,"roles":["member"]}`) &&
		stored("attributes", `{"email":"email"}`), "stored in the escaped JSON form: %v", row)
	secret, err := providers.Secret(p)
	check(t, secret == "shh" && err == nil, "secret %q %v", secret, err)
	m := p.Map()
	_, leaked := m["config"].(map[string]any)["client_secret"]
	check(t, !leaked && m["config"].(map[string]any)["client_secret_set"] == true, "map %v", m)

	p = u.update(p, func(n *sso.Provider) {
		n.Name, n.Config, n.Enabled = "Okta 2", map[string]any{"client_id": "c1"}, false
	})
	found, _, _ := providers.Find(u.ctx, p.ID)
	secret, _ = providers.Secret(found)
	check(t, secret == "shh" && found.Name == "Okta 2" && !found.Enabled, "an update without a secret keeps it: %q %+v", secret, found)
	p = u.update(p, func(n *sso.Provider) {
		n.Name, n.Config, n.JIT = "Okta 3", map[string]any{"client_id": "c1", "client_secret": "new"}, sso.JIT{}
	})
	secret, _ = providers.Secret(p)
	check(t, secret == "new" && p.Name == "Okta 3" && !p.JIT.Enabled, "a new secret: %q", secret)
	samlP := u.provider(sso.Provider{OrganizationID: "org-1", Type: sso.TypeSAML, Name: "IdP", Issuer: "https://idp",
		Config: map[string]any{"sso_url": "https://idp/sso", "certificate": "x"}, RedirectURIs: []string{"https://app.example/done"}, Enabled: true})
	secret, _ = providers.Secret(samlP)
	_, hasSet := samlP.Map()["config"].(map[string]any)["client_secret_set"]
	check(t, secret == "" && !hasSet && samlP.Map()["created_by"] == nil, "a SAML provider has no secret")
	all, _ := providers.ForOrganization(u.ctx, "org-1")
	check(t, len(all) == 2, "for organization %d", len(all))
	page, next, err := providers.List(u.ctx, "", "", 1)
	check(t, len(page) == 1 && next != "" && err == nil, "page %v %q", page, next)
	rest, next, _ := providers.List(u.ctx, "org-1", next, 500)
	check(t, len(rest) == 1 && next == "", "rest %v", rest)
	deleted, _ := providers.Delete(u.ctx, p.ID)
	again, _ := providers.Delete(u.ctx, p.ID)
	check(t, deleted && !again, "delete")
}

func TestTheOIDCFlowRoutesByDomainProvisionsAndHandsTheSessionOver(t *testing.T) {
	u := newUnit(t)
	g := u.srv.Graph()
	orgID := u.organization("ada@example.com")
	prov := u.provider(sso.Provider{OrganizationID: orgID, Type: sso.TypeOIDC, Name: "Okta", Issuer: "https://acme.okta.com",
		Config: map[string]any{"client_id": "c1"}, JIT: sso.JIT{Enabled: true, Roles: []string{"member"}},
		RedirectURIs: []string{"https://app.example/done", "https://app.example/other"}, Enabled: true})
	domain, err := u.p.Domains().Add(u.ctx, orgID, prov.ID, "ACME.example")
	if err != nil {
		t.Fatal(err)
	}

	_, err = u.p.Start(u.ctx, "carol@acme.example", "", "")
	refused(t, err, sso.ReasonProviderNotFound, "the domain is not verified yet")
	verified, _ := u.p.DomainVerified(u.ctx, orgID, "acme.example")
	check(t, !verified, "not verified yet")
	if _, err := u.p.Domains().MarkVerified(u.ctx, domain); err != nil {
		t.Fatal(err)
	}
	_, err = u.p.Start(u.ctx, "carol@elsewhere.example", "", "")
	refused(t, err, sso.ReasonProviderNotFound, "another domain")
	_, err = u.p.Start(u.ctx, "", "", "")
	refused(t, err, sso.ReasonInvalidInput, "no email")
	_, err = u.p.Start(u.ctx, "carol@acme.example", "", "https://evil.example/")
	refused(t, err, sso.ReasonInvalidInput, "not one of the provider's redirect uris")
	started, err := u.p.Start(u.ctx, "Carol@ACME.example", "", "https://app.example/other")
	check(t, err == nil && started == sso.Started{URL: "https://idp.example/authorize?client_id=c1", ProviderID: prov.ID, Type: "oidc"}, "started %v %v", started, err)

	restart := func(redirect string) string {
		if _, err := u.p.Start(u.ctx, "ada@acme.example", "", redirect); err != nil {
			t.Fatal(err)
		}
		return u.oidc.state()
	}
	_, err = u.p.CompleteOIDC(u.ctx, prov.ID, "good", "unknown-state", "", u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "unknown state")
	_, err = u.p.CompleteOIDC(u.ctx, prov.ID, "bad", restart(""), "", u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "a bad code")
	_, err = u.p.CompleteOIDC(u.ctx, prov.ID, "", restart(""), "access_denied", u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "the provider refused")
	_, err = u.p.CompleteOIDC(u.ctx, prov.ID, "", restart(""), "", u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "no code")
	_, err = u.p.CompleteOIDC(u.ctx, "nope", "good", restart(""), "", u.client)
	refused(t, err, sso.ReasonProviderNotFound, "no provider")

	state := restart("https://app.example/other")
	to, err := u.p.CompleteOIDC(u.ctx, prov.ID, "good", state, "", u.client)
	check(t, err == nil && strings.HasPrefix(to, "https://app.example/other?sso_code="), "redirect %q %v", to, err)
	_, err = u.p.CompleteOIDC(u.ctx, prov.ID, "good", state, "", u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "a state is single-use")
	loc, _ := url.Parse(to)
	session, err := u.p.Exchange(u.ctx, loc.Query().Get("sso_code"))
	user, _ := session["user"].(map[string]any)
	check(t, err == nil && session["token_type"] == "Bearer" && user["email"] == "ada@acme.example" && user["email_verified"] == true, "session %v %v", session, err)
	_, err = u.p.Exchange(u.ctx, loc.Query().Get("sso_code"))
	refused(t, err, sso.ReasonCodeInvalid, "once")
	_, err = u.p.Exchange(u.ctx, "nope")
	refused(t, err, sso.ReasonCodeInvalid, "unknown")

	ada, err := g.Repos().Users.ByEmail(u.ctx, "ada@acme.example")
	check(t, err == nil && ada.DisplayName != nil && *ada.DisplayName == "Ada Lovelace" && ada.EmailVerifiedAt != nil && ada.PasswordHash == nil && ada.LastLoginAt != nil,
		"provisioned just in time: %+v %v", ada, err)
	m, err := g.Repos().Memberships.ByUserAndOrganization(u.ctx, ada.ID, orgID)
	links, _ := g.Repos().MembershipRoles.ListByMembership(u.ctx, m.ID)
	check(t, err == nil && m.Status == model.MembershipStatusActive && len(links) == 1, "the member role: %+v %v", m, links)
	tok, err := g.Tokens().Verify(session["access_token"].(string))
	if err != nil {
		t.Fatal(err)
	}
	check(t, tok.Subject() == ada.ID && tok.Organization() == orgID && slices.Equal(tok.Claim("amr").([]any), []any{"sso"}) &&
		slices.Contains(tok.Claim("roles").([]any), any("member")), "claims %v", tok)
	var logins []event.UserLoggedIn
	joined := 0
	for _, e := range u.srv.Events.All() {
		switch e := e.(type) {
		case event.UserLoggedIn:
			logins = append(logins, e)
		case event.MemberJoined:
			joined++
		}
	}
	check(t, len(logins) == 1 && logins[0].UserID == ada.ID && slices.Equal(logins[0].AMR, []string{"sso"}) && *logins[0].IP == "203.0.113.7" && joined == 1, "events %v %d", logins, joined)
	f := &flow{t: t, trail: u.trail}
	signedIn := f.audited(sso.AuditSignedIn)[0]
	check(t, signedIn.Data["provider_id"] == prov.ID && signedIn.Data["type"] == "oidc" && signedIn.Data["provisioned"] == true && signedIn.Data["joined"] == true && signedIn.IP == "203.0.113.7",
		"signed in %+v", signedIn)
	check(t, slices.Equal(u.reasons(sso.AuditAssertionRejected), []any{"unknown or expired state", "no code in the callback", "the provider answered access_denied", "the code is not good", "unknown or expired state"}),
		"reasons %v", u.reasons(sso.AuditAssertionRejected))

	again, err := u.p.CompleteOIDC(u.ctx, prov.ID, "good", restart(""), "", u.client)
	check(t, err == nil && strings.HasPrefix(again, "https://app.example/done?sso_code="), "the first redirect uri by default: %q", again)
	latest := f.audited(sso.AuditSignedIn)[0]
	check(t, latest.Data["provisioned"] == false && latest.Data["joined"] == false, "a returning member %v", latest.Data)

	prov = u.update(prov, func(n *sso.Provider) { n.JIT = sso.JIT{} })
	disabled := ada
	disabled.Status = model.UserStatusDisabled
	if err := g.Repos().Users.Update(u.ctx, ada, disabled); err != nil {
		t.Fatal(err)
	}
	_, err = u.p.CompleteOIDC(u.ctx, prov.ID, "good", restart(""), "", u.client)
	refused(t, err, sso.ReasonAccountDisabled, "a disabled account")
	moved := disabled
	moved.Email = "moved@acme.example"
	if err := g.Repos().Users.Update(u.ctx, disabled, moved); err != nil {
		t.Fatal(err)
	}
	_, err = u.p.CompleteOIDC(u.ctx, prov.ID, "good", restart(""), "", u.client)
	refused(t, err, sso.ReasonUserUnknown, "no account and no provisioning")

	prov = u.update(prov, func(n *sso.Provider) { n.Enabled = false })
	_, err = u.p.Start(u.ctx, "carol@acme.example", "", "")
	refused(t, err, sso.ReasonProviderDisabled, "a disabled provider")
	_, err = u.p.CompleteOIDC(u.ctx, prov.ID, "good", "x", "", u.client)
	refused(t, err, sso.ReasonProviderDisabled, "a disabled provider's callback")
	to, err = u.p.Logout(u.ctx, moved, orgID, prov.ID, "", u.client)
	check(t, err == nil && to == "https://idp.example/logout?post_logout_redirect_uri=https://app.example/done", "logout %q %v", to, err)
	to, err = u.p.Logout(u.ctx, moved, orgID, "", "https://app.example/other", u.client)
	check(t, err == nil && strings.HasSuffix(to, "=https://app.example/other"), "the organization's first provider %q %v", to, err)
	_, err = u.p.Logout(u.ctx, moved, orgID, "", "https://evil.example/", u.client)
	refused(t, err, sso.ReasonInvalidInput, "a foreign post-logout uri")
	silent := u.update(prov, func(n *sso.Provider) { n.Config = map[string]any{"client_id": "c1", "no_logout": true} })
	to, err = u.p.Logout(u.ctx, moved, orgID, silent.ID, "", u.client)
	check(t, err == nil && to == "", "no end session %q %v", to, err)
}

func TestTheSAMLFlowRefusesReplaysAndUnsolicitedResponsesUnlessAllowedAndLogsOutBothWays(t *testing.T) {
	u := newUnit(t)
	g := u.srv.Graph()
	orgID := u.organization("ada@example.com")
	config := map[string]any{"sso_url": "https://idp.example/sso", "slo_url": "https://idp.example/slo", "certificate": "cert"}
	prov := u.provider(sso.Provider{OrganizationID: orgID, Type: sso.TypeSAML, Name: "IdP", Issuer: "https://idp.example/metadata",
		Config: config, JIT: sso.JIT{Enabled: true}, RedirectURIs: []string{"https://app.example/done"}, Enabled: true})
	start := func() string {
		started, err := u.p.Start(u.ctx, "", prov.ID, "")
		check(t, err == nil && started.URL == "https://idp.example/sso?SAMLRequest=fake", "started %v %v", started, err)
		return u.saml.relay()
	}

	_, err := u.p.CompleteSAML(u.ctx, prov.ID, "bad", start(), u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "a bad response")
	to, err := u.p.CompleteSAML(u.ctx, prov.ID, "good:bob@acme.example", start(), u.client)
	check(t, err == nil && strings.HasPrefix(to, "https://app.example/done?sso_code="), "redirect %q %v", to, err)
	bob, err := g.Repos().Users.ByEmail(u.ctx, "bob@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	m, _ := g.Repos().Memberships.ByUserAndOrganization(u.ctx, bob.ID, orgID)
	links, _ := g.Repos().MembershipRoles.ListByMembership(u.ctx, m.ID)
	check(t, len(links) == 1, "the member role by default")

	_, err = u.p.CompleteSAML(u.ctx, prov.ID, "good:bob@acme.example", start(), u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "the assertion id was seen")
	_, err = u.p.CompleteSAML(u.ctx, prov.ID, "unsolicited:carol@acme.example", "", u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "IdP-initiated is off")
	_, err = u.p.CompleteSAML(u.ctx, prov.ID, "", "", u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "no response")
	allowed := map[string]any{"idp_initiated": true}
	for k, v := range config {
		allowed[k] = v
	}
	prov = u.update(prov, func(n *sso.Provider) { n.Config = allowed })
	to, err = u.p.CompleteSAML(u.ctx, prov.ID, "unsolicited:carol@acme.example", "", u.client)
	check(t, err == nil && strings.HasPrefix(to, "https://app.example/done?sso_code="), "IdP-initiated is on: %q %v", to, err)
	check(t, slices.Equal(u.reasons(sso.AuditAssertionRejected), []any{"no SAMLResponse in the callback",
		"unsolicited response and the provider does not allow IdP-initiated sign-in", "assertion assertion-bob@acme.example replayed", "the response is not good"}),
		"reasons %v", u.reasons(sso.AuditAssertionRejected))

	to, err = u.p.IdPLogout(u.ctx, prov.ID, sso.LogoutMessage{SAMLRequest: "logout:bob@acme.example", Redirect: true}, u.client)
	check(t, err == nil && to == "https://idp.example/slo?SAMLResponse=fake-response&InResponseTo=logout-request-1", "idp logout %q %v", to, err)
	slo := (&flow{t: t, trail: u.trail}).audited(sso.AuditSLOCompleted)[0]
	check(t, slo.Data["direction"] == "idp" && fmt.Sprint(slo.Data["sessions_revoked"]) == "1" && slo.SubjectID == bob.ID, "slo %+v", slo)
	_, err = u.p.IdPLogout(u.ctx, prov.ID, sso.LogoutMessage{SAMLRequest: "bogus"}, u.client)
	refused(t, err, sso.ReasonAssertionInvalid, "a bogus logout request")
	to, err = u.p.IdPLogout(u.ctx, prov.ID, sso.LogoutMessage{SAMLRequest: "logout:nobody@acme.example"}, u.client)
	check(t, err == nil && to != "", "an unknown user's logout still answers: %v", err)
	to, err = u.p.Logout(u.ctx, bob, orgID, "", "", u.client)
	check(t, err == nil && to == "https://idp.example/slo?SAMLRequest=fake-logout", "logout %q %v", to, err)
	_, err = u.p.Logout(u.ctx, bob, "other-org", "", "", u.client)
	refused(t, err, sso.ReasonProviderNotFound, "another organization")
	_, err = u.p.Logout(u.ctx, bob, "other-org", prov.ID, "", u.client)
	refused(t, err, sso.ReasonProviderNotFound, "another organization's provider")

	noSLO := u.update(prov, func(n *sso.Provider) {
		n.Config = map[string]any{"sso_url": "https://idp.example/sso", "certificate": "cert"}
	})
	to, err = u.p.IdPLogout(u.ctx, noSLO.ID, sso.LogoutMessage{SAMLRequest: "logout:bob@acme.example"}, u.client)
	check(t, err == nil && to == "", "no SLO URL: %q %v", to, err)
}

func TestMembershipsGateTheSignIn(t *testing.T) {
	u := newUnit(t)
	g := u.srv.Graph()
	orgID := u.organization("owner@acme.example")
	prov := u.provider(sso.Provider{OrganizationID: orgID, Type: sso.TypeSAML, Name: "IdP", Issuer: "https://idp",
		Config: map[string]any{"sso_url": "https://idp/sso", "certificate": "c"}, JIT: sso.JIT{Enabled: true, Roles: []string{"admin", "ghost"}},
		RedirectURIs: []string{"https://app.example/done?from=sso"}, Enabled: true})
	if _, err := u.p.Start(u.ctx, "", prov.ID, ""); err != nil {
		t.Fatal(err)
	}
	to, err := u.p.CompleteSAML(u.ctx, prov.ID, "good:eve@acme.example", u.saml.relay(), u.client)
	check(t, err == nil && strings.HasPrefix(to, "https://app.example/done?from=sso&sso_code="), "a redirect with a query %q %v", to, err)
	eve, _ := g.Repos().Users.ByEmail(u.ctx, "eve@acme.example")
	m, _ := g.Repos().Memberships.ByUserAndOrganization(u.ctx, eve.ID, orgID)
	links, _ := g.Repos().MembershipRoles.ListByMembership(u.ctx, m.ID)
	check(t, len(links) == 1, "the admin role; an unknown slug is skipped: %v", links)
	suspended := m
	suspended.Status = model.MembershipStatusSuspended
	if err := g.Repos().Memberships.Update(u.ctx, m, suspended); err != nil {
		t.Fatal(err)
	}
	if _, err := u.p.Start(u.ctx, "", prov.ID, ""); err != nil {
		t.Fatal(err)
	}
	_, err = u.p.CompleteSAML(u.ctx, prov.ID, "good:eve2@acme.example", u.saml.relay(), u.client)
	check(t, err == nil, "another person signs in: %v", err)
	if _, err := u.p.Start(u.ctx, "", prov.ID, ""); err != nil {
		t.Fatal(err)
	}
	u.saml.mu.Lock()
	u.saml.lastRequestID = "request-" + prov.ID
	u.saml.mu.Unlock()
	_, err = g.Repos().Users.ByEmail(u.ctx, "eve@acme.example")
	check(t, err == nil, "eve exists")
	// eve's assertion id was used: a fresh identity with the same email needs another id, so go
	// through the OIDC fake bound to eve instead.
	u.oidc.email = "eve@acme.example"
	oidcProv := u.provider(sso.Provider{OrganizationID: orgID, Type: sso.TypeOIDC, Name: "Okta", Issuer: "https://okta",
		Config: map[string]any{"client_id": "c"}, RedirectURIs: []string{"https://app.example/done"}, Enabled: true})
	if _, err := u.p.Start(u.ctx, "", oidcProv.ID, ""); err != nil {
		t.Fatal(err)
	}
	_, err = u.p.CompleteOIDC(u.ctx, oidcProv.ID, "good", u.oidc.state(), "", u.client)
	refused(t, err, sso.ReasonMembershipSuspended, "a suspended membership")

	noRedirect := u.provider(sso.Provider{OrganizationID: orgID, Type: sso.TypeOIDC, Name: "Bare", Issuer: "https://bare",
		Config: map[string]any{"client_id": "c"}, Enabled: true})
	_, err = u.p.Start(u.ctx, "", noRedirect.ID, "")
	refused(t, err, sso.ReasonInvalidInput, "a provider without redirect uris")
}

func TestDomainVerifiedIsPerOrganizationAndExact(t *testing.T) {
	u := newUnit(t)
	orgID := u.organization("owner@acme.example")
	d, err := u.p.Domains().Add(u.ctx, orgID, "p1", "Acme.Example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.p.Domains().MarkVerified(u.ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := u.p.Domains().Add(u.ctx, orgID, "p1", "pending.example"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		org, domain string
		want        bool
	}{
		{orgID, "acme.example", true}, {orgID, "ACME.EXAMPLE", true}, {"other-org", "acme.example", false},
		{orgID, "sub.acme.example", false}, {orgID, "example", false}, {orgID, " acme.example", false},
		{orgID, "pending.example", false}, {orgID, "", false},
	} {
		got, err := u.p.DomainVerified(u.ctx, c.org, c.domain)
		check(t, got == c.want && err == nil, "DomainVerified(%q, %q) = %v %v", c.org, c.domain, got, err)
	}
	var verifier interface {
		DomainVerified(context.Context, string, string) (bool, error)
	}
	verifier, ok := u.srv.Graph().Plugin("sso").(interface {
		DomainVerified(context.Context, string, string) (bool, error)
	})
	check(t, ok && verifier != nil, "scim reaches it through g.Plugin(\"sso\")")
}

// An organization admin runs the organization's IdP, so its assertions reach only the
// organization's members, the people of its verified domains and the new accounts it provisions.
func TestAnOrganizationsIdPCannotClaimOutsideAccounts(t *testing.T) {
	u := newUnit(t)
	g := u.srv.Graph()
	orgID := u.organization("owner@acme.example")
	now := time.Now().UTC().Truncate(time.Second)
	victim := model.User{ID: "u-victim", Email: "ceo@globex.example", Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := g.Repos().Users.Insert(u.ctx, victim); err != nil {
		t.Fatal(err)
	}
	issued, err := g.Sessions().Issue(u.ctx, token.SessionPrincipal{UserID: victim.ID}, u.client)
	if err != nil {
		t.Fatal(err)
	}
	prov := u.provider(sso.Provider{OrganizationID: orgID, Type: sso.TypeSAML, Name: "IdP", Issuer: "https://idp",
		Config: map[string]any{"sso_url": "https://idp/sso", "slo_url": "https://idp/slo", "certificate": "c"}, JIT: sso.JIT{Enabled: true},
		RedirectURIs: []string{"https://app.example/done"}, Enabled: true})
	if _, err := u.p.Start(u.ctx, "", prov.ID, ""); err != nil {
		t.Fatal(err)
	}
	_, err = u.p.CompleteSAML(u.ctx, prov.ID, "good:ceo@globex.example", u.saml.relay(), u.client)
	refused(t, err, sso.ReasonUserUnknown, "an outside account")
	_, err = g.Repos().Memberships.ByUserAndOrganization(u.ctx, victim.ID, orgID)
	check(t, err != nil, "no membership was created")

	to, err := u.p.IdPLogout(u.ctx, prov.ID, sso.LogoutMessage{SAMLRequest: "logout:ceo@globex.example"}, u.client)
	check(t, err == nil && to != "", "the IdP is answered: %v", err)
	_, err = services.Of(g).Sessions.Refresh(u.ctx, issued.RefreshToken, u.client)
	check(t, err == nil, "an outside account's sessions stay: %v", err)

	d, err := u.p.Domains().Add(u.ctx, orgID, prov.ID, "globex.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.p.Domains().MarkVerified(u.ctx, d); err != nil {
		t.Fatal(err)
	}
	u.oidc.email = "ceo@globex.example"
	oidcProv := u.provider(sso.Provider{OrganizationID: orgID, Type: sso.TypeOIDC, Name: "Okta", Issuer: "https://okta",
		Config: map[string]any{"client_id": "c"}, RedirectURIs: []string{"https://app.example/done"}, Enabled: true})
	if _, err := u.p.Start(u.ctx, "", oidcProv.ID, ""); err != nil {
		t.Fatal(err)
	}
	_, err = u.p.CompleteOIDC(u.ctx, oidcProv.ID, "good", u.oidc.state(), "", u.client)
	check(t, err == nil, "the organization's verified domain: %v", err)
}
