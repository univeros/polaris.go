package sso_test

// Decision 74: what an organization's identity provider may vouch for, the browser a sign-in
// belongs to, the roles a provider hands out, and domain claims.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/token"
)

// do is one JSON request with cookies, as a browser sends it.
func (u *unit) do(method, path, bearer string, body map[string]any, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	u.t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	u.srv.Handler().ServeHTTP(w, r)
	return w
}

// tenant registers email, creates an organization of theirs over HTTP and switches to it: the
// organization's id and the owner's access token.
func (u *unit) tenant(email, name string) (string, string) {
	u.t.Helper()
	_, access := u.account(email)
	_, org := u.call(http.MethodPost, "/orgs", access, map[string]any{"name": name})
	id, _ := org["id"].(string)
	return id, u.switchTo(access, id)
}

// joinAs makes userID an active member of the organization with one of its roles.
func (u *unit) joinAs(userID, organizationID, slug string) {
	u.t.Helper()
	g := u.srv.Graph()
	now := time.Now().UTC().Truncate(time.Second)
	m := model.Membership{ID: repository.NewID(), UserID: userID, OrganizationID: organizationID, Status: model.MembershipStatusActive,
		JoinedAt: &now, CreatedAt: now, UpdatedAt: now}
	if err := g.Repos().Memberships.Insert(u.ctx, m); err != nil {
		u.t.Fatal(err)
	}
	role, err := g.Repos().Roles.ByOrganizationAndSlug(u.ctx, &organizationID, slug)
	if err != nil {
		u.t.Fatal(err)
	}
	if err := g.Repos().MembershipRoles.Insert(u.ctx, model.MembershipRole{MembershipID: m.ID, RoleID: role.ID}); err != nil {
		u.t.Fatal(err)
	}
}

func (u *unit) switchTo(access, organizationID string) string {
	u.t.Helper()
	code, body := u.call(http.MethodPost, "/auth/switch-org", access, map[string]any{"organization_id": organizationID})
	switched, _ := body["access_token"].(string)
	if code != 200 || switched == "" {
		u.t.Fatalf("switch-org: %d %v", code, body)
	}
	return switched
}

// A provider vouches for a mailbox only on a domain its organization verified. Anywhere else the
// account it creates is unverified, and the first proof by the mailbox's owner ends the
// organization's hold on it.
func TestAProviderVouchesOnlyForItsOrganizationsDomains(t *testing.T) {
	u := newUnit(t)
	g := u.srv.Graph()
	acme := u.organization("owner@acme.example")
	prov := u.oidcProvider(acme)

	session, err := u.ssoSession(prov, "ceo@globex.example")
	if err != nil {
		t.Fatal(err)
	}
	created, err := g.Repos().Users.ByEmail(u.ctx, "ceo@globex.example")
	if err != nil {
		t.Fatal(err)
	}
	if user, _ := session["user"].(map[string]any); created.EmailVerifiedAt != nil || user["email_verified"] != false {
		t.Fatalf("the provider verified an address outside its organization's domains: %v %v", created.EmailVerifiedAt, user)
	}
	if _, err := u.ssoSession(prov, "ceo@globex.example"); err != nil {
		t.Fatalf("the account it provisioned signs in again: %v", err)
	}
	if again, _ := g.Repos().Users.Get(u.ctx, created.ID); again.EmailVerifiedAt != nil {
		t.Fatal("a later sign-in verified the account")
	}

	// The mailbox's owner proves it (a reset): the account is theirs, the organization's no more.
	identity := services.Of(g).Identity
	if err := identity.ForgotPassword(u.ctx, "ceo@globex.example", u.client); err != nil {
		t.Fatal(err)
	}
	var reset event.PasswordResetRequested
	for _, e := range u.srv.Events.All() {
		if r, ok := e.(event.PasswordResetRequested); ok {
			reset = r
		}
	}
	if err := identity.ResetPassword(u.ctx, reset.ResetToken, "correct horse battery staple", u.client); err != nil {
		t.Fatal(err)
	}
	_, err = u.ssoSession(prov, "ceo@globex.example")
	refused(t, err, sso.ReasonUserUnknown, "an account whose owner proved the mailbox")

	// On a domain the organization verified, the provider's word is the proof.
	d, err := u.p.Domains().Add(u.ctx, acme, prov.ID, "acme.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.p.Domains().MarkVerified(u.ctx, d); err != nil {
		t.Fatal(err)
	}
	session, err = u.ssoSession(prov, "bob@acme.example")
	if user, _ := session["user"].(map[string]any); err != nil || user["email_verified"] != true {
		t.Fatalf("a verified domain: %v %v", session, err)
	}
}

// A sign-in completes only in the browser that started it.
func TestASignInCompletesOnlyInTheBrowserThatStartedIt(t *testing.T) {
	u := newUnit(t)
	acme := u.organization("owner@acme.example")
	prov := u.oidcProvider(acme)
	u.oidc.email = "mallory@elsewhere.example"
	start := func() []*http.Cookie {
		w := u.do(http.MethodPost, "/sso/sign-in", "", map[string]any{"provider_id": prov.ID})
		if w.Code != 200 {
			t.Fatalf("sign-in: %d %s", w.Code, w.Body)
		}
		return w.Result().Cookies()
	}
	callback := func(cookies ...*http.Cookie) int {
		return u.do(http.MethodGet, "/sso/callback/"+prov.ID+"?code=good&state="+url.QueryEscape(u.oidc.state()), "", nil, cookies...).Code
	}

	// The attacker starts a sign-in as themselves and hands the callback URL to a victim.
	attacker := start()
	if len(attacker) != 1 || !attacker[0].HttpOnly || !attacker[0].Secure || attacker[0].SameSite != http.SameSiteNoneMode {
		t.Fatalf("the sign-in binds its browser with one cookie: %+v", attacker)
	}
	if code := callback(); code != 403 {
		t.Fatalf("a callback in another browser: %d, want 403", code)
	}
	// Nor with a binding of the victim's own, from a sign-in they started.
	victim := start()
	forged := *victim[0]
	other := start()
	forged.Name = other[0].Name
	if code := callback(&forged); code != 403 {
		t.Fatalf("a callback with another sign-in's binding: %d, want 403", code)
	}
	if code := callback(start()...); code != 302 {
		t.Fatalf("the browser that started it: %d, want 302", code)
	}
}

// The roles a provider gives the members it provisions are the organization's own: whoever may
// configure a provider may grant any of them (TestOnlyWhoCouldGrantEveryRoleConfiguresSingleSignOn).
func TestAProvidersRolesAreTheOrganizations(t *testing.T) {
	u := newUnit(t)
	acme, owner := u.tenant("owner@acme.example", "Acme")
	provider := func(roles ...any) map[string]any {
		return map[string]any{"type": "oidc", "name": "IdP", "issuer": "https://idp.acme.example", "config": map[string]any{"client_id": "c1"},
			"jit": map[string]any{"enabled": true, "roles": roles}, "redirect_uris": []any{"https://app.example/done"}}
	}
	path := "/orgs/" + acme + "/sso/providers"
	if code, body := u.call(http.MethodPost, path, owner, provider("no-such-role")); code != 422 {
		t.Fatalf("a role the organization does not have: %d %v", code, body)
	}
	code, created := u.call(http.MethodPost, path, owner, provider("member"))
	id, _ := created["id"].(string)
	if code != 201 || id == "" {
		t.Fatalf("a role of the organization: %d %v", code, created)
	}
	if code, body := u.call(http.MethodPatch, path+"/"+id, owner, map[string]any{"jit": map[string]any{"enabled": true, "roles": []any{"no-such-role"}}}); code != 422 {
		t.Fatalf("an update naming a role the organization does not have: %d %v", code, body)
	}
	if code, body := u.call(http.MethodPatch, path+"/"+id, owner, map[string]any{"jit": map[string]any{"enabled": true, "roles": []any{"owner"}}}); code != 200 {
		t.Fatalf("the owner hands out what the owner holds: %d %v", code, body)
	}
}

// A claim nobody verified reserves nothing: the domain's owner claims it and verifies, whoever
// claimed it first; a verified domain stays its organization's.
func TestAnUnverifiedDomainClaimReservesNothing(t *testing.T) {
	verifier := &fakeVerifier{}
	u := &unit{t: t, ctx: context.Background(), trail: audit.New(audit.Config{}), oidc: &fakeOIDC{}, saml: &fakeSAML{},
		client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}}
	u.p = sso.New(sso.Config{BaseURL: base, OIDC: u.oidc, SAML: u.saml, Domains: verifier})
	u.srv = polaristest.New(t, polaristest.WithPlugins(u.trail, admin.New(admin.Config{}), u.p))

	squatter, asSquatter := u.tenant("mallory@evil.example", "Evil")
	globex, asGlobex := u.tenant("it@globex.example", "Globex")
	claim := func(org, access string) (int, map[string]any) {
		prov := u.oidcProvider(org)
		return u.call(http.MethodPost, "/orgs/"+org+"/sso/domains", access, map[string]any{"domain": "globex.example", "provider_id": prov.ID})
	}
	if code, body := claim(squatter, asSquatter); code != 201 {
		t.Fatalf("the first claim: %d %v", code, body)
	}
	code, mine := claim(globex, asGlobex)
	if code != 201 {
		t.Fatalf("an unverified claim elsewhere blocked the domain's owner: %d %v", code, mine)
	}
	if code, body := claim(globex, asGlobex); code != 409 {
		t.Fatalf("the organization's own claim, twice: %d %v", code, body)
	}
	instructions, _ := mine["verification"].(map[string]any)

	// Displaced before it could publish the token, the owner claims again and reads the same one.
	if code, _ := claim(squatter, asSquatter); code != 201 {
		t.Fatalf("the squatter claims again: %d", code)
	}
	code, mine = claim(globex, asGlobex)
	if again, _ := mine["verification"].(map[string]any); code != 201 || again["token"] == "" || again["token"] != instructions["token"] {
		t.Fatalf("an organization's token for a domain is stable: %d %v, was %v", code, again, instructions)
	}
	id, _ := mine["id"].(string)

	verifier.allow("globex.example")
	if code, body := u.call(http.MethodPost, "/orgs/"+globex+"/sso/domains/"+id+"/verify", asGlobex, nil); code != 200 || body["verified"] != true {
		t.Fatalf("verify: %d %v", code, body)
	}
	if code, body := claim(squatter, asSquatter); code != 409 {
		t.Fatalf("a verified domain was claimed again: %d %v", code, body)
	}
	if verified, err := u.p.DomainVerified(u.ctx, globex, "globex.example"); err != nil || !verified {
		t.Fatalf("the domain is its owner's: %v %v", verified, err)
	}
}

// A logout at the identity provider is for the organization's members: to anyone else its providers do
// not exist, and nothing of theirs ends.
func TestOnlyAMemberLogsOutThroughAnOrganization(t *testing.T) {
	u := newUnit(t)
	acme := u.organization("owner@acme.example")
	u.oidcProvider(acme)
	_, outsider := u.account("outsider@example.com")
	if code, body := u.call(http.MethodPost, "/sso/logout", outsider, map[string]any{"organization_id": acme}); code != 404 {
		t.Fatalf("an outsider: %d %v", code, body)
	}
	if code, body := u.call(http.MethodGet, "/auth/sessions", outsider, nil); code != 200 {
		t.Fatalf("the outsider's own sessions: %d %v", code, body)
	}
}
