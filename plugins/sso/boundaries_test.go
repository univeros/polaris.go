package sso_test

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
	"github.com/univeros/polaris.go/plugins/scim"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// call is one JSON request to the server: the status and the decoded body.
func (u *unit) call(method, path, bearer string, body map[string]any) (int, map[string]any) {
	u.t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	u.srv.Handler().ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if d, ok := out["data"].(map[string]any); ok {
		out = d
	}
	return w.Code, out
}

// account registers, verifies and signs in an account over HTTP: its id and access token.
func (u *unit) account(email string) (string, string) {
	u.t.Helper()
	const pw = "correct horse battery staple"
	if code, body := u.call(http.MethodPost, "/auth/register", "", map[string]any{"email": email, "password": pw}); code >= 300 {
		u.t.Fatalf("register %s: %d %v", email, code, body)
	}
	var reg event.UserRegistered
	for _, e := range u.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok && r.Email == email {
			reg = r
		}
	}
	u.call(http.MethodPost, "/auth/email/verify", "", map[string]any{"token": reg.VerificationToken})
	code, body := u.call(http.MethodPost, "/auth/login", "", map[string]any{"email": email, "password": pw})
	access, _ := body["access_token"].(string)
	if code != 200 || access == "" {
		u.t.Fatalf("login %s: %d %v", email, code, body)
	}
	return reg.UserID, access
}

// join makes userID an active member of the organization, as an accepted invitation does.
func (u *unit) join(userID, organizationID string) {
	u.t.Helper()
	g := u.srv.Graph()
	now := time.Now().UTC().Truncate(time.Second)
	m := model.Membership{ID: repository.NewID(), UserID: userID, OrganizationID: organizationID, Status: model.MembershipStatusActive,
		JoinedAt: &now, CreatedAt: now, UpdatedAt: now}
	if err := g.Repos().Memberships.Insert(u.ctx, m); err != nil {
		u.t.Fatal(err)
	}
	orgID := organizationID
	role, err := g.Repos().Roles.ByOrganizationAndSlug(u.ctx, &orgID, "member")
	if err != nil {
		u.t.Fatal(err)
	}
	if err := g.Repos().MembershipRoles.Insert(u.ctx, model.MembershipRole{MembershipID: m.ID, RoleID: role.ID}); err != nil {
		u.t.Fatal(err)
	}
}

// ssoSession signs email in through the organization's OIDC provider: the exchanged session, or
// the refusal.
func (u *unit) ssoSession(prov sso.Provider, email string) (map[string]any, error) {
	u.t.Helper()
	u.oidc.email = email
	if _, err := u.p.Start(u.ctx, "", prov.ID, ""); err != nil {
		u.t.Fatal(err)
	}
	to, err := u.p.CompleteOIDC(u.ctx, prov.ID, "good", u.oidc.state(), "", u.client)
	if err != nil {
		return nil, err
	}
	loc, _ := url.Parse(to)
	return u.p.Exchange(u.ctx, loc.Query().Get("sso_code"))
}

func (u *unit) oidcProvider(organizationID string) sso.Provider {
	return u.provider(sso.Provider{OrganizationID: organizationID, Type: sso.TypeOIDC, Name: "IdP", Issuer: "https://idp.acme.example",
		Config: map[string]any{"client_id": "c1"}, JIT: sso.JIT{Enabled: true, Roles: []string{"member"}},
		RedirectURIs: []string{"https://app.example/done"}, Enabled: true})
}

// An organization's IdP asserts whatever its owner wants. Membership is not consent to that: a
// person who joined an organization did not hand it their account.
func TestAMembershipDoesNotLetTheOrganizationsIdPSignTheMemberIn(t *testing.T) {
	u := newUnit(t)
	acme := u.organization("owner@acme.example")
	prov := u.oidcProvider(acme)
	victimID, _ := u.account("ceo@globex.example")
	u.join(victimID, acme)

	_, err := u.ssoSession(prov, "ceo@globex.example")
	refused(t, err, sso.ReasonUserUnknown, "a member whose email domain the organization has not verified")

	// The organization proves the domain: the account's mailbox is the organization's to vouch for.
	d, err := u.p.Domains().Add(u.ctx, acme, prov.ID, "globex.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := u.p.Domains().MarkVerified(u.ctx, d); err != nil {
		t.Fatal(err)
	}
	if _, err := u.ssoSession(prov, "ceo@globex.example"); err != nil {
		t.Fatalf("a verified domain: %v", err)
	}

	// The accounts the provider provisioned stay its own, verified domain or not.
	if _, err := u.ssoSession(prov, "contractor@elsewhere.example"); err != nil {
		t.Fatalf("provisioned just in time: %v", err)
	}
	if _, err := u.ssoSession(prov, "contractor@elsewhere.example"); err != nil {
		t.Fatalf("a provisioned account signs in again: %v", err)
	}
}

// A session an organization's IdP opened is that organization's: it cannot move to another
// organization of the user, nor act on the account itself.
func TestAnSSOSessionStaysInItsOrganization(t *testing.T) {
	u := newUnit(t)
	g := u.srv.Graph()
	acme := u.organization("owner@acme.example")
	prov := u.oidcProvider(acme)
	if _, err := u.ssoSession(prov, "ada@elsewhere.example"); err != nil {
		t.Fatal(err)
	}
	ada, err := g.Repos().Users.ByEmail(u.ctx, "ada@elsewhere.example")
	if err != nil {
		t.Fatal(err)
	}
	// Ada also has an organization of her own, and a password she set by reset.
	own, err := services.Of(g).Orgs.CreateOrganization(u.ctx, "Ada's", "", ada.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Identity().SetPassword(u.ctx, ada.ID, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	// SetPassword ended the sessions: the IdP signs her in again.
	session, err := u.ssoSession(prov, "ada@elsewhere.example")
	if err != nil {
		t.Fatal(err)
	}
	access, _ := session["access_token"].(string)

	refusedRoutes := []struct {
		method, path string
		body         map[string]any
	}{
		{http.MethodPost, "/auth/switch-org", map[string]any{"organization_id": own.ID}},
		{http.MethodPost, "/auth/password/change", map[string]any{"current_password": "correct horse battery staple", "new_password": "an entirely different passphrase"}},
		{http.MethodPost, "/auth/mfa/totp/enroll", map[string]any{}},
		{http.MethodPost, "/auth/mfa/email/enroll", map[string]any{"email": "attacker@evil.example"}},
		{http.MethodPost, "/auth/mfa/step-up/challenge", map[string]any{}},
		{http.MethodPost, "/auth/logout-all", nil},
		{http.MethodPost, "/orgs", map[string]any{"name": "Another"}},
		{http.MethodPatch, "/users/" + ada.ID, map[string]any{"display_name": "Mallory"}},
		{http.MethodDelete, "/users/" + ada.ID, nil},
	}
	attempt := func(access, when string) {
		t.Helper()
		for _, r := range refusedRoutes {
			if code, body := u.call(r.method, r.path, access, r.body); code != http.StatusForbidden {
				t.Errorf("%s: %s %s: %d (%v), want 403", when, r.method, r.path, code, body["error"])
			}
		}
	}
	attempt(access, "the session the IdP opened")
	if code, me := u.call(http.MethodGet, "/auth/me", access, nil); code != 200 {
		t.Fatalf("it still reads who it is: %d %v", code, me)
	}

	// Refreshing keeps the session where it is.
	refresh, _ := session["refresh_token"].(string)
	code, refreshed := u.call(http.MethodPost, "/auth/token/refresh", "", map[string]any{"refresh_token": refresh})
	if code != 200 {
		t.Fatalf("refresh: %d %v", code, refreshed)
	}
	access, _ = refreshed["access_token"].(string)
	attempt(access, "after a refresh")
	tok, err := g.Tokens().Verify(access)
	if err != nil || tok.Organization() != acme {
		t.Fatalf("the refreshed token's organization: %v %v", tok, err)
	}

	if after, err := g.Repos().Users.Get(u.ctx, ada.ID); err != nil || after.Status != model.UserStatusActive ||
		after.DisplayName != nil && *after.DisplayName == "Mallory" {
		t.Fatalf("the account is untouched: %+v %v", after, err)
	}
	if code, body := u.call(http.MethodPost, "/auth/logout", access, nil); code != 200 {
		t.Fatalf("it can end itself: %d %v", code, body)
	}
}

// The platform operator's override is not reachable through a tenant's IdP.
func TestAnSSOSessionCarriesNoSuperadminOverride(t *testing.T) {
	u := newUnit(t)
	g := u.srv.Graph()
	acme := u.organization("owner@acme.example")
	prov := u.oidcProvider(acme)
	session, err := u.ssoSession(prov, "ops@elsewhere.example")
	if err != nil {
		t.Fatal(err)
	}
	ops, _ := g.Repos().Users.ByEmail(u.ctx, "ops@elsewhere.example")
	m, err := g.Repos().Memberships.ByUserAndOrganization(u.ctx, ops.ID, acme)
	if err != nil {
		t.Fatal(err)
	}
	super, err := g.Repos().Roles.ByOrganizationAndSlug(u.ctx, nil, "superadmin")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Repos().MembershipRoles.Insert(u.ctx, model.MembershipRole{MembershipID: m.ID, RoleID: super.ID}); err != nil {
		t.Fatal(err)
	}
	// The account became a superadmin while its session lived: the refreshed token carries no
	// override, and the provider does not sign it in again.
	_, err = u.ssoSession(prov, "ops@elsewhere.example")
	refused(t, err, sso.ReasonUserUnknown, "a superadmin through an organization's provider")
	refresh, _ := session["refresh_token"].(string)
	code, refreshed := u.call(http.MethodPost, "/auth/token/refresh", "", map[string]any{"refresh_token": refresh})
	access, _ := refreshed["access_token"].(string)
	if code != 200 {
		t.Fatalf("refresh: %d", code)
	}
	tok, err := g.Tokens().Verify(access)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range tok.Claim("roles").([]any) {
		if role == "superadmin" {
			t.Fatalf("the token carries the override: %v", tok.Claim("roles"))
		}
	}
	other, err := services.Of(g).Orgs.CreateOrganization(u.ctx, "Other", "", "u-owner")
	if err != nil {
		t.Fatal(err)
	}
	if code, body := u.call(http.MethodGet, "/orgs/"+other.ID+"/members", access, nil); code != http.StatusForbidden {
		t.Fatalf("another organization's members: %d %v", code, body)
	}
}

// An account the organization created another way is the organization's too: one its SCIM
// directory provisioned, and one a host records for a provider that predates the record
// (MarkProvisioned). An IdP logout reaches the same accounts and no other member.
func TestTheAccountsAnOrganizationProvisionedAreItsIdPsToSignIn(t *testing.T) {
	u := &unit{t: t, ctx: context.Background(), trail: audit.New(audit.Config{}), oidc: &fakeOIDC{name: "X"}, saml: &fakeSAML{},
		client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}}
	u.p = sso.New(sso.Config{BaseURL: base, OIDC: u.oidc, SAML: u.saml, Domains: &fakeVerifier{}})
	u.srv = polaristest.New(t, polaristest.WithPlugins(u.trail, admin.New(admin.Config{}), u.p, scim.New(scim.Config{BaseURL: base})))
	g := u.srv.Graph()
	acme := u.organization("owner@acme.example")
	prov := u.oidcProvider(acme)
	prov = u.update(prov, func(n *sso.Provider) { n.JIT = sso.JIT{} })
	created := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	person := func(id, email string) model.User {
		p := model.User{ID: id, Email: email, Status: model.UserStatusActive, EmailVerifiedAt: &created, CreatedAt: created, UpdatedAt: created}
		if err := g.Repos().Users.Insert(u.ctx, p); err != nil {
			t.Fatal(err)
		}
		u.join(id, acme)
		return p
	}
	provenance := func(userID string, at time.Time) {
		if err := g.DB().Insert(u.ctx, scim.TableProvenance, store.Row{"id": repository.NewID(), "organization_id": acme, "user_id": userID,
			"connection_id": "conn-1", "created_at": at}); err != nil {
			t.Fatal(err)
		}
	}

	directory := person("u-directory", "dana@elsewhere.example")
	provenance(directory.ID, created) // the directory created the account
	if _, err := u.ssoSession(prov, directory.Email); err != nil {
		t.Fatalf("an account the organization's directory created: %v", err)
	}
	linked := person("u-linked", "lee@elsewhere.example")
	provenance(linked.ID, created.Add(time.Minute)) // the directory joined an account that existed
	_, err := u.ssoSession(prov, linked.Email)
	refused(t, err, sso.ReasonUserUnknown, "an account the directory only joined")

	legacy := person("u-legacy", "old@elsewhere.example")
	_, err = u.ssoSession(prov, legacy.Email)
	refused(t, err, sso.ReasonUserUnknown, "a member with no record")
	for range 2 { // recording twice is harmless
		if err := u.p.MarkProvisioned(u.ctx, acme, legacy.ID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := u.ssoSession(prov, legacy.Email); err != nil {
		t.Fatalf("an account the host recorded as provisioned: %v", err)
	}

	samlProv := u.provider(sso.Provider{OrganizationID: acme, Type: sso.TypeSAML, Name: "SAML", Issuer: "https://idp",
		Config:       map[string]any{"sso_url": "https://idp/sso", "slo_url": "https://idp/slo", "certificate": "c"},
		RedirectURIs: []string{"https://app.example/done"}, Enabled: true})
	live := func(userID string) int {
		list, err := g.Sessions().List(u.ctx, userID, "")
		if err != nil {
			t.Fatal(err)
		}
		return len(list)
	}
	for _, p := range []model.User{linked, legacy} {
		if _, err := g.Sessions().Issue(u.ctx, token.SessionPrincipal{UserID: p.ID}, u.client); err != nil {
			t.Fatal(err)
		}
		if _, err := u.p.IdPLogout(u.ctx, samlProv.ID, sso.LogoutMessage{SAMLRequest: "logout:" + p.Email}, u.client); err != nil {
			t.Fatal(err)
		}
	}
	if live(linked.ID) != 1 || live(legacy.ID) != 0 {
		t.Fatalf("an IdP logout ends the sessions of the organization's accounts only: member %d, provisioned %d", live(linked.ID), live(legacy.ID))
	}
}
