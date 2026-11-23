package sso_test

// Decision 78: who may configure an organization's identity providers and domains, what address an
// assertion may name, and a sign-in that loses the account while it runs.

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// Every route that changes an organization's providers or domains takes the authority to grant every
// role of the organization; org.update alone reads and tests.
func TestOnlyWhoCouldGrantEveryRoleConfiguresSingleSignOn(t *testing.T) {
	verifier := &fakeVerifier{}
	u := &unit{t: t, ctx: context.Background(), trail: audit.New(audit.Config{}), oidc: &fakeOIDC{}, saml: &fakeSAML{},
		client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}}
	u.p = sso.New(sso.Config{BaseURL: base, OIDC: u.oidc, SAML: u.saml, Domains: verifier})
	u.srv = polaristest.New(t, polaristest.WithPlugins(u.trail, admin.New(admin.Config{}), u.p))
	verifier.allow("acme.example")
	verifier.allow("other.example")

	acme, owner := u.tenant("owner@acme.example", "Acme")
	adminID, adminAccess := u.account("admin@acme.example")
	u.joinAs(adminID, acme, "admin")
	asAdmin := u.switchTo(adminAccess, acme)

	providers, domains := "/orgs/"+acme+"/sso/providers", "/orgs/"+acme+"/sso/domains"
	provider := map[string]any{"type": "oidc", "name": "IdP", "issuer": "https://idp.acme.example", "config": map[string]any{"client_id": "c1"},
		"redirect_uris": []any{"https://app.example/done"}}
	create := func(path, as string, body map[string]any) string {
		t.Helper()
		code, created := u.call(http.MethodPost, path, as, body)
		id, _ := created["id"].(string)
		if code != 201 || id == "" {
			t.Fatalf("POST %s as the owner: %d %v", path, code, created)
		}
		return id
	}
	providerID := create(providers, owner, provider)
	domainID := create(domains, owner, map[string]any{"domain": "acme.example", "provider_id": providerID})

	writes := []struct {
		method, path string
		body         map[string]any
		want         int // the owner's answer
	}{
		{http.MethodPost, providers, provider, 201},
		{http.MethodPatch, providers + "/" + providerID, map[string]any{"issuer": "https://idp2.acme.example"}, 200},
		{http.MethodPatch, providers + "/" + providerID, map[string]any{"enabled": true}, 200},
		{http.MethodPost, domains, map[string]any{"domain": "other.example", "provider_id": providerID}, 201},
		{http.MethodPost, domains + "/" + domainID + "/verify", nil, 200},
		{http.MethodDelete, domains + "/" + domainID, nil, 200},
		{http.MethodDelete, providers + "/" + providerID, nil, 200},
	}
	for _, w := range writes {
		code, body := u.call(w.method, w.path, asAdmin, w.body)
		if code != 403 || body["error"] != "sso_forbidden" {
			t.Errorf("%s %s as an administrator: %d %v, want 403 sso_forbidden", w.method, w.path, code, body)
		}
	}
	// The refusal comes before anything is read or validated: it tells a caller nothing else.
	for _, path := range []string{providers + "/nope", domains + "/nope"} {
		if code, _ := u.call(http.MethodDelete, path, asAdmin, nil); code != 403 {
			t.Errorf("DELETE %s as an administrator: %d, want 403", path, code)
		}
	}
	if code, body := u.call(http.MethodPost, providers, asAdmin, map[string]any{"type": "ldap"}); code != 403 {
		t.Errorf("an invalid provider as an administrator: %d %v, want 403", code, body)
	}
	for _, path := range []string{providers, providers + "/" + providerID, domains} {
		if code, body := u.call(http.MethodGet, path, asAdmin, nil); code != 200 {
			t.Errorf("GET %s as an administrator: %d %v", path, code, body)
		}
	}
	if code, body := u.call(http.MethodPost, providers+"/"+providerID+"/test", asAdmin, nil); code != 200 {
		t.Errorf("testing a provider as an administrator: %d %v", code, body)
	}
	stored, _, err := u.p.Providers().Find(u.ctx, providerID)
	if err != nil || stored.Issuer != "https://idp.acme.example" {
		t.Fatalf("the provider changed: %+v %v", stored, err)
	}
	for _, w := range writes {
		if code, body := u.call(w.method, w.path, owner, w.body); code != w.want {
			t.Errorf("%s %s as the owner: %d %v, want %d", w.method, w.path, code, body, w.want)
		}
	}
}

// A provider creates accounts for email addresses only: what it sends becomes an account's address,
// so it passes the rule every other account's address does. An account that has another one already
// (an earlier release's) keeps signing in.
func TestAnAssertionNamesAnEmailAddress(t *testing.T) {
	u := newUnit(t)
	prov := u.oidcProvider(u.organization("owner@acme.example"))
	for _, email := range []string{"", "ada", "@acme.example", "ada@", "ada@acme.example\r\nBcc: eve@evil.example", "ada @acme.example",
		"Ada <ada@acme.example>", "ada@acme.example,eve@evil.example", "аda@acme.example"} {
		_, err := u.ssoSession(prov, email)
		refused(t, err, sso.ReasonAssertionInvalid, "the address "+email)
	}
	if n, err := u.srv.Graph().Repos().Users.Count(u.ctx, nil); err != nil || n != 1 {
		t.Fatalf("accounts: %d %v, want the owner only", n, err)
	}
	if _, err := u.ssoSession(prov, " Ada@Acme.Example "); err != nil {
		t.Fatalf("a normalized address: %v", err)
	}
	ada, err := u.srv.Graph().Repos().Users.ByEmail(u.ctx, "ada@acme.example")
	if err != nil {
		t.Fatal(err)
	}
	intranet := ada
	intranet.Email = "ada@intranet"
	if err := u.srv.Graph().Repos().Users.Update(u.ctx, ada, intranet); err != nil {
		t.Fatal(err)
	}
	if _, err := u.ssoSession(prov, "ada@intranet"); err != nil {
		t.Fatalf("an existing account: %v", err)
	}
}

// A sign-in that loses the account, or the membership, while it runs opens no session.
func TestASignInThatLosesTheAccountOpensNoSession(t *testing.T) {
	type race struct {
		do   func(u *unit, userID string) error
		want string
	}
	for name, r := range map[string]race{
		"the owner proves the mailbox": {func(u *unit, userID string) error {
			_, first, err := u.srv.Graph().Identity().ProveEmail(u.ctx, userID, false)
			if !first {
				t.Error("not the first proof")
			}
			return err
		}, sso.ReasonUserUnknown},
		"an operator disables the account": {func(u *unit, userID string) error {
			return u.srv.Graph().Identity().DisableUser(u.ctx, "operator", userID)
		}, sso.ReasonAccountDisabled},
		"the membership is suspended": {func(u *unit, userID string) error {
			m, err := u.srv.Graph().Repos().Memberships.ListByUser(u.ctx, userID)
			if err != nil || len(m) != 1 {
				return fmt.Errorf("memberships %v: %w", m, err)
			}
			return u.srv.Graph().Orgs().SetMemberStatus(u.ctx, "operator", m[0].OrganizationID, userID, model.MembershipStatusSuspended)
		}, sso.ReasonMembershipSuspended},
		"the membership ends": {func(u *unit, userID string) error {
			m, err := u.srv.Graph().Repos().Memberships.ListByUser(u.ctx, userID)
			if err != nil || len(m) != 1 {
				return fmt.Errorf("memberships %v: %w", m, err)
			}
			if _, err := u.srv.Graph().DB().Delete(u.ctx, "auth_membership_roles", store.Criteria{"membership_id": m[0].ID}); err != nil {
				return err
			}
			return u.srv.Graph().Repos().Memberships.Delete(u.ctx, m[0])
		}, sso.ReasonUserUnknown},
	} {
		t.Run(name, func(t *testing.T) {
			u := &unit{t: t, ctx: context.Background(), trail: audit.New(audit.Config{}), oidc: &fakeOIDC{name: "Ada"}, saml: &fakeSAML{},
				client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}}
			u.p = sso.New(sso.Config{BaseURL: base, OIDC: u.oidc, SAML: u.saml, Domains: &fakeVerifier{}})
			var userID string
			// MemberJoined is dispatched between the provisioning's transaction and the session's.
			between := func(_ context.Context, e event.Event) {
				joined, ok := e.(event.MemberJoined)
				if !ok {
					return
				}
				userID = joined.UserID
				if err := r.do(u, userID); err != nil {
					t.Error(err)
				}
			}
			u.srv = polaristest.New(t, polaristest.WithPlugins(u.trail, admin.New(admin.Config{}), u.p), polaristest.WithConfig(func(c *polaris.Config) {
				c.Listeners = append(c.Listeners, between)
			}))
			prov := u.oidcProvider(u.organization("owner@acme.example"))
			_, err := u.ssoSession(prov, "ceo@globex.example")
			refused(t, err, r.want, name)
			if userID == "" {
				t.Fatal("the race did not happen")
			}
			sessions, err := services.Of(u.srv.Graph()).Sessions.List(u.ctx, userID, "")
			if err != nil || len(sessions) != 0 {
				t.Fatalf("sessions: %v %v", sessions, err)
			}
		})
	}
}

// A registration's confirmation ends a provider's hold like any other first proof.
func TestAConfirmedRegistrationEndsAProvidersHold(t *testing.T) {
	u := newUnit(t)
	g := u.srv.Graph()
	prov := u.oidcProvider(u.organization("owner@acme.example"))
	if _, err := u.ssoSession(prov, "ceo@globex.example"); err != nil {
		t.Fatal(err)
	}
	ceo, err := g.Repos().Users.ByEmail(u.ctx, "ceo@globex.example")
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Identity().SetPassword(u.ctx, ceo.ID, "correct horse battery staple"); err != nil { // an operator's
		t.Fatal(err)
	}
	if _, first, err := g.Identity().ProveEmail(u.ctx, ceo.ID, true); err != nil || !first {
		t.Fatal(first, err)
	}
	_, err = u.ssoSession(prov, "ceo@globex.example")
	refused(t, err, sso.ReasonUserUnknown, "an account whose owner confirmed it")
}
