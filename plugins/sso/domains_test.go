package sso_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/sso"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/token"
)

// slowVerifier proves every domain, running during while it looks one up.
type slowVerifier struct{ during func() }

func (v *slowVerifier) Verify(context.Context, string, string) string {
	if f := v.during; f != nil {
		v.during = nil
		f()
	}
	return "dns"
}

// A verification is what its answer says: what happens to the claim while its domain is looked up
// neither loses the proof nor makes it one.
func TestAVerifiedDomainIsItsProversWhateverWasClaimedMeanwhile(t *testing.T) {
	setup := func(t *testing.T) (u *unit, v *slowVerifier, owner, asOwner, other, asOther string, claim func(org, access string) (int, string)) {
		v = &slowVerifier{}
		u = &unit{t: t, ctx: context.Background(), trail: audit.New(audit.Config{}), oidc: &fakeOIDC{}, saml: &fakeSAML{},
			client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}}
		u.p = sso.New(sso.Config{BaseURL: base, OIDC: u.oidc, SAML: u.saml, Domains: v})
		u.srv = polaristest.New(t, polaristest.WithPlugins(u.trail, admin.New(admin.Config{}), u.p))
		owner, asOwner = u.tenant("it@globex.example", "Globex")
		other, asOther = u.tenant("other@elsewhere.example", "Other")
		claim = func(org, access string) (int, string) {
			code, body := u.call(http.MethodPost, "/orgs/"+org+"/sso/domains", access,
				map[string]any{"domain": "globex.example", "provider_id": u.oidcProvider(org).ID})
			id, _ := body["id"].(string)
			return code, id
		}
		return u, v, owner, asOwner, other, asOther, claim
	}
	verified := func(t *testing.T, u *unit, org string, want bool) {
		t.Helper()
		if got, err := u.p.DomainVerified(u.ctx, org, "globex.example"); err != nil || got != want {
			t.Fatalf("verified for %s: %v %v, want %v", org, got, err, want)
		}
	}

	t.Run("another organization claims it", func(t *testing.T) {
		u, v, owner, asOwner, other, asOther, claim := setup(t)
		_, id := claim(owner, asOwner)
		v.during = func() {
			if code, _ := claim(other, asOther); code != 201 {
				t.Errorf("the other claim: %d", code)
			}
		}
		code, body := u.call(http.MethodPost, "/orgs/"+owner+"/sso/domains/"+id+"/verify", asOwner, nil)
		if code != 200 || body["verified"] != true {
			t.Fatalf("verify: %d %v", code, body)
		}
		verified(t, u, owner, true)
		verified(t, u, other, false)
		if _, listed := u.call(http.MethodGet, "/orgs/"+other+"/sso/domains", asOther, nil); len(listed["data"].([]any)) != 0 {
			t.Fatalf("the replaced claim stays: %v", listed)
		}
		// What the answer names exists.
		answered, _ := body["id"].(string)
		if code, body := u.call(http.MethodPost, "/orgs/"+owner+"/sso/domains/"+answered+"/verify", asOwner, nil); code != 200 {
			t.Fatalf("the answered domain: %d %v", code, body)
		}
	})
	t.Run("another organization claims and verifies it", func(t *testing.T) {
		u, v, owner, asOwner, other, asOther, claim := setup(t)
		_, id := claim(owner, asOwner)
		v.during = func() {
			_, theirs := claim(other, asOther)
			if code, body := u.call(http.MethodPost, "/orgs/"+other+"/sso/domains/"+theirs+"/verify", asOther, nil); code != 200 {
				t.Errorf("the other verification: %d %v", code, body)
			}
		}
		code, body := u.call(http.MethodPost, "/orgs/"+owner+"/sso/domains/"+id+"/verify", asOwner, nil)
		if code != 409 || body["error"] != "sso_conflict" {
			t.Fatalf("verify: %d %v, want 409", code, body)
		}
		verified(t, u, owner, false)
		verified(t, u, other, true)
	})
	t.Run("its provider is deleted", func(t *testing.T) {
		u, v, owner, asOwner, _, _, claim := setup(t)
		_, id := claim(owner, asOwner)
		v.during = func() {
			list, err := u.p.Providers().ForOrganization(u.ctx, owner)
			if err != nil || len(list) != 1 {
				t.Errorf("providers %v %v", list, err)
			}
			if code, body := u.call(http.MethodDelete, "/orgs/"+owner+"/sso/providers/"+list[0].ID, asOwner, nil); code != 200 {
				t.Errorf("delete: %d %v", code, body)
			}
		}
		if code, body := u.call(http.MethodPost, "/orgs/"+owner+"/sso/domains/"+id+"/verify", asOwner, nil); code != 404 {
			t.Fatalf("verify: %d %v, want 404", code, body)
		}
		verified(t, u, owner, false)
	})
}

// A name the provider sends is stored as every other display name is.
func TestAProvidersDisplayNameIsTrimmedAndBounded(t *testing.T) {
	u := newUnit(t)
	prov := u.oidcProvider(u.organization("owner@acme.example"))
	for email, c := range map[string]struct{ name, want string }{
		"a@elsewhere.example": {"  Ada Lovelace\n", "Ada Lovelace"},
		"b@elsewhere.example": {strings.Repeat("é", 500), strings.Repeat("é", 120)},
		"c@elsewhere.example": {" \t", ""},
	} {
		u.oidc.name = c.name
		if _, err := u.ssoSession(prov, email); err != nil {
			t.Fatal(err)
		}
		got, err := u.srv.Graph().Repos().Users.ByEmail(u.ctx, email)
		if err != nil || (got.DisplayName == nil) != (c.want == "") || got.DisplayName != nil && *got.DisplayName != c.want {
			t.Errorf("%q: %v %v", c.name, got.DisplayName, err)
		}
	}
}
