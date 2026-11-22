package sso

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/store"
)

func TestALimitIsADecimalInteger(t *testing.T) {
	for _, v := range []any{"0", "x", 3.5, "-1", " 7 ", "7 ", "2.9", "1e2", "+3", "0x10", json.Number("2.5"), json.Number("1e2"), true,
		"99999999999999999999"} {
		if _, ok := positiveInt(v, DefaultLimit); ok {
			t.Fatalf("positiveInt(%#v) accepted", v)
		}
	}
}

func TestProviderInputTakesJSONObjectsAndListsOnly(t *testing.T) {
	base := func(extra map[string]any) map[string]any {
		body := map[string]any{"type": "oidc", "name": "x", "issuer": "https://idp", "config": map[string]any{"client_id": "c"},
			"redirect_uris": []any{"https://app.example/done"}}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	for name, c := range map[string]struct {
		extra map[string]any
		want  string
	}{
		"config as a list":           {map[string]any{"config": []any{}}, "config must be an object."},
		"config as a string":         {map[string]any{"config": "x"}, "config must be an object."},
		"attributes as a list":       {map[string]any{"attributes": []any{}}, "attributes must map field names to claim or attribute names."},
		"jit as a list":              {map[string]any{"jit": []any{}}, "jit must be an object."},
		"jit.enabled as a string":    {map[string]any{"jit": map[string]any{"enabled": "yes"}}, "jit.enabled must be a boolean."},
		"jit.roles as a string":      {map[string]any{"jit": map[string]any{"roles": "member"}}, "jit.roles must be a list of role slugs."},
		"redirect_uris as an object": {map[string]any{"redirect_uris": map[string]any{"0": "https://app.example/done"}}, "redirect_uris must be a list of http(s) URLs."},
	} {
		if _, errs := providerInput(base(c.extra), nil); !slices.Contains(errs, c.want) {
			t.Fatalf("%s: %v", name, errs)
		}
	}
	if p, errs := providerInput(base(map[string]any{"attributes": map[string]any{}, "jit": map[string]any{}}), nil); errs != nil || len(p.Attributes) != 0 || p.JIT.Enabled {
		t.Fatalf("empty objects: %+v %v", p, errs)
	}
}

func TestProviderRowsAreStandardJSONAndOldRowsStillRead(t *testing.T) {
	p := Provider{Type: TypeOIDC, Name: "Ünï", Config: map[string]any{"client_id": "c/é", "scopes": "openid"}, Attributes: map[string]string{},
		RedirectURIs: []string{"https://app.example/done"}}
	row, err := providerRow(p)
	if err != nil {
		t.Fatal(err)
	}
	if row["config"] != `{"client_id":"c/é","scopes":"openid"}` || row["attributes"] != `{}` || row["jit"] != `{"enabled":false,"roles":[]}` ||
		row["redirect_uris"] != `["https://app.example/done"]` {
		t.Fatalf("row %v", row)
	}
	// Rows written by earlier releases: slashes escaped, non-ASCII as \u escapes, an empty object as [].
	old := store.Row{"id": "p1", "type": TypeSAML, "name": "Old", "issuer": "https://idp", "enabled": true,
		"config":        `{"sso_url":"https:\/\/idp.example\/sso","certificate":"MIIC","idp_initiated":true,"x":"Ünï 😀"}`,
		"attributes":    `[]`,
		"jit":           `{"enabled":true,"roles":["member"]}`,
		"redirect_uris": `["https:\/\/app.example\/done"]`,
		"created_at":    "2026-11-20 18:32:59", "updated_at": "2026-11-20 18:32:59"}
	got := hydrateProvider(old)
	if got.Setting("sso_url") != "https://idp.example/sso" || !got.Flag("idp_initiated") || got.Setting("x") != "Ünï 😀" ||
		len(got.Attributes) != 0 || !got.JIT.Enabled || !slices.Equal(got.JIT.Roles, []string{"member"}) ||
		!slices.Equal(got.RedirectURIs, []string{"https://app.example/done"}) {
		t.Fatalf("an old row %+v", got)
	}
}

func TestTimestampsAreRFC3339InUTC(t *testing.T) {
	at := time.Date(2026, 11, 20, 18, 32, 59, 0, time.FixedZone("x", 3600))
	m := Provider{CreatedAt: at, UpdatedAt: at}.Map()
	d := Domain{VerifiedAt: &at, CreatedAt: at}.Map()
	for _, v := range []any{m["created_at"], m["updated_at"], d["verified_at"], d["created_at"]} {
		if v != "2026-11-20T17:32:59Z" {
			t.Fatalf("timestamp %v", v)
		}
	}
}

func TestProviderInputIsValidated(t *testing.T) {
	if _, errs := providerInput(map[string]any{"type": "ldap"}, nil); !slices.Equal(errs, []string{"type must be saml or oidc."}) {
		t.Fatalf("type: %v", errs)
	}
	_, errs := providerInput(map[string]any{"type": "saml", "name": "", "issuer": "", "config": map[string]any{"sso_url": "nope", "idp_initiated": "yes"},
		"redirect_uris": []any{"ftp://x"}, "enabled": "no"}, nil)
	if len(errs) != 7 {
		t.Fatalf("seven errors: %v", errs)
	}
	if _, errs := providerInput(map[string]any{"type": "oidc", "name": "x", "issuer": "https://idp", "config": map[string]any{}, "redirect_uris": []any{}}, nil); !slices.Equal(errs,
		[]string{"config.client_id is required.", "redirect_uris needs at least one URL the sign-in may end on."}) {
		t.Fatalf("oidc: %v", errs)
	}
	_, errs = providerInput(map[string]any{"type": "oidc", "name": strings.Repeat("é", 121), "issuer": "https://idp",
		"config":     map[string]any{"client_id": 5, "client_secret": true, "scopes": []any{}, "issuer": 1},
		"attributes": map[string]any{"email": 3}, "jit": map[string]any{"roles": []any{"Not A Slug"}}, "redirect_uris": map[string]any{"a": "https://x.example"}}, nil)
	for _, want := range []string{"name must be 1 to 120 characters.", "config.client_id is required.", "config.client_secret must be a string.",
		"config.issuer must be a string.", "attributes must map field names to claim or attribute names.", "jit.roles must be a list of role slugs."} {
		if !slices.Contains(errs, want) {
			t.Fatalf("%q missing from %v", want, errs)
		}
	}
	if _, errs := providerInput(map[string]any{"type": "oidc", "name": "x", "issuer": "i", "config": map[string]any{"client_id": "c"},
		"attributes": []any{"x"}, "redirect_uris": []any{"https://x.example"}}, nil); !slices.Contains(errs, "attributes must map field names to claim or attribute names.") {
		t.Fatalf("a list of attributes: %v", errs)
	}
	p, errs := providerInput(map[string]any{"type": "oidc", "name": " Okta ", "issuer": "https://idp", "config": map[string]any{"client_id": "c", "unknown": "dropped", "scopes": ""},
		"jit": map[string]any{"enabled": true, "roles": []any{"member", "ops"}}, "redirect_uris": []any{"https://app.example/done"}, "attributes": map[string]any{"email": "mail"}}, nil)
	if errs != nil || p.Name != "Okta" || len(p.Config) != 1 || p.Config["client_id"] != "c" || !p.JIT.Enabled || !slices.Equal(p.JIT.Roles, []string{"member", "ops"}) ||
		p.Attributes["email"] != "mail" || !p.Enabled {
		t.Fatalf("input %+v %v", p, errs)
	}
	existing := Provider{Type: TypeOIDC, Name: "Okta 3", Issuer: "https://idp", Config: map[string]any{"client_id": "c", secretKey: "sealed"},
		Attributes: map[string]string{"email": "mail"}, JIT: JIT{Enabled: true, Roles: []string{"member"}}, RedirectURIs: []string{"https://app.example/done"}, Enabled: true}
	patched, errs := providerInput(map[string]any{"enabled": false, "type": "saml"}, &existing)
	if errs != nil || patched.Type != TypeOIDC || patched.Name != "Okta 3" || patched.Enabled || !slices.Equal(patched.RedirectURIs, existing.RedirectURIs) ||
		patched.Attributes["email"] != "mail" || !patched.JIT.Enabled || patched.Config[secretKey] != nil || patched.Config["client_id"] != "c" {
		t.Fatalf("patched %+v %v (the stored secret is never resealed)", patched, errs)
	}
	for raw, want := range map[string]bool{"https://idp.example/sso": true, "http://idp.example:8080/sso?x=1": true, "nope": false,
		"javascript:alert(1)": false, "https://": false, "https://a b": false, "https://idp.example/a b": false, "urn:x": false,
		"1http://x": false, "https://idp.example/\u00e9": false, "https://idp.example/\x00": false, "HTTPS://IDP.EXAMPLE": true} {
		if validURL(raw) != want {
			t.Fatalf("validURL(%q) != %v", raw, want)
		}
	}
}

func TestTheProblemsAndTheirTypes(t *testing.T) {
	for reason, status := range map[string]int{ReasonProviderNotFound: 404, ReasonProviderDisabled: 403, ReasonInvalidInput: 422, ReasonUserUnknown: 403,
		ReasonAccountDisabled: 403, ReasonMembershipSuspended: 403, ReasonCodeInvalid: 422, ReasonAssertionInvalid: 403, "other": 403} {
		r := problem(refuse(reason, "d"))
		body := r.Body.(map[string]any)
		if r.Status != status || !r.Problem || !strings.HasPrefix(body["type"].(string), "https://polaris.univeros.io/problems/sso/") {
			t.Fatalf("%s: %+v", reason, r)
		}
	}
	if problem(refuse(ReasonAssertionInvalid, "secret reason")).Body.(map[string]any)["detail"] != "The sign-in could not be completed." {
		t.Fatal("a rejection's reason leaks")
	}
	if e := rejected(errors.New("library")); e.Reason != ReasonAssertionInvalid || e.Detail != "library" || e.Error() != "sso: assertion_invalid: library" {
		t.Fatalf("rejected %v", e)
	}
	if (Event{Name: AuditSignedIn}).EventName() != AuditSignedIn || (errUnknownKey{"k"}).Error() != "k" {
		t.Fatal("names")
	}
}

func TestHelpers(t *testing.T) {
	for v, want := range map[any]int{nil: DefaultLimit, "": DefaultLimit, "5": 5, json.Number("3"): 3, "500": MaxLimit} {
		if got, ok := positiveInt(v, DefaultLimit); !ok || got != want {
			t.Fatalf("positiveInt(%v) = %d", v, got)
		}
	}
	if !audienceHas([]any{"x", "c"}, "c") || audienceHas(5, "c") || !audienceHas("c", "c") {
		t.Fatal("audienceHas")
	}
	if nonNil(nil) == nil || optional("") != nil || *optional("x") != "x" || nullable("") != nil {
		t.Fatal("nil helpers")
	}
	if (Provider{Attributes: map[string]string{}}).Attribute("email") != "email" {
		t.Fatal("the field's own name by default")
	}
}

func TestTheSPKeyPairIsParsedAtStartup(t *testing.T) {
	key, cert := newKeyPair(t, "app.example")
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pkcs8 := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	for name, k := range map[string]string{"pkcs1": pkcs1, "pkcs8": pkcs8} {
		sp, err := spOf("https://app.example", certPEM, k)
		if err != nil || sp.Key == nil || sp.Certificate == nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	other, _ := newKeyPair(t, "other.example")
	otherPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(other)}))
	garbage := string(pem.EncodeToMemory(&pem.Block{Type: "X", Bytes: []byte("x")}))
	for name, pair := range map[string][2]string{"another key": {certPEM, otherPEM}, "half": {certPEM, ""}, "bad cert": {garbage, pkcs1}, "bad key": {certPEM, garbage}} {
		if _, err := spOf("https://app.example", pair[0], pair[1]); err == nil || !strings.Contains(err.Error(), "SPPrivateKey") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if sp, err := spOf("https://app.example", "", ""); err != nil || sp.Key != nil {
		t.Fatal("no key pair")
	}
}

// FuzzSAMLResponse: whatever arrives at the ACS, the parser never panics and never accepts a
// response the provider's key did not sign.
func FuzzSAMLResponse(f *testing.F) {
	i := idp(f)
	sp := SP{BaseURL: testBase}
	prov := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "certificate": i.certificateBody()}, idpEntityID, nil)
	f.Add([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/></samlp:Response>`))
	f.Add([]byte("<<<"))
	f.Add([]byte(`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x>&a;</x>`))
	valid := i.response(f, sp.EntityID(prov.ID), sp.ACSURL(prov.ID), "ada@example.com", responseOptions{})
	raw, _ := base64Decode(valid)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, xml []byte) {
		id, err := DefaultSAML{}.Consume(prov, sp, base64Encode(xml), "")
		if err == nil && (string(xml) != string(raw) || id.Email != "ada@example.com") {
			t.Fatalf("accepted %q as %+v", xml, id)
		}
	})
}

// FuzzMetadata: whatever an organization names its provider's settings, the SP metadata is
// well-formed XML naming this SP, and generating it never panics.
func FuzzMetadata(f *testing.F) {
	f.Add("p1", "https://idp.example/metadata", "https://idp.example/sso", "MIIC")
	f.Add("<x>", "\"'&", "javascript:alert(1)", "-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----")
	f.Fuzz(func(t *testing.T, id, issuer, ssoURL, cert string) {
		prov := testProvider(TypeSAML, map[string]any{"sso_url": ssoURL, "certificate": cert, "slo_url": ssoURL}, issuer, nil)
		prov.ID = id
		out, err := DefaultSAML{}.Metadata(prov, SP{BaseURL: testBase})
		if err != nil {
			return // an id that is no URL path
		}
		if !wellFormed(out) {
			t.Fatalf("malformed metadata for %q: %s", id, out)
		}
	})
}

// FuzzLogoutRequest: an IdP's LogoutRequest is accepted only when signed.
func FuzzLogoutRequest(f *testing.F) {
	i := idp(f)
	sp := SP{BaseURL: testBase}
	prov := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "slo_url": idpSLOURL, "certificate": i.certificateBody()}, idpEntityID, nil)
	f.Add("SAMLRequest=x&SigAlg=y&Signature=z", "x", true)
	f.Add("", base64Encode([]byte(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="a"/>`)), false)
	f.Fuzz(func(t *testing.T, query, request string, redirect bool) {
		if _, err := (DefaultSAML{}).ConsumeLogoutRequest(prov, sp, LogoutMessage{SAMLRequest: request, RawQuery: query, Redirect: redirect}); err == nil {
			t.Fatalf("accepted %q %q", query, request)
		}
	})
}
