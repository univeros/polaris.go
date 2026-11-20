package sso

import (
	"encoding/base64"
	"strings"
	"testing"
)

// GO-2026-6909 is reported against every crewjam/saml version with no fix. Both of its findings
// are absent from the version in go.mod (Assertion.Issuer is a value, Subject.NameID is namespace
// qualified); these tests keep it that way across upgrades.
func TestSAMLGO20266909(t *testing.T) {
	i := idp(t)
	sp := SP{BaseURL: testBase}
	prov := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "slo_url": idpSLOURL, "certificate": i.certificateBody()},
		idpEntityID, nil)
	// signedWith rewrites the assertion of an honest response, then signs it as the IdP.
	signedWith := func(rewrite func(assertion string) string) string {
		raw, err := base64.StdEncoding.DecodeString(i.response(t, sp.EntityID(prov.ID), sp.ACSURL(prov.ID), "ada@example.com", responseOptions{unsigned: true}))
		if err != nil {
			t.Fatal(err)
		}
		doc := string(raw)
		start, end := strings.Index(doc, "<saml:Assertion"), strings.Index(doc, "</saml:Assertion>")
		return base64.StdEncoding.EncodeToString([]byte(i.sign(t, doc[:start]+rewrite(doc[start:end])+doc[end:], i.key)))
	}

	noIssuer := signedWith(func(a string) string {
		from, to := strings.Index(a, "<saml:Issuer>"), strings.Index(a, "</saml:Issuer>")+len("</saml:Issuer>")
		return a[:from] + a[to:]
	})
	_, err := DefaultSAML{}.Consume(prov, sp, noIssuer, "")
	refusedAs(t, err, ReasonAssertionInvalid, "issuer", "signed assertion without Issuer")

	foreignNameID := signedWith(func(a string) string {
		a = strings.Replace(a, "<saml:NameID ", `<x:NameID xmlns:x="urn:example:foreign" `, 1)
		return strings.Replace(a, "</saml:NameID>", "</x:NameID>", 1)
	})
	if id, err := (DefaultSAML{}).Consume(prov, sp, foreignNameID, ""); err == nil {
		t.Fatalf("a NameID outside the SAML namespace was read as the subject: %+v", id)
	}
}
