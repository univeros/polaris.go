package sso

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"math/big"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// testIdP is a SAML identity provider for the tests: a self-signed certificate made once per
// process, signed responses and logout requests built for a service provider.
type testIdP struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
	sha1 bool // sign with RSA-SHA1
}

const (
	idpEntityID = "https://idp.example/metadata"
	idpSSOURL   = "https://idp.example/sso"
	idpSLOURL   = "https://idp.example/slo"
	rsaSHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
)

var (
	idpOnce     sync.Once
	theIdP      *testIdP
	otherKeyOne sync.Once
	otherKey    *rsa.PrivateKey
)

func newKeyPair(t testing.TB, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert
}

func idp(t testing.TB) *testIdP {
	idpOnce.Do(func() {
		key, cert := newKeyPair(t, "idp.example")
		theIdP = &testIdP{key: key, cert: cert}
	})
	return theIdP
}

func anotherKey(t testing.TB) *rsa.PrivateKey {
	otherKeyOne.Do(func() { otherKey, _ = newKeyPair(t, "attacker.example") })
	return otherKey
}

// certificateBody is the certificate as a provider stores it: base64 without the PEM armour.
func (i *testIdP) certificateBody() string { return base64.StdEncoding.EncodeToString(i.cert.Raw) }

func (i *testIdP) certificatePEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.cert.Raw}))
}

// responseOptions shape a test response: every zero value is the honest default.
type responseOptions struct {
	issuer, audience, destination, inResponseTo, assertionID string
	notOnOrAfter, notBefore                                  *time.Duration
	unsigned, extraAssertion                                 bool
	key                                                      *rsa.PrivateKey
	attributes                                               [][2]string
}

func seconds(n int) *time.Duration { d := time.Duration(n) * time.Second; return &d }

var idCounter struct {
	sync.Mutex
	n int
}

func uniqid(prefix string) string {
	idCounter.Lock()
	defer idCounter.Unlock()
	idCounter.n++
	return fmt.Sprintf("_%s%d%d", prefix, time.Now().UnixNano(), idCounter.n)
}

// response is a signed Response (the message signature covers the assertion) with one
// assertion, base64.
func (i *testIdP) response(t testing.TB, spEntityID, acs, nameID string, o responseOptions) string {
	t.Helper()
	now := time.Now().UTC()
	or := func(v, def string) string {
		if v == "" {
			return def
		}
		return v
	}
	at := func(d *time.Duration, def time.Duration) string {
		if d != nil {
			def = *d
		}
		return now.Add(def).Format("2006-01-02T15:04:05Z")
	}
	issuer, audience, destination := html.EscapeString(or(o.issuer, idpEntityID)), html.EscapeString(or(o.audience, spEntityID)), html.EscapeString(or(o.destination, acs))
	inResponseTo := ""
	if o.inResponseTo != "" {
		inResponseTo = fmt.Sprintf(` InResponseTo="%s"`, html.EscapeString(o.inResponseTo))
	}
	notOnOrAfter, notBefore, instant := at(o.notOnOrAfter, 300*time.Second), at(o.notBefore, -60*time.Second), at(nil, 0)
	assertionID := or(o.assertionID, uniqid("a"))
	var attrs strings.Builder
	for _, a := range o.attributes {
		fmt.Fprintf(&attrs, `<saml:Attribute Name="%s"><saml:AttributeValue xsi:type="xs:string">%s</saml:AttributeValue></saml:Attribute>`, html.EscapeString(a[0]), html.EscapeString(a[1]))
	}
	attributeXML := ""
	if attrs.Len() > 0 {
		attributeXML = "<saml:AttributeStatement>" + attrs.String() + "</saml:AttributeStatement>"
	}
	assertion := fmt.Sprintf(`<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="%s" Version="2.0" IssueInstant="%s">
    <saml:Issuer>%s</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData NotOnOrAfter="%s" Recipient="%s"%s/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="%s" NotOnOrAfter="%s">
      <saml:AudienceRestriction><saml:Audience>%s</saml:Audience></saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="%s" SessionIndex="session-%s">
      <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext>
    </saml:AuthnStatement>
    %s
  </saml:Assertion>`, assertionID, instant, issuer, nameID, notOnOrAfter, destination, inResponseTo, notBefore, notOnOrAfter, audience, instant, assertionID, attributeXML)
	extra := ""
	if o.extraAssertion {
		extra = "\n  " + strings.ReplaceAll(assertion, assertionID, assertionID+"x")
	}
	xml := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s"%s>
  <saml:Issuer>%s</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  %s%s
</samlp:Response>`, uniqid("r"), instant, destination, inResponseTo, issuer, assertion, extra)
	if !o.unsigned {
		key := i.key
		if o.key != nil {
			key = o.key
		}
		xml = i.sign(t, xml, key)
	}
	return base64.StdEncoding.EncodeToString([]byte(xml))
}

// sign adds an enveloped signature to the root, right after its Issuer, where SAML 2.0 places the
// ds:Signature.
func (i *testIdP) sign(t testing.TB, xml string, key *rsa.PrivateKey) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xml); err != nil {
		t.Fatal(err)
	}
	ctx, err := dsig.NewSigningContext(key, [][]byte{i.cert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	method := rsaSHA256
	if i.sha1 {
		method = dsig.RSASHA1SignatureMethod
	}
	if err := ctx.SetSignatureMethod(method); err != nil {
		t.Fatal(err)
	}
	signed, err := ctx.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	children := signed.ChildElements()
	sig := children[len(children)-1]
	root := doc.Root()
	issuer := root.ChildElements()[0]
	root.InsertChildAt(issuer.Index()+1, sig.Copy())
	s, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// logoutRequest is a LogoutRequest for the SP: with the redirect binding deflated, base64 and the
// query signed (the raw query); with the POST binding an enveloped signature.
func (i *testIdP) logoutRequest(t testing.TB, sloURL, nameID string, redirect bool, relayState string, sign bool) LogoutMessage {
	t.Helper()
	xml := fmt.Sprintf(`<?xml version="1.0"?>
<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="%s" Version="2.0" IssueInstant="%s" Destination="%s">
  <saml:Issuer>%s</saml:Issuer>
  <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">%s</saml:NameID>
  <samlp:SessionIndex>session-1</samlp:SessionIndex>
</samlp:LogoutRequest>`, uniqid("l"), time.Now().UTC().Format("2006-01-02T15:04:05Z"), sloURL, idpEntityID, nameID)
	if !redirect {
		if sign {
			xml = i.sign(t, xml, i.key)
		}
		return LogoutMessage{SAMLRequest: base64.StdEncoding.EncodeToString([]byte(xml))}
	}
	var b bytes.Buffer
	w, _ := flate.NewWriter(&b, flate.BestCompression)
	_, _ = w.Write([]byte(xml))
	_ = w.Close()
	m := LogoutMessage{SAMLRequest: base64.StdEncoding.EncodeToString(b.Bytes()), RelayState: relayState, Redirect: true}
	query := "SAMLRequest=" + url.QueryEscape(m.SAMLRequest)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	if sign {
		m.SigAlg = rsaSHA256
		query += "&SigAlg=" + url.QueryEscape(m.SigAlg)
		sum := sha256.Sum256([]byte(query))
		sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
		if err != nil {
			t.Fatal(err)
		}
		m.Signature = base64.StdEncoding.EncodeToString(sig)
		query += "&Signature=" + url.QueryEscape(m.Signature)
	}
	m.RawQuery = query
	return m
}

func base64Encode(b []byte) string          { return base64.StdEncoding.EncodeToString(b) }
func base64Decode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

// wellFormed reports whether b is one well-formed XML document.
func wellFormed(b []byte) bool {
	dec := xml.NewDecoder(bytes.NewReader(b))
	for {
		if _, err := dec.Token(); err != nil {
			return errors.Is(err, io.EOF)
		}
	}
}
