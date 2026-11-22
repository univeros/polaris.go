package sso

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/univeros/polaris.go/clock"
)

// DefaultSAML is the default SAML: github.com/crewjam/saml, strict. A response is accepted only
// when it carries exactly one assertion (a smuggled second one is refused before parsing), signed
// on the response or on the assertion by the provider's certificate, read from what the signature
// covers (signature wrapping), issued by the provider's entity id, for the SP entity id (audience),
// sent to the assertion consumer URL (Destination, Recipient), answering the AuthnRequest the SP
// sent (InResponseTo; none for an IdP-initiated response), within its conditions with three
// minutes of skew. A LogoutRequest must be signed (the redirect binding's query signature or an
// enveloped signature), sent to the SLO URL, by the provider. Replay is refused by the flow, which
// keeps the assertion ids seen.
type DefaultSAML struct {
	Clock clock.Clock // the system clock when nil
}

// AuthnRequest implements SAML: the redirect binding, signed when the SP has a key.
func (s DefaultSAML) AuthnRequest(p Provider, sp SP, relayState string) (string, string, error) {
	csp, err := s.serviceProvider(p, sp, "", false)
	if err != nil {
		return "", "", err
	}
	req, err := csp.MakeAuthenticationRequest(p.Setting("sso_url"), saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		return "", "", err
	}
	u, err := req.Redirect(relayState, csp)
	if err != nil {
		return "", "", err
	}
	return req.ID, u.String(), nil
}

// Consume implements SAML.
func (s DefaultSAML) Consume(p Provider, sp SP, samlResponse, requestID string) (Identity, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(samlResponse), ""))
	if err != nil {
		return Identity{}, refuse(ReasonAssertionInvalid, "the SAMLResponse is not base64")
	}
	if err := oneAssertion(raw); err != nil {
		return Identity{}, err
	}
	csp, err := s.serviceProvider(p, sp, "", requestID == "")
	if err != nil {
		return Identity{}, err
	}
	var requestIDs []string
	if requestID != "" {
		requestIDs = []string{requestID}
	}
	a, err := csp.ParseXMLResponse(raw, requestIDs, csp.AcsURL)
	if err != nil {
		return Identity{}, refuse(ReasonAssertionInvalid, private(err))
	}
	var nameID string
	if a.Subject != nil && a.Subject.NameID != nil {
		nameID = strings.TrimSpace(a.Subject.NameID.Value)
	}
	attributes := map[string]any{}
	for _, statement := range a.AttributeStatements {
		for _, attr := range statement.Attributes {
			values, _ := attributes[attr.Name].([]string)
			for _, v := range attr.Values {
				values = append(values, v.Value)
			}
			attributes[attr.Name] = values
		}
	}
	email := first(attributes, p.Attribute("email"))
	if email == "" && strings.Contains(nameID, "@") {
		email = nameID
	}
	if email == "" {
		return Identity{}, refuse(ReasonAssertionInvalid, "the assertion carries no email")
	}
	id := Identity{Subject: nameID, Email: strings.ToLower(email), Name: first(attributes, p.Attribute("name")),
		Attributes: attributes, AssertionID: a.ID, NotOnOrAfter: notOnOrAfter(a)}
	if len(a.AuthnStatements) > 0 {
		id.SessionIndex = a.AuthnStatements[0].SessionIndex
	}
	return id, nil
}

// Metadata implements SAML: the SP's entity id, assertion consumer (POST), single logout
// (redirect) and, when the SP has one, its certificate.
func (s DefaultSAML) Metadata(p Provider, sp SP) ([]byte, error) {
	csp, err := s.serviceProvider(p, sp, "", false)
	if err != nil {
		return nil, err
	}
	return xml.MarshalIndent(csp.Metadata(), "", "  ")
}

// LogoutURL implements SAML.
func (s DefaultSAML) LogoutURL(p Provider, sp SP, nameID, sessionIndex, relayState string) (string, error) {
	if p.Setting("slo_url") == "" {
		return "", nil
	}
	csp, err := s.serviceProvider(p, sp, "", false)
	if err != nil {
		return "", err
	}
	var opts []saml.LogoutRequestOption
	if sessionIndex != "" {
		opts = append(opts, saml.WithSessionIndex(sessionIndex))
	}
	u, err := csp.MakeRedirectLogoutRequest(nameID, relayState, opts...)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// ConsumeLogoutRequest implements SAML.
func (s DefaultSAML) ConsumeLogoutRequest(p Provider, sp SP, m LogoutMessage) (LogoutRequest, error) {
	csp, err := s.serviceProvider(p, sp, "", false)
	if err != nil {
		return LogoutRequest{}, err
	}
	var req *saml.LogoutRequest
	if m.Redirect {
		query := m.RawQuery
		if query == "" {
			query = rawQuery(m)
		}
		req, err = csp.ValidateLogoutRequest(&http.Request{Method: http.MethodGet, URL: &url.URL{RawQuery: query}})
	} else {
		req, err = csp.ValidateLogoutRequestForm(m.SAMLRequest)
	}
	if err != nil {
		return LogoutRequest{}, refuse(ReasonAssertionInvalid, private(err))
	}
	out := LogoutRequest{ID: req.ID, SessionIndexes: []string{}}
	if req.NameID != nil {
		out.NameID = req.NameID.Value
	}
	if req.SessionIndex != nil {
		out.SessionIndexes = append(out.SessionIndexes, req.SessionIndex.Value)
	}
	for _, si := range req.AdditionalSessionIndexes {
		out.SessionIndexes = append(out.SessionIndexes, si.Value)
	}
	return out, nil
}

// LogoutResponseURL implements SAML: to slo_response_url, else slo_url.
func (s DefaultSAML) LogoutResponseURL(p Provider, sp SP, inResponseTo, relayState string) (string, error) {
	location := p.Setting("slo_response_url")
	if location == "" {
		location = p.Setting("slo_url")
	}
	if location == "" {
		return "", nil
	}
	csp, err := s.serviceProvider(p, sp, location, false)
	if err != nil {
		return "", err
	}
	u, err := csp.MakeRedirectLogoutResponse(inResponseTo, relayState)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// Check implements SAML.
func (s DefaultSAML) Check(p Provider, _ SP) []string {
	problems := []string{}
	if p.Issuer == "" {
		problems = append(problems, "issuer (the IdP entity id) is not set")
	}
	if p.Setting("sso_url") == "" {
		problems = append(problems, "sso_url is not set")
	}
	switch cert := p.Setting("certificate"); {
	case cert == "":
		problems = append(problems, "certificate is not set")
	case parseCertificate(cert) == nil:
		problems = append(problems, "certificate does not parse as X.509")
	}
	return problems
}

// serviceProvider is crewjam's service provider for one provider; sloLocation overrides the IdP's
// single-logout location (the LogoutResponse goes to slo_response_url).
func (s DefaultSAML) serviceProvider(p Provider, sp SP, sloLocation string, idpInitiated bool) (*saml.ServiceProvider, error) {
	parse := func(raw string) (url.URL, error) {
		u, err := url.Parse(raw)
		if err != nil {
			return url.URL{}, err
		}
		return *u, nil
	}
	metadata, err := parse(sp.MetadataURL(p.ID))
	if err != nil {
		return nil, err
	}
	acs, _ := parse(sp.ACSURL(p.ID))
	slo, _ := parse(sp.SLOURL(p.ID))
	if sloLocation == "" {
		sloLocation = p.Setting("slo_url")
	}
	idp := saml.IDPSSODescriptor{
		SSODescriptor: saml.SSODescriptor{RoleDescriptor: saml.RoleDescriptor{
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptors: []saml.KeyDescriptor{{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{
				X509Certificates: []saml.X509Certificate{{Data: certificateBody(p.Setting("certificate"))}}}}}},
		}},
		SingleSignOnServices: []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: p.Setting("sso_url")}},
	}
	if sloLocation != "" {
		idp.SingleLogoutServices = []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: sloLocation}}
	}
	now := time.Now
	if s.Clock != nil {
		now = s.Clock.Now
	}
	csp := &saml.ServiceProvider{
		EntityID: sp.EntityID(p.ID), MetadataURL: metadata, AcsURL: acs, SloURL: slo,
		IDPMetadata:                      &saml.EntityDescriptor{EntityID: p.Issuer, IDPSSODescriptors: []saml.IDPSSODescriptor{idp}},
		AllowIDPInitiated:                idpInitiated,
		Clock:                            dsig.NewFakeClockAt(now()),
		AuthnNameIDFormat:                saml.UnspecifiedNameIDFormat,
		LogoutBindings:                   []string{saml.HTTPRedirectBinding},
		AssertionConsumerServiceBindings: []string{saml.HTTPPostBinding},
		// The certificate is only a container for the IdP's key, which the operator configured
		// explicitly: the configuration is the trust anchor (no chain, no revocation), so its
		// dates add nothing, and IdPs commonly publish long-expired self-signed certificates. An
		// expired one still verifies; rotating the key is a configuration change.
		IgnoreCertificateExpiry: true,
	}
	if sp.Key != nil && sp.Certificate != nil {
		csp.Key, csp.Certificate, csp.SignatureMethod = sp.Key, sp.Certificate, dsig.RSASHA256SignatureMethod
	}
	return csp, nil
}

// maxAssertions is the number of assertions a response carries: exactly one.
const maxAssertions = 1

// oneAssertion refuses a response that does not carry exactly one Assertion or
// EncryptedAssertion element anywhere (whatever its namespace prefix): a second one smuggled in
// next to the signed one, or nested elsewhere, is a wrapping attempt.
func oneAssertion(raw []byte) error {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil || doc.Root() == nil {
		return refuse(ReasonAssertionInvalid, "the SAMLResponse is not XML")
	}
	n := 0
	var walk func(*etree.Element)
	walk = func(el *etree.Element) {
		if el.Tag == "Assertion" || el.Tag == "EncryptedAssertion" {
			n++
		}
		for _, child := range el.ChildElements() {
			walk(child)
		}
	}
	walk(doc.Root())
	if n != maxAssertions {
		return refuse(ReasonAssertionInvalid, "the SAML Response must contain exactly one assertion")
	}
	return nil
}

// private is the reason behind crewjam's generic error, for the audit trail.
func private(err error) string {
	if e, ok := errors.AsType[*saml.InvalidResponseError](err); ok && e.PrivateErr != nil {
		return e.PrivateErr.Error()
	}
	return err.Error()
}

// notOnOrAfter is the latest validity end the assertion states (its subject confirmations and
// conditions): how long its id must stay in the replay set.
func notOnOrAfter(a *saml.Assertion) time.Time {
	var latest time.Time
	if a.Conditions != nil && a.Conditions.NotOnOrAfter.After(latest) {
		latest = a.Conditions.NotOnOrAfter
	}
	if a.Subject != nil {
		for _, sc := range a.Subject.SubjectConfirmations {
			if d := sc.SubjectConfirmationData; d != nil && d.NotOnOrAfter.After(latest) {
				latest = d.NotOnOrAfter
			}
		}
	}
	return latest
}

// first is the first non-blank value of an attribute, trimmed.
func first(attributes map[string]any, name string) string {
	values, _ := attributes[name].([]string)
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// certificateBody is a certificate given as PEM or base64, as base64 without the BEGIN/END
// armour lines or any whitespace.
func certificateBody(cert string) string {
	for _, armour := range []string{"-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"} {
		cert = strings.ReplaceAll(cert, armour, "")
	}
	return strings.Join(strings.Fields(cert), "")
}

func parseCertificate(cert string) *x509.Certificate {
	der, err := base64.StdEncoding.DecodeString(certificateBody(cert))
	if err != nil {
		return nil
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil
	}
	return c
}

// rawQuery is a redirect-binding query built from the message's fields.
func rawQuery(m LogoutMessage) string {
	q := "SAMLRequest=" + url.QueryEscape(m.SAMLRequest)
	for _, kv := range [][2]string{{"RelayState", m.RelayState}, {"SigAlg", m.SigAlg}, {"Signature", m.Signature}} {
		if kv[1] != "" {
			q += "&" + kv[0] + "=" + url.QueryEscape(kv[1])
		}
	}
	return q
}
