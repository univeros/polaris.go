package sso

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/univeros/polaris.go/internal/netguard"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

const testBase = "https://app.example/auth"

func testProvider(typ string, config map[string]any, issuer string, attributes map[string]string) Provider {
	if attributes == nil {
		attributes = map[string]string{}
	}
	return Provider{ID: "p1", OrganizationID: "org-1", Type: typ, Name: "Test", Issuer: issuer, Config: config,
		Attributes: attributes, RedirectURIs: []string{"https://app.example/done"}, Enabled: true}
}

// refusedAs asserts err is an *Error with reason whose detail contains want.
func refusedAs(t *testing.T, err error, reason, want, what string) {
	t.Helper()
	e, ok := errors.AsType[*Error](err)
	if !ok || e.Reason != reason || !strings.Contains(e.Detail, want) {
		t.Fatalf("%s: %v, want %s containing %q", what, err, reason, want)
	}
	t.Logf("%s: %s", what, e.Detail)
}

func TestSAMLAcceptsASignedResponseAndRefusesTheClassicAttacks(t *testing.T) {
	i := idp(t)
	saml := DefaultSAML{}
	sp := SP{BaseURL: testBase}
	prov := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "slo_url": idpSLOURL, "certificate": i.certificateBody()},
		idpEntityID, map[string]string{"email": "mail", "name": "displayName"})
	acs, entity := sp.ACSURL(prov.ID), sp.EntityID(prov.ID)

	requestID, target, err := saml.AuthnRequest(prov, sp, "relay-1")
	if err != nil || !strings.HasPrefix(target, idpSSOURL+"?SAMLRequest=") || !strings.Contains(target, "RelayState=relay-1") || requestID == "" {
		t.Fatalf("authn request %q %q %v", requestID, target, err)
	}

	id, err := saml.Consume(prov, sp, i.response(t, entity, acs, "ada@example.com", responseOptions{inResponseTo: requestID, assertionID: "_a1",
		attributes: [][2]string{{"mail", "Ada@Example.com"}, {"displayName", "Ada"}}}), requestID)
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "ada@example.com" || id.Email != "ada@example.com" || id.Name != "Ada" || id.AssertionID != "_a1" || id.SessionIndex != "session-_a1" ||
		id.NotOnOrAfter.Before(time.Now().Add(200*time.Second)) || id.Attributes["mail"].([]string)[0] != "Ada@Example.com" {
		t.Fatalf("identity %+v", id)
	}
	unsolicited, err := saml.Consume(prov, sp, i.response(t, entity, acs, "bob@example.com", responseOptions{}), "")
	if err != nil || unsolicited.Email != "bob@example.com" {
		t.Fatalf("the NameID is the email when no attribute carries one: %+v %v", unsolicited, err)
	}

	attacks := map[string]struct {
		o         responseOptions
		requestID string
	}{
		"unsigned":                       {responseOptions{unsigned: true}, ""},
		"signed by another key":          {responseOptions{key: anotherKey(t)}, ""},
		"a second assertion smuggled in": {responseOptions{extraAssertion: true, inResponseTo: requestID}, requestID},
		"another audience":               {responseOptions{audience: "https://someone.else/sp"}, ""},
		"another destination":            {responseOptions{destination: "https://someone.else/acs"}, ""},
		"expired beyond the drift":       {responseOptions{notOnOrAfter: seconds(-400)}, ""},
		"not yet valid beyond the drift": {responseOptions{notBefore: seconds(400)}, ""},
		"answering another request":      {responseOptions{inResponseTo: "id-other"}, requestID},
		"another issuer":                 {responseOptions{issuer: "https://someone.else/idp"}, ""},
		"unsolicited with InResponseTo":  {responseOptions{inResponseTo: requestID}, ""},
		"solicited without InResponseTo": {responseOptions{}, requestID},
	}
	for name, a := range attacks {
		_, err := saml.Consume(prov, sp, i.response(t, entity, acs, "ada@example.com", a.o), a.requestID)
		refusedAs(t, err, ReasonAssertionInvalid, "", name)
	}
	if id, err := saml.Consume(prov, sp, i.response(t, entity, acs, "ada@example.com", responseOptions{notOnOrAfter: seconds(-60)}), ""); err != nil || id.Email != "ada@example.com" {
		t.Fatalf("a minute past is within the drift: %v", err)
	}
	for name, raw := range map[string]string{
		"not base64":   "not base64 xml!",
		"not XML":      base64.StdEncoding.EncodeToString([]byte("<<<")),
		"no email":     i.response(t, entity, acs, "no-email", responseOptions{}),
		"tampered":     tamper(t, i.response(t, entity, acs, "ada@example.com", responseOptions{}), "ada@example.com", "eve@example.com"),
		"wrapped":      wrap(t, i.response(t, entity, acs, "ada@example.com", responseOptions{})),
		"no assertion": base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)),
	} {
		_, err := saml.Consume(prov, sp, raw, "")
		refusedAs(t, err, ReasonAssertionInvalid, "", name)
	}

	metadata, err := saml.Metadata(prov, sp)
	for _, want := range []string{`entityID="` + entity + `"`, `Location="` + acs + `"`, `Location="` + sp.SLOURL(prov.ID) + `"`} {
		if err != nil || !strings.Contains(string(metadata), want) {
			t.Fatalf("metadata lacks %s: %s %v", want, metadata, err)
		}
	}
	if p := saml.Check(prov, sp); len(p) != 0 {
		t.Fatalf("check %v", p)
	}
	pemProvider := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "certificate": i.certificatePEM()}, idpEntityID, nil)
	if p := saml.Check(pemProvider, sp); len(p) != 0 {
		t.Fatalf("a PEM certificate: %v", p)
	}
	if p := saml.Check(testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "certificate": "nope"}, idpEntityID, nil), sp); len(p) != 1 || p[0] != "certificate does not parse as X.509" {
		t.Fatalf("check %v", p)
	}
	if p := saml.Check(testProvider(TypeSAML, map[string]any{}, "", nil), sp); strings.Join(p, "|") != "issuer (the IdP entity id) is not set|sso_url is not set|certificate is not set" {
		t.Fatalf("check %v", p)
	}
}

// tamper changes the signed content of a base64 response.
func tamper(t *testing.T, response, from, to string) string {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(response)
	return base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), from, to, 1)))
}

// wrap is a signature wrapping attempt: the signed response moved into an Extensions element of a
// forged response carrying the attacker's assertion.
func wrap(t *testing.T, response string) string {
	t.Helper()
	raw, _ := base64.StdEncoding.DecodeString(response)
	signed := strings.TrimPrefix(string(raw), `<?xml version="1.0"?>`)
	forged := strings.Replace(signed, "ada@example.com", "eve@example.com", 1)
	forged = strings.Replace(forged, "<saml:Issuer>", "<samlp:Extensions>"+signed+"</samlp:Extensions><saml:Issuer>", 1)
	return base64.StdEncoding.EncodeToString([]byte(forged))
}

func TestSAMLSingleLogoutBothWays(t *testing.T) {
	i := idp(t)
	saml := DefaultSAML{Clock: clock.System{}}
	sp := SP{BaseURL: testBase}
	prov := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "slo_url": idpSLOURL, "certificate": i.certificateBody()}, idpEntityID, nil)
	slo := sp.SLOURL(prov.ID)

	redirect, err := saml.ConsumeLogoutRequest(prov, sp, i.logoutRequest(t, slo, "ada@example.com", true, "rs", true))
	if err != nil || redirect.NameID != "ada@example.com" || len(redirect.SessionIndexes) != 1 || redirect.SessionIndexes[0] != "session-1" || !strings.HasPrefix(redirect.ID, "_l") {
		t.Fatalf("redirect %+v %v", redirect, err)
	}
	fields := i.logoutRequest(t, slo, "ada@example.com", true, "", true)
	fields.RawQuery = "" // rebuilt from the fields
	if _, err := saml.ConsumeLogoutRequest(prov, sp, fields); err != nil {
		t.Fatalf("from the fields: %v", err)
	}
	post, err := saml.ConsumeLogoutRequest(prov, sp, i.logoutRequest(t, slo, "ada@example.com", false, "", true))
	if err != nil || post.NameID != "ada@example.com" {
		t.Fatalf("post %+v %v", post, err)
	}
	tampered := i.logoutRequest(t, slo, "ada@example.com", true, "rs", true)
	tampered.RawQuery = strings.Replace(tampered.RawQuery, "RelayState=rs", "RelayState=changed", 1)
	for name, m := range map[string]LogoutMessage{
		"unsigned redirect":   i.logoutRequest(t, slo, "ada@example.com", true, "", false),
		"unsigned post":       i.logoutRequest(t, slo, "ada@example.com", false, "", false),
		"another destination": i.logoutRequest(t, "https://someone.else/slo", "ada@example.com", true, "", true),
		"tampered":            tampered,
	} {
		_, err := saml.ConsumeLogoutRequest(prov, sp, m)
		refusedAs(t, err, ReasonAssertionInvalid, "", name)
	}

	responseURL, err := saml.LogoutResponseURL(prov, sp, redirect.ID, "rs")
	if err != nil || !strings.HasPrefix(responseURL, idpSLOURL+"?SAMLResponse=") || !strings.Contains(responseURL, "RelayState=rs") {
		t.Fatalf("response url %q %v", responseURL, err)
	}
	logoutURL, err := saml.LogoutURL(prov, sp, "ada@example.com", "session-1", "rs")
	if err != nil || !strings.HasPrefix(logoutURL, idpSLOURL+"?SAMLRequest=") {
		t.Fatalf("logout url %q %v", logoutURL, err)
	}
	responses := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "slo_url": idpSLOURL, "slo_response_url": "https://idp.example/slo-response", "certificate": i.certificateBody()}, idpEntityID, nil)
	if u, err := saml.LogoutResponseURL(responses, sp, "x", ""); err != nil || !strings.HasPrefix(u, "https://idp.example/slo-response?SAMLResponse=") {
		t.Fatalf("slo_response_url %q %v", u, err)
	}
	noSLO := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "certificate": i.certificateBody()}, idpEntityID, nil)
	if u, err := saml.LogoutURL(noSLO, sp, "ada@example.com", "", "rs"); u != "" || err != nil {
		t.Fatalf("no slo: %q %v", u, err)
	}
	if u, err := saml.LogoutResponseURL(noSLO, sp, "x", ""); u != "" || err != nil {
		t.Fatalf("no slo: %q %v", u, err)
	}
}

func TestAnSPKeyPairSignsTheRequestsAndIsPublished(t *testing.T) {
	key, cert := newKeyPair(t, "app.example")
	sp := SP{BaseURL: testBase, Key: key, Certificate: cert}
	prov := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "slo_url": idpSLOURL, "certificate": idp(t).certificateBody()}, idpEntityID, nil)
	_, target, err := DefaultSAML{}.AuthnRequest(prov, sp, "rs")
	if err != nil || !strings.Contains(target, "Signature=") || !strings.Contains(target, "SigAlg=") {
		t.Fatalf("a signed AuthnRequest: %q %v", target, err)
	}
	metadata, err := DefaultSAML{}.Metadata(prov, sp)
	if err != nil || !strings.Contains(string(metadata), base64.StdEncoding.EncodeToString(cert.Raw)[:40]) {
		t.Fatalf("the certificate in the metadata: %v", err)
	}
}

func TestOIDCRunsDiscoveryTheCodeExchangeAndVerifiesTheIdToken(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var mu sync.Mutex
	var requests []*http.Request
	var forms []url.Values
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	issuer := srv.URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks", "end_session_endpoint": issuer + "/logout"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		forms = append(forms, r.PostForm)
		mu.Unlock()
		code := r.PostForm.Get("code")
		now := time.Now().Unix()
		claims := map[string]any{"iss": issuer, "aud": "client-1", "sub": "u-42", "email": "Ada@Example.com", "name": "Ada Lovelace", "nonce": "nonce-1", "iat": now, "exp": now + 300}
		signer := key
		switch code {
		case "wrong-nonce":
			claims["nonce"] = "other"
		case "wrong-aud":
			claims["aud"] = "someone-else"
		case "wrong-iss":
			claims["iss"] = "https://someone.else"
		case "expired":
			claims["exp"] = now - 600
		case "no-email":
			delete(claims, "email")
		case "wrong-key":
			signer, _ = rsa.GenerateKey(rand.Reader, 2048)
		case "refused":
			w.WriteHeader(http.StatusBadRequest)
		case "no-token":
			_, _ = w.Write([]byte(`{"access_token": "at"}`))
			return
		}
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signer}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		payload, _ := json.Marshal(claims)
		jws, _ := s.Sign(payload)
		token, _ := jws.CompactSerialize()
		_ = json.NewEncoder(w).Encode(map[string]any{"id_token": token, "access_token": "at", "token_type": "Bearer"})
	})
	counting := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		mu.Lock()
		requests = append(requests, r)
		mu.Unlock()
		return http.DefaultTransport.RoundTrip(r)
	})}
	o := &HTTPOIDC{HTTP: netguard.NoRedirects(counting), Cache: cache.NewMemory(clock.System{}), Clock: clock.System{}}
	ctx := context.Background()
	prov := testProvider(TypeOIDC, map[string]any{"client_id": "client-1", "scopes": "openid email"}, issuer, nil)
	callback := testBase + "/sso/callback/p1"

	target, err := o.AuthorizationURL(ctx, prov, callback, "state-1", "nonce-1", "challenge")
	u, _ := url.Parse(target)
	q := u.Query()
	if err != nil || !strings.HasPrefix(target, issuer+"/authorize?") || q.Get("response_type") != "code" || q.Get("client_id") != "client-1" ||
		q.Get("redirect_uri") != callback || q.Get("scope") != "openid email" || q.Get("state") != "state-1" || q.Get("nonce") != "nonce-1" ||
		q.Get("code_challenge") != "challenge" || q.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorization url %q %v", target, err)
	}
	id, err := o.Exchange(ctx, prov, "secret-1", "good", callback, "verifier", "nonce-1")
	if err != nil || id.Subject != "u-42" || id.Email != "ada@example.com" || id.Name != "Ada Lovelace" {
		t.Fatalf("identity %+v %v", id, err)
	}
	f := forms[0]
	if f.Get("grant_type") != "authorization_code" || f.Get("code") != "good" || f.Get("client_id") != "client-1" || f.Get("client_secret") != "secret-1" || f.Get("code_verifier") != "verifier" {
		t.Fatalf("token request %v", f)
	}
	if len(requests) != 3 {
		t.Fatalf("discovery once, the JWKS once, the token endpoint: %d", len(requests))
	}
	if _, err := o.Exchange(ctx, prov, "", "good", callback, "verifier", "nonce-1"); err != nil || len(requests) != 4 || forms[1].Has("client_secret") {
		t.Fatalf("discovery and the JWKS come from the cache: %d %v", len(requests), err)
	}
	for code, reason := range map[string]string{"wrong-nonce": "nonce mismatch", "wrong-aud": "audience mismatch", "wrong-iss": "issuer mismatch",
		"expired": "id_token rejected: the token has expired", "wrong-key": "id_token rejected: the signature does not verify", "no-email": "no subject or email", "refused": "answered 400",
		"no-token": "no id_token"} {
		_, err := o.Exchange(ctx, prov, "", code, callback, "verifier", "nonce-1")
		refusedAs(t, err, ReasonAssertionInvalid, reason, code)
	}
	if got := o.EndSessionURL(ctx, prov, "https://app.example/done"); got != issuer+"/logout?client_id=client-1&post_logout_redirect_uri=https%3A%2F%2Fapp.example%2Fdone" {
		t.Fatalf("end session %q", got)
	}
	if p := o.Check(ctx, prov); len(p) != 0 {
		t.Fatalf("check %v", p)
	}

	unreachable := &HTTPOIDC{HTTP: netguard.NoRedirects(srv.Client()), Cache: cache.NewMemory(clock.System{}), Clock: clock.System{}}
	nowhere := testProvider(TypeOIDC, map[string]any{"client_id": "client-1"}, issuer+"/nowhere", nil)
	if p := unreachable.Check(ctx, nowhere); len(p) != 1 || p[0] != "discovery answered 404" {
		t.Fatalf("check %v", p)
	}
	if unreachable.EndSessionURL(ctx, nowhere, "") != "" {
		t.Fatal("no discovery, no end session")
	}
	if p := unreachable.Check(ctx, testProvider(TypeOIDC, map[string]any{}, issuer+"/nowhere", nil)); strings.Join(p, "|") != "client_id is not set|discovery answered 404" {
		t.Fatalf("check %v", p)
	}
	if _, err := unreachable.AuthorizationURL(ctx, nowhere, callback, "s", "n", "c"); err == nil {
		t.Fatal("no discovery, no authorization URL")
	}
}

func TestAKeyWithoutAlgVerifiesTheAlgorithmItsTypeImplies(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct {
		key  any
		want string
	}{
		"RSA": {&rsaKey.PublicKey, "RS256"}, "EC P-256": {&p256.PublicKey, "ES256"}, "OKP Ed25519": {edPub, "EdDSA"},
		"EC P-384": {&p384.PublicKey, ""}, "symmetric": {[]byte("secret"), ""},
	} {
		got, err := algorithmOf(jose.JSONWebKey{Key: c.key})
		if got != c.want || (c.want == "") != (err != nil) {
			t.Fatalf("%s: %q %v", name, got, err)
		}
	}
	if got, err := algorithmOf(jose.JSONWebKey{Key: &rsaKey.PublicKey, Algorithm: "RS512"}); got != "RS512" || err != nil {
		t.Fatalf("a key's own alg: %q %v", got, err)
	}

	now := time.Now()
	sign := func(alg jose.SignatureAlgorithm, key any, kid string) string {
		opts := &jose.SignerOptions{}
		if kid != "" {
			opts = opts.WithHeader("kid", kid)
		}
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
		jws, _ := s.Sign([]byte(fmt.Sprintf(`{"sub":"u","exp":%d}`, now.Unix()+60)))
		raw, _ := jws.CompactSerialize()
		return raw
	}
	keys := []jose.JSONWebKey{{Key: &rsaKey.PublicKey, KeyID: "rsa"}, {Key: &p256.PublicKey, KeyID: "ec"}, {Key: &p384.PublicKey, KeyID: "p384"}}
	for name, c := range map[string]struct {
		token, err string
	}{
		"RS256 by an RSA key":          {sign(jose.RS256, rsaKey, "rsa"), ""},
		"ES256 by a P-256 key":         {sign(jose.ES256, p256, "ec"), ""},
		"RS384 by an RSA key":          {sign(jose.RS384, rsaKey, "rsa"), "the key's algorithm is not the token's (alg)"},
		"ES384 by a key without alg":   {sign(jose.ES384, p384, "p384"), "the key names no alg and its type implies none"},
		"no kid":                       {sign(jose.RS256, rsaKey, ""), "the token names no key (kid)"},
		"a kid the set does not carry": {sign(jose.RS256, rsaKey, "other"), "no key in the key set has the token's kid"},
	} {
		_, err := verifyIDToken(c.token, keys, now)
		if (c.err == "" && err != nil) || (c.err != "" && (err == nil || err.Error() != c.err)) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestIDTokenTimeErrorsAreGoNative(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keys := []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256"}}
	now := time.Now()
	for claims, want := range map[string]string{
		fmt.Sprintf(`{"nbf":%d}`, now.Unix()+600): "the token is not valid yet (nbf)",
		fmt.Sprintf(`{"iat":%d}`, now.Unix()+600): "the token was issued in the future (iat)",
		fmt.Sprintf(`{"exp":%d}`, now.Unix()-600): "the token has expired",
		`[1]`: "the claims are not a JSON object",
	} {
		s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k"))
		jws, _ := s.Sign([]byte(claims))
		raw, _ := jws.CompactSerialize()
		if _, err := verifyIDToken(raw, keys, now); err == nil || err.Error() != want {
			t.Fatalf("%s: %v", claims, err)
		}
	}
}

// An IdP's certificate is the container of the key the organization configured; its validity
// dates are not checked (the configuration is the trust anchor), so an expired one verifies.
func TestAnExpiredIdPCertificateStillVerifies(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "expired.idp.example"},
		NotBefore: time.Now().Add(-2 * 365 * 24 * time.Hour), NotAfter: time.Now().Add(-365 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	expired := &testIdP{key: key, cert: cert}
	sp := SP{BaseURL: testBase}
	prov := testProvider(TypeSAML, map[string]any{"sso_url": idpSSOURL, "certificate": expired.certificateBody()}, idpEntityID, nil)
	id, err := DefaultSAML{}.Consume(prov, sp, expired.response(t, sp.EntityID(prov.ID), sp.ACSURL(prov.ID), "ada@example.com", responseOptions{}), "")
	if err != nil || id.Email != "ada@example.com" {
		t.Fatalf("an expired certificate: %+v %v", id, err)
	}
	_, err = DefaultSAML{}.Consume(prov, sp, expired.response(t, sp.EntityID(prov.ID), sp.ACSURL(prov.ID), "ada@example.com", responseOptions{key: anotherKey(t)}), "")
	refusedAs(t, err, ReasonAssertionInvalid, "", "another key, the expired certificate configured")
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTheDomainVerifierChecksDNSThenTheWellKnownFile(t *testing.T) {
	var fetched []string
	client := &http.Client{Transport: roundTripper(func(r *http.Request) (*http.Response, error) {
		fetched = append(fetched, r.URL.String())
		rec := httptest.NewRecorder()
		if r.URL.String() == "https://acme.example/.well-known/polaris-sso.txt" {
			_, _ = rec.WriteString("polaris-sso-token\n")
		} else {
			rec.WriteHeader(http.StatusNotFound)
		}
		return rec.Result(), nil
	})}
	lookup := func(_ context.Context, name string) ([]string, error) {
		if name == "_polaris.dns.example" {
			return []string{"other", " polaris-sso-token "}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	v := DNSHTTPSVerifier{LookupTXT: lookup, HTTP: client}
	ctx := context.Background()
	for domain, want := range map[string]string{"dns.example": "dns", "acme.example": "https"} {
		if got := v.Verify(ctx, domain, "polaris-sso-token"); got != want {
			t.Fatalf("%s: %q", domain, got)
		}
	}
	if v.Verify(ctx, "acme.example", "other-token") != "" || v.Verify(ctx, "nowhere.example", "polaris-sso-token") != "" {
		t.Fatal("verified without the token")
	}
	if (DNSHTTPSVerifier{LookupTXT: lookup}).Verify(ctx, "acme.example", "polaris-sso-token") != "" {
		t.Fatal("no client, no HTTPS check")
	}
	if !strings.Contains(fetched[0], "acme.example") {
		t.Fatalf("fetched %v", fetched)
	}
}

func TestTheDefaultClientRefusesNonPublicAddresses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("polaris-sso-token")) }))
	defer srv.Close()
	resp, err := netguard.NoRedirects(nil).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("the loopback address was reached")
	}
	if !errors.Is(err, netguard.ErrNonPublicAddress) {
		t.Fatalf("error %v", err)
	}
	for addr, public := range map[string]bool{"8.8.8.8": true, "10.0.0.1": false, "169.254.169.254": false, "100.64.0.1": false, "::1": false, "2606:4700::1111": true} {
		if got := netguard.Control("tcp", net.JoinHostPort(addr, "443"), nil) == nil; got != public {
			t.Fatalf("%s public = %v", addr, got)
		}
	}
	if netguard.Control("tcp", "nonsense", nil) == nil {
		t.Fatal("an address without a port")
	}
	redirecting := httptest.NewServer(http.RedirectHandler("https://elsewhere.example/", http.StatusFound))
	defer redirecting.Close()
	resp, err = netguard.NoRedirects(redirecting.Client()).Get(redirecting.URL)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("a redirect is not followed: %v", err)
	}
	resp.Body.Close()
}
