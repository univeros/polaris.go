package sso

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

const (
	oidcCacheTTL     = time.Hour
	idTokenLeeway    = 60 // seconds
	defaultScopes    = "openid email profile"
	maxProviderBytes = 1 << 20
)

// idTokenAlgorithms are the signatures an id_token may carry.
var idTokenAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512}

// HTTPOIDC is the default OIDC: discovery (<issuer>/.well-known/openid-configuration, cached an
// hour), the authorization code flow with PKCE (S256) and a nonce, the token endpoint with
// client_secret_post, the id_token verified against the provider's JWKS (a minute of leeway, one
// fresh fetch for an unknown kid), then its issuer, audience and nonce.
type HTTPOIDC struct {
	HTTP  *http.Client // never follows redirects
	Cache cache.Cache
	Clock clock.Clock
}

// discovery is the part of a discovery document the flow reads.
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
}

// AuthorizationURL implements OIDC.
func (o *HTTPOIDC) AuthorizationURL(ctx context.Context, p Provider, redirectURI, state, nonce, codeChallenge string) (string, error) {
	d, err := o.discover(ctx, p, false)
	if err != nil {
		return "", err
	}
	scope := p.Setting("scopes")
	if scope == "" {
		scope = defaultScopes
	}
	return withQuery(d.AuthorizationEndpoint, [][2]string{
		{"response_type", "code"}, {"client_id", p.Setting("client_id")}, {"redirect_uri", redirectURI}, {"scope", scope},
		{"state", state}, {"nonce", nonce}, {"code_challenge", codeChallenge}, {"code_challenge_method", "S256"},
	}), nil
}

// Exchange implements OIDC.
func (o *HTTPOIDC) Exchange(ctx context.Context, p Provider, clientSecret, code, redirectURI, codeVerifier, nonce string) (Identity, error) {
	d, err := o.discover(ctx, p, false)
	if err != nil {
		return Identity{}, err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI},
		"client_id": {p.Setting("client_id")}, "code_verifier": {codeVerifier}}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, refuse(ReasonAssertionInvalid, "token endpoint unreachable: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	var body struct {
		IDToken any `json:"id_token"`
	}
	if err := o.send(req, "token endpoint", &body); err != nil {
		return Identity{}, err
	}
	idToken, _ := body.IDToken.(string)
	if idToken == "" {
		return Identity{}, refuse(ReasonAssertionInvalid, "no id_token in the token response")
	}
	claims, err := o.claims(ctx, p, d, idToken, nonce)
	if err != nil {
		return Identity{}, err
	}
	sub, _ := claims["sub"].(string)
	email, _ := claims[p.Attribute("email")].(string)
	if sub == "" || !strings.Contains(email, "@") {
		return Identity{}, refuse(ReasonAssertionInvalid, "id_token carries no subject or email")
	}
	name, _ := claims[p.Attribute("name")].(string)
	return Identity{Subject: sub, Email: strings.ToLower(strings.TrimSpace(email)), Name: name, Attributes: claims}, nil
}

// EndSessionURL implements OIDC.
func (o *HTTPOIDC) EndSessionURL(ctx context.Context, p Provider, postLogoutRedirectURI string) string {
	d, err := o.discover(ctx, p, false)
	if err != nil || d.EndSessionEndpoint == "" {
		return ""
	}
	query := [][2]string{{"client_id", p.Setting("client_id")}}
	if postLogoutRedirectURI != "" {
		query = append(query, [2]string{"post_logout_redirect_uri", postLogoutRedirectURI})
	}
	return withQuery(d.EndSessionEndpoint, query)
}

// Check implements OIDC: the client id, then discovery and the JWKS fetched fresh.
func (o *HTTPOIDC) Check(ctx context.Context, p Provider) []string {
	problems := []string{}
	if p.Setting("client_id") == "" {
		problems = append(problems, "client_id is not set")
	}
	d, err := o.discover(ctx, p, true)
	if err == nil {
		_, err = o.keySet(ctx, d.JWKSURI, true)
	}
	if err != nil {
		problems = append(problems, rejected(err).Detail)
	}
	return problems
}

func (o *HTTPOIDC) discover(ctx context.Context, p Provider, fresh bool) (discovery, error) {
	issuer := p.Setting("issuer")
	if issuer == "" {
		issuer = p.Issuer
	}
	key := "polaris.sso.oidc.discovery." + digest(issuer)
	var d discovery
	if !fresh {
		if raw, ok, err := o.Cache.Get(ctx, key); err == nil && ok && json.Unmarshal(raw, &d) == nil && d.Issuer != "" {
			return d, nil
		}
	}
	var doc map[string]any
	if err := o.getJSON(ctx, strings.TrimRight(issuer, "/")+"/.well-known/openid-configuration", "discovery", &doc); err != nil {
		return d, err
	}
	for _, required := range []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if s, _ := doc[required].(string); s == "" {
			return d, refuse(ReasonAssertionInvalid, "discovery document lacks "+required)
		}
	}
	// OpenID Connect Discovery §4.3: the document must be the configured issuer's own, or whoever
	// serves that URL could name another issuer's endpoints and keys.
	if strings.TrimRight(doc["issuer"].(string), "/") != strings.TrimRight(issuer, "/") {
		return d, refuse(ReasonAssertionInvalid, "discovery document is for another issuer")
	}
	d.Issuer, d.AuthorizationEndpoint, d.TokenEndpoint, d.JWKSURI = doc["issuer"].(string), doc["authorization_endpoint"].(string), doc["token_endpoint"].(string), doc["jwks_uri"].(string)
	d.EndSessionEndpoint, _ = doc["end_session_endpoint"].(string)
	if raw, err := json.Marshal(d); err == nil {
		_ = o.Cache.Set(ctx, key, raw, oidcCacheTTL)
	}
	return d, nil
}

// keySet is the provider's keys, cached an hour (fetched again when fresh).
func (o *HTTPOIDC) keySet(ctx context.Context, jwksURI string, fresh bool) (jose.JSONWebKeySet, error) {
	key := "polaris.sso.oidc.jwks." + digest(jwksURI)
	var set jose.JSONWebKeySet
	if !fresh {
		if raw, ok, err := o.Cache.Get(ctx, key); err == nil && ok && json.Unmarshal(raw, &set) == nil && len(set.Keys) > 0 {
			return set, nil
		}
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := o.getJSON(ctx, jwksURI, "JWKS", &doc); err != nil {
		return set, err
	}
	for _, raw := range doc.Keys {
		var k jose.JSONWebKey
		if k.UnmarshalJSON(raw) == nil {
			set.Keys = append(set.Keys, k)
		}
	}
	if len(set.Keys) == 0 {
		return set, refuse(ReasonAssertionInvalid, "the JWKS carries no keys")
	}
	if raw, err := json.Marshal(set); err == nil {
		_ = o.Cache.Set(ctx, key, raw, oidcCacheTTL)
	}
	return set, nil
}

func (o *HTTPOIDC) getJSON(ctx context.Context, rawURL, what string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return refuse(ReasonAssertionInvalid, what+" unreachable: "+err.Error())
	}
	req.Header.Set("Accept", "application/json")
	return o.send(req, what, into)
}

// send answers the decoded JSON object of a 200, else an *Error naming what answered what.
func (o *HTTPOIDC) send(req *http.Request, what string, into any) error {
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return refuse(ReasonAssertionInvalid, what+" unreachable: "+err.Error())
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBytes))
	trimmed := bytes.TrimSpace(body)
	if err != nil || resp.StatusCode != http.StatusOK || !bytes.HasPrefix(trimmed, []byte("{")) || json.Unmarshal(trimmed, into) != nil {
		return refuse(ReasonAssertionInvalid, fmt.Sprintf("%s answered %d", what, resp.StatusCode))
	}
	return nil
}

// claims verifies the id_token and returns its claims.
func (o *HTTPOIDC) claims(ctx context.Context, p Provider, d discovery, idToken, nonce string) (map[string]any, error) {
	var claims map[string]any
	for _, fresh := range []bool{false, true} {
		set, err := o.keySet(ctx, d.JWKSURI, fresh)
		if err != nil {
			return nil, err
		}
		claims, err = verifyIDToken(idToken, set.Keys, o.Clock.Now())
		if err == nil {
			break
		}
		if _, unknown := errors.AsType[errUnknownKey](err); fresh || !unknown {
			return nil, refuse(ReasonAssertionInvalid, "id_token rejected: "+err.Error())
		}
	}
	if claims["iss"] != d.Issuer {
		return nil, refuse(ReasonAssertionInvalid, "id_token issuer mismatch")
	}
	if !audienceHas(claims["aud"], p.Setting("client_id")) {
		return nil, refuse(ReasonAssertionInvalid, "id_token audience mismatch")
	}
	claimed, _ := claims["nonce"].(string)
	if claimed == "" || !hmac.Equal([]byte(claimed), []byte(nonce)) {
		return nil, refuse(ReasonAssertionInvalid, "id_token nonce mismatch")
	}
	return claims, nil
}

func audienceHas(aud any, clientID string) bool {
	switch a := aud.(type) {
	case string:
		return a == clientID
	case []any:
		return slices.Contains(a, any(clientID))
	}
	return false
}

// errUnknownKey is a kid the key set lacks: perhaps a rotated key, worth one fresh fetch.
type errUnknownKey struct{ msg string }

func (e errUnknownKey) Error() string { return e.msg }

// algorithmOf is the algorithm a key verifies: its alg or, for a key without one, the algorithm
// its type implies (RSA RS256, EC P-256 ES256, OKP Ed25519 EdDSA). Any other key without alg
// verifies nothing: guessing would let one key serve algorithms it was not published for.
func algorithmOf(k jose.JSONWebKey) (string, error) {
	if k.Algorithm != "" {
		return k.Algorithm, nil
	}
	switch key := k.Key.(type) {
	case *rsa.PublicKey:
		return string(jose.RS256), nil
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() {
			return string(jose.ES256), nil
		}
	case ed25519.PublicKey:
		return string(jose.EdDSA), nil
	}
	return "", errors.New("the key names no alg and its type implies none")
}

// verifyIDToken verifies an ID token against a key set: a compact JWS whose kid names a key
// verifying the header's algorithm (algorithmOf), a valid signature, a JSON object payload, and
// an exp (required) and nbf / iat / exp within a minute of leeway.
func verifyIDToken(raw string, keys []jose.JSONWebKey, now time.Time) (map[string]any, error) {
	jws, err := jose.ParseSignedCompact(raw, idTokenAlgorithms)
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("one signature expected")
	}
	h := jws.Signatures[0].Header
	if h.KeyID == "" {
		return nil, errors.New("the token names no key (kid)")
	}
	i := slices.IndexFunc(keys, func(k jose.JSONWebKey) bool { return k.KeyID == h.KeyID })
	if i < 0 {
		return nil, errUnknownKey{"no key in the key set has the token's kid"}
	}
	alg, err := algorithmOf(keys[i])
	if err != nil {
		return nil, err
	}
	if alg != h.Algorithm {
		return nil, errors.New("the key's algorithm is not the token's (alg)")
	}
	payload, err := jws.Verify(keys[i].Key)
	if err != nil {
		return nil, errors.New("the signature does not verify")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, errors.New("the claims are not a JSON object")
	}
	ts := float64(now.Unix())
	times := map[string]float64{}
	for _, c := range []string{"nbf", "iat", "exp"} {
		if claims[c] == nil {
			continue
		}
		n, ok := claims[c].(json.Number)
		f, err := n.Float64()
		if !ok || err != nil {
			return nil, fmt.Errorf("payload %s must be a number", c)
		}
		times[c] = f
	}
	nbf, hasNbf := times["nbf"]
	if hasNbf && math.Floor(nbf) > ts+idTokenLeeway {
		return nil, errors.New("the token is not valid yet (nbf)")
	}
	if iat, ok := times["iat"]; ok && !hasNbf && math.Floor(iat) > ts+idTokenLeeway {
		return nil, errors.New("the token was issued in the future (iat)")
	}
	exp, ok := times["exp"]
	if !ok {
		return nil, errors.New("the token has no expiry (exp)") // required: OpenID Connect Core §2
	}
	if ts-idTokenLeeway >= exp {
		return nil, errors.New("the token has expired")
	}
	return claims, nil
}

// withQuery appends members to a URL that may carry a query already, in order.
func withQuery(base string, members [][2]string) string {
	parts := make([]string, len(members))
	for i, m := range members {
		parts[i] = url.QueryEscape(m[0]) + "=" + url.QueryEscape(m[1])
	}
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + strings.Join(parts, "&")
}

// digest names a cache entry after a URL or a secret.
func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
