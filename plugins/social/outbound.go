package social

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
)

// outbound is what the providers share: the HTTP client (no redirects), the cache for discovery
// documents and key sets, the clock.
type outbound struct {
	http  *http.Client
	cache cache.Cache
	clock clock.Clock
}

const (
	maxProviderBody = 1 << 20
	idTokenLeeway   = 60 // seconds
)

// idTokenAlgorithms are the signatures an id_token may carry (upstream's list).
var idTokenAlgorithms = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.ES256, jose.ES384, jose.ES512}

// postForm POSTs a form to a token endpoint and decodes the answer.
func (o *outbound) postForm(ctx context.Context, endpoint string, form url.Values, header http.Header) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, refuse(kindProviderError, "the token endpoint is not a URL")
	}
	req.Header = header.Clone()
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return o.send(req, "the token endpoint")
}

// getJSON fetches a JSON document (with a bearer when given).
func (o *outbound) getJSON(ctx context.Context, method, endpoint, bearer string, headers map[string]string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return nil, refuse(kindProviderError, endpoint+" is not a URL")
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	return o.send(req, endpoint)
}

// send answers the decoded body: JSON, or a form-encoded body (GitHub without the Accept header).
// An HTTP error or an empty answer is a provider error naming what the provider said.
func (o *outbound) send(req *http.Request, what string) (any, error) {
	resp, err := o.http.Do(req)
	if err != nil {
		return nil, refuse(kindProviderError, fmt.Sprintf("%s could not be reached: %v", what, err))
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderBody))
	if err != nil {
		return nil, refuse(kindProviderError, fmt.Sprintf("%s could not be read: %v", what, err))
	}
	decoded := decodeBody(body)
	if resp.StatusCode >= 400 {
		m, _ := decoded.(map[string]any)
		said := or(or(str(m["error_description"]), str(m["error"])), str(m["message"]))
		if said != "" {
			said = ": " + truncate(said, 200)
		}
		return nil, refuse(kindProviderError, fmt.Sprintf("%s answered HTTP %d%s", what, resp.StatusCode, said))
	}
	if empty(decoded) {
		return nil, refuse(kindProviderError, what+" answered no JSON")
	}
	return decoded, nil
}

func decodeBody(body []byte) any {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) == nil {
		switch v.(type) {
		case map[string]any, []any:
			return v
		}
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	for k, vs := range values {
		out[k] = vs[len(vs)-1]
	}
	return out
}

func empty(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		return len(v) == 0
	case []any:
		return len(v) == 0
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// discovery is an Issuer-configured provider's definition from its discovery document.
type discovery struct {
	issuer, name string
	scopes       []string
}

func (d *discovery) definition(ctx context.Context, o *outbound) (Definition, error) {
	doc, err := o.cachedJSON(ctx, "polaris.social.discovery."+digest(d.issuer)+".document", d.issuer+"/.well-known/openid-configuration")
	if err != nil {
		return Definition{}, err
	}
	authz, _ := doc["authorization_endpoint"].(string)
	tok, _ := doc["token_endpoint"].(string)
	if authz == "" || tok == "" {
		return Definition{}, refuse(kindProviderError, fmt.Sprintf("the discovery document of %q names no authorization_endpoint or token_endpoint", d.issuer))
	}
	scopes := d.scopes
	if scopes == nil {
		scopes = []string{"openid", "email", "profile"}
	}
	def := Definition{Name: d.name, AuthorizationURL: authz, TokenURL: tok, Scopes: scopes, Profile: OIDCProfile, Issuer: d.issuer}
	def.UserinfoURL, _ = doc["userinfo_endpoint"].(string)
	def.JWKSURL, _ = doc["jwks_uri"].(string)
	if iss, ok := doc["issuer"].(string); ok {
		def.Issuer = iss
	}
	return def, nil
}

// cachedJSON fetches a JSON object, cached an hour under key.
func (o *outbound) cachedJSON(ctx context.Context, key, endpoint string) (map[string]any, error) {
	if raw, ok, err := o.cache.Get(ctx, key); err == nil && ok {
		if m, isMap := decodeBody(raw).(map[string]any); isMap && len(m) > 0 {
			return m, nil
		}
	}
	v, err := o.getJSON(ctx, http.MethodGet, endpoint, "", nil)
	if err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	if raw, err := json.Marshal(m); err == nil {
		_ = o.cache.Set(ctx, key, raw, keySetTTL)
	}
	return m, nil
}

// verifyIDToken returns the claims of a valid id_token: signed by a key of the provider's set
// (fetched again once for an unknown kid), within its times (a minute of leeway), from the
// provider's issuer, for this client, with the nonce when one is expected.
func (o *outbound) verifyIDToken(ctx context.Context, def Definition, clientID, raw string, nonce *string) (map[string]any, error) {
	jwksURL, err := o.jwksURL(ctx, def)
	if err != nil {
		return nil, err
	}
	claims, err := o.decode(ctx, jwksURL, raw)
	if err != nil {
		return nil, err
	}
	iss, _ := claims["iss"].(string)
	issuerOK := iss == def.Issuer || iss == strings.TrimRight(def.Issuer, "/")
	if def.IssuerPattern != nil {
		issuerOK = def.IssuerPattern.MatchString(iss)
	}
	if !issuerOK {
		return nil, refuse(kindTokenInvalid, "the id_token issuer is not the provider's")
	}
	if !audienceHas(claims["aud"], clientID) {
		return nil, refuse(kindTokenInvalid, "the id_token is not for this client")
	}
	if nonce != nil {
		claimed, _ := claims["nonce"].(string)
		if !hmac.Equal([]byte(*nonce), []byte(claimed)) || claimed == "" {
			return nil, refuse(kindTokenInvalid, "the id_token nonce does not match")
		}
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

func (o *outbound) jwksURL(ctx context.Context, def Definition) (string, error) {
	if def.JWKSURL != "" {
		return def.JWKSURL, nil
	}
	issuer := strings.TrimRight(def.Issuer, "/")
	key := "polaris.social.discovery." + digest(issuer)
	if raw, ok, err := o.cache.Get(ctx, key); err == nil && ok && len(raw) > 0 {
		return string(raw), nil
	}
	v, err := o.getJSON(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", "", nil)
	if err != nil {
		return "", err
	}
	uri, _ := at(v, "jwks_uri").(string)
	if uri == "" {
		return "", refuse(kindProviderError, "the discovery document names no jwks_uri")
	}
	_ = o.cache.Set(ctx, key, []byte(uri), keySetTTL)
	return uri, nil
}

// errUnknownKey is a kid the key set lacks: perhaps a rotated key, worth one fresh fetch.
type errUnknownKey struct{ msg string }

func (e errUnknownKey) Error() string { return e.msg }

func (o *outbound) decode(ctx context.Context, jwksURL, raw string) (map[string]any, error) {
	for _, fresh := range []bool{false, true} {
		keys, err := o.keySet(ctx, jwksURL, fresh)
		if err != nil {
			return nil, err
		}
		claims, err := verifyJWT(raw, keys, o.clock.Now())
		if err == nil {
			return claims, nil
		}
		if _, unknown := err.(errUnknownKey); fresh || !unknown {
			return nil, refuse(kindTokenInvalid, "the id_token does not verify: "+err.Error())
		}
	}
	return nil, refuse(kindTokenInvalid, "the id_token does not verify")
}

// keySet is the provider's keys, cached an hour (or fetched again when fresh).
func (o *outbound) keySet(ctx context.Context, jwksURL string, fresh bool) ([]jose.JSONWebKey, error) {
	key := "polaris.social.jwks." + digest(jwksURL)
	var doc map[string]any
	if !fresh {
		if raw, ok, err := o.cache.Get(ctx, key); err == nil && ok {
			doc, _ = decodeBody(raw).(map[string]any)
		}
	}
	if list, _ := at(doc, "keys").([]any); len(list) == 0 {
		v, err := o.getJSON(ctx, http.MethodGet, jwksURL, "", nil)
		if err != nil {
			return nil, err
		}
		doc, _ = v.(map[string]any)
		if list, _ := at(doc, "keys").([]any); len(list) == 0 {
			return nil, refuse(kindProviderError, "the key set carries no keys")
		}
		if raw, err := json.Marshal(doc); err == nil {
			_ = o.cache.Set(ctx, key, raw, keySetTTL)
		}
	}
	var keys []jose.JSONWebKey
	for _, k := range doc["keys"].([]any) {
		raw, err := json.Marshal(k)
		var jwk jose.JSONWebKey
		if err == nil && jwk.UnmarshalJSON(raw) == nil {
			keys = append(keys, jwk)
		}
	}
	return keys, nil
}

// verifyJWT is firebase/php-jwt's decode against a key set: a compact JWS whose kid names a key
// of the set of the header's algorithm (a key without alg is RS256), a valid signature, a JSON
// object payload, and nbf / iat / exp within a minute of leeway.
func verifyJWT(raw string, keys []jose.JSONWebKey, now time.Time) (map[string]any, error) {
	jws, err := jose.ParseSigned(raw, idTokenAlgorithms)
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, fmt.Errorf("one signature expected")
	}
	h := jws.Signatures[0].Header
	if h.KeyID == "" {
		return nil, errUnknownKey{`"kid" empty, unable to lookup correct key`}
	}
	var key *jose.JSONWebKey
	for i := range keys {
		if keys[i].KeyID == h.KeyID {
			key = &keys[i]
			break
		}
	}
	if key == nil {
		return nil, errUnknownKey{`"kid" invalid, unable to lookup correct key`}
	}
	alg := key.Algorithm
	if alg == "" {
		alg = string(jose.RS256)
	}
	if alg != h.Algorithm {
		return nil, fmt.Errorf("incorrect key for this algorithm")
	}
	payload, err := jws.Verify(key.Key)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var claims map[string]any
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, fmt.Errorf("the payload is not a JSON object")
	}
	for _, c := range []string{"nbf", "iat", "exp"} {
		if _, ok := number(claims[c]); claims[c] != nil && !ok {
			return nil, fmt.Errorf("payload %s must be a number", c)
		}
	}
	ts := float64(now.Unix())
	nbf, hasNbf := number(claims["nbf"])
	if hasNbf && math.Floor(nbf) > ts+idTokenLeeway {
		return nil, fmt.Errorf("cannot handle token prior to its nbf")
	}
	if iat, ok := number(claims["iat"]); !hasNbf && ok && math.Floor(iat) > ts+idTokenLeeway {
		return nil, fmt.Errorf("cannot handle token prior to its iat")
	}
	if exp, ok := number(claims["exp"]); ok && ts-idTokenLeeway >= exp {
		return nil, fmt.Errorf("expired token")
	}
	return claims, nil
}

func number(v any) (float64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	return f, err == nil
}

// digest names a cache entry after a URL or an issuer.
func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func basic(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + password))
}
