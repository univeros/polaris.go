package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/univeros/polaris.go/wiring"
	"log/slog"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

const (
	clientPepper   = "oauth_client"
	secretPrefix   = "pcs_"
	metadataCache  = "polaris.oauth.cimd."
	jwksCache      = "polaris.oauth.jwks."
	assertionCache = "polaris.oauth.assertion."
	metadataTTL    = time.Hour
	// AssertionType is the client_assertion_type of a private_key_jwt assertion.
	AssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// ClientFields are a client's registration metadata under their wire names: name, type,
// redirect_uris, grant_types, scopes (or scope, space-separated, when creating),
// token_endpoint_auth_method, jwks, jwks_uri, dpop_bound_access_tokens, trusted, logo_uri,
// client_uri, policy_uri, tos_uri, and disabled (update only). Values are as JSON decodes them
// ([]any or []string for lists, map[string]any for jwks). A key left out keeps its value on update
// and takes its default on create.
type ClientFields map[string]any

// IssuedClient is a freshly registered client and its secret, shown exactly once ("" for a public
// client or one that authenticates with a key).
type IssuedClient struct {
	Client Client
	Secret string
}

// LogValue keeps the secret out of logs.
func (i IssuedClient) LogValue() slog.Value {
	return slog.GroupValue(slog.String("client_id", i.Client.ClientID))
}

// credentials is how a request identifies its client.
type credentials struct {
	clientID, secret         string
	basic                    bool
	assertion, assertionType string
}

// clients holds the registered clients and the metadata-document ones.
type clients struct {
	db       store.Adapter
	pepper   wiring.Pepper
	scopes   *scopes
	settings settings
	cache    cache.Cache
	once     *onceGuard
	clock    clock.Clock
	log      *slog.Logger
}

// find returns the client a client_id names: a registered one, or the one its https metadata
// document describes; nil when unknown.
func (s *clients) find(ctx context.Context, clientID string) (*Client, error) {
	row, err := s.db.FindOne(ctx, TableClients, store.Criteria{"client_id": clientID})
	if err != nil {
		return nil, err
	}
	if row != nil {
		c := clientFromRow(row)
		return &c, nil
	}
	if len(clientID) > 8 && clientID[:8] == "https://" {
		return s.fromMetadata(ctx, clientID)
	}
	return nil, nil
}

func (s *clients) findByID(ctx context.Context, id string) (*Client, error) {
	row, err := s.db.FindOne(ctx, TableClients, store.Criteria{"id": id})
	if err != nil || row == nil {
		return nil, err
	}
	c := clientFromRow(row)
	return &c, nil
}

// list returns the clients matching c, by id.
func (s *clients) list(ctx context.Context, c store.Criteria) ([]Client, error) {
	rows, err := s.db.FindMany(ctx, TableClients, c, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, err
	}
	out := make([]Client, 0, len(rows))
	for _, r := range rows {
		out = append(out, clientFromRow(r))
	}
	return out, nil
}

// create registers a client; mayTrust honours trusted (operators) instead of ignoring it.
func (s *clients) create(ctx context.Context, fields ClientFields, organizationID, createdBy string, mayTrust bool) (IssuedClient, error) {
	now := s.clock.Now()
	c := Client{
		ID: repository.NewID(), ClientID: repository.NewID(), OrganizationID: organizationID,
		CreatedBy: createdBy, CreatedAt: now, UpdatedAt: now,
	}
	c, err := s.apply(c, fields, mayTrust, true)
	if err != nil {
		return IssuedClient{}, err
	}
	var secret string
	if c.TokenEndpointAuthMethod == AuthSecretBasic || c.TokenEndpointAuthMethod == AuthSecretPost {
		buf := make([]byte, 32)
		_, _ = rand.Read(buf)
		secret = secretPrefix + b64(buf)
		c.secretHash = s.pepper.Hash(clientPepper, secret)
	}
	row, err := c.row()
	if err != nil {
		return IssuedClient{}, err
	}
	if err := s.db.Insert(ctx, TableClients, row); err != nil {
		return IssuedClient{}, err
	}
	return IssuedClient{Client: c, Secret: secret}, nil
}

// update changes a registered client and returns it with the names of what changed.
func (s *clients) update(ctx context.Context, c Client, fields ClientFields, mayTrust bool) (Client, []string, error) {
	if c.IsMetadataClient() {
		return c, nil, refusal(CodeInvalidRequest, "A client described by its metadata document is not managed here.")
	}
	next, err := s.apply(c, fields, mayTrust, false)
	if err != nil {
		return c, nil, err
	}
	next.UpdatedAt = s.clock.Now()
	before, after := c.view(), next.view()
	changes := []string{}
	for _, key := range sortedKeys(after) {
		if key != "updated_at" && !reflect.DeepEqual(before[key], after[key]) {
			changes = append(changes, key)
		}
	}
	row, err := next.row()
	if err != nil {
		return c, nil, err
	}
	if _, err := s.db.Update(ctx, TableClients, store.Criteria{"id": c.ID}, store.Data(row)); err != nil {
		return c, nil, err
	}
	return next, changes, nil
}

func (s *clients) delete(ctx context.Context, c Client) error {
	_, err := s.db.Delete(ctx, TableClients, store.Criteria{"id": c.ID})
	return err
}

// authenticate returns the client the credentials authenticate, by the method it registered
// with; audience is the endpoint URL a signed assertion may name instead of the issuer.
func (s *clients) authenticate(ctx context.Context, cr credentials, audience, issuer string) (*Client, error) {
	if cr.assertion != "" {
		return s.authenticateByAssertion(ctx, cr, audience, issuer)
	}
	if cr.clientID == "" {
		return nil, unauthorizedClient("client_id is required.")
	}
	c, err := s.find(ctx, cr.clientID)
	if err != nil {
		return nil, err
	}
	if c == nil || c.DisabledAt != nil {
		return nil, unauthorizedClient("Unknown client.")
	}
	method := c.TokenEndpointAuthMethod
	if cr.secret != "" {
		expected := AuthSecretPost
		if cr.basic {
			expected = AuthSecretBasic
		}
		matches := c.secretHash != "" && s.pepper.Matches(clientPepper, cr.secret, c.secretHash)
		if method != expected || !matches {
			return nil, unauthorizedClient("The client secret does not match, or the client does not authenticate this way.")
		}
		return c, nil
	}
	if method != AuthNone {
		return nil, unauthorizedClient("The client must authenticate with " + method + ".")
	}
	return c, nil
}

// authenticateByAssertion verifies a private_key_jwt assertion (RFC 7523) against the client's
// keys: the client as iss and sub, the endpoint or the issuer as aud, exp, and a jti used once.
func (s *clients) authenticateByAssertion(ctx context.Context, cr credentials, audience, issuer string) (*Client, error) {
	if cr.assertionType != AssertionType {
		return nil, unauthorizedClient("client_assertion_type must be " + AssertionType + ".")
	}
	header := JWTHeader(cr.assertion)
	iss, _ := jwtPayload(cr.assertion)["iss"].(string)
	if header == nil || iss == "" || (cr.clientID != "" && cr.clientID != iss) {
		return nil, unauthorizedClient("The client assertion is not a JWT naming the client as its issuer.")
	}
	c, err := s.find(ctx, iss)
	if err != nil {
		return nil, err
	}
	if c == nil || c.DisabledAt != nil || c.TokenEndpointAuthMethod != AuthPrivateKeyJWT {
		return nil, unauthorizedClient("Unknown client, or one that does not authenticate with a key.")
	}
	alg, _ := header["alg"].(string)
	if !slices.Contains(asymmetricAlgorithms, alg) {
		return nil, unauthorizedClient("The assertion must be signed with an asymmetric algorithm.")
	}
	set, err := s.keySet(ctx, *c)
	if err != nil {
		return nil, err
	}
	now := s.clock.Now()
	claims, err := verifyWithKeySet(cr.assertion, header, alg, set, now)
	if err != nil {
		return nil, unauthorizedClient("The client assertion does not verify: " + err.Error())
	}
	exp, expOK := integer(claims["exp"])
	if claims["sub"] != iss || !audienceIncludes(claims["aud"], audience, issuer) || !expOK {
		return nil, unauthorizedClient("The client assertion needs sub = the client, aud = this endpoint or issuer, and exp.")
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, unauthorizedClient("The client assertion needs a jti, and one not used before.")
	}
	sum := sha256.Sum256([]byte(iss + "|" + jti))
	ttl := min(600, max(60, exp-now.Unix()+60))
	fresh, err := s.once.claim(ctx, assertionCache+hex.EncodeToString(sum[:]), time.Duration(ttl)*time.Second)
	if err != nil {
		return nil, err
	}
	if !fresh {
		return nil, unauthorizedClient("The client assertion needs a jti, and one not used before.")
	}
	return c, nil
}

// audienceIncludes reports whether aud (a string or a list) names one of want.
func audienceIncludes(aud any, want ...string) bool {
	list, ok := aud.([]any)
	if !ok {
		list = []any{aud}
	}
	for _, a := range list {
		if s, ok := a.(string); ok && slices.Contains(want, s) {
			return true
		}
	}
	return false
}

// verifyWithKeySet picks the key the header's kid names (a key without kid is named by its
// index), as firebase/php-jwt does, and verifies the assertion with a minute of leeway.
func verifyWithKeySet(raw string, header map[string]any, alg string, set []any, now time.Time) (map[string]any, error) {
	if len(set) == 0 {
		return nil, errors.New("JWK Set did not contain any keys")
	}
	kid, _ := header["kid"].(string)
	if kid == "" {
		return nil, errors.New(`"kid" empty, unable to lookup correct key`)
	}
	for i, entry := range set {
		m, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		name, ok := m["kid"].(string)
		if !ok {
			name = fmt.Sprint(i)
		}
		if name != kid {
			continue
		}
		if ka, ok := m["alg"].(string); ok && ka != alg {
			return nil, errors.New("Incorrect key for this algorithm")
		}
		key, err := parseJWK(m)
		if err != nil {
			return nil, errors.New("the key could not be read")
		}
		return verifySigned(raw, alg, key, now, time.Minute)
	}
	return nil, errors.New(`"kid" invalid, unable to lookup correct key`)
}

// keySet is the client's keys: inline, or fetched from its jwks_uri and cached for an hour.
func (s *clients) keySet(ctx context.Context, c Client) ([]any, error) {
	if keys := jwksKeys(c.JWKS); keys != nil {
		return keys, nil
	}
	if err := assertPublicHTTPSURL(c.JWKSURI, "jwks_uri"); err != nil {
		return nil, err
	}
	key := jwksCache + hashHex(c.JWKSURI)
	if cached, found, err := s.cache.Get(ctx, key); err == nil && found {
		var doc map[string]any
		if json.Unmarshal(cached, &doc) == nil {
			if keys := jwksKeys(doc); keys != nil {
				return keys, nil
			}
		}
	}
	doc, err := fetchJSON(ctx, s.settings.httpClient, s.log, c.JWKSURI, CodeInvalidClient)
	if err != nil {
		return nil, err
	}
	keys := jwksKeys(doc)
	if keys == nil {
		return nil, unauthorizedClient("jwks_uri did not answer a JWK Set.")
	}
	if raw, err := json.Marshal(doc); err == nil {
		_ = s.cache.Set(ctx, key, raw, metadataTTL)
	}
	return keys, nil
}

// jwksKeys is the keys member of a JWK Set (a list, or an object as PHP's array), nil without one.
func jwksKeys(set map[string]any) []any {
	switch keys := set["keys"].(type) {
	case []any:
		return keys
	case map[string]any:
		out := make([]any, 0, len(keys))
		for _, k := range sortedKeys(keys) {
			out = append(out, keys[k])
		}
		return out
	}
	return nil
}

// fromMetadata is the client a metadata document at url describes (the MCP 2026 profile):
// fetched over HTTPS from a public host, validated, cached for an hour once it validated.
func (s *clients) fromMetadata(ctx context.Context, url string) (*Client, error) {
	if !s.settings.clientIDMetadata {
		return nil, unauthorizedClient("Client ID metadata documents are not accepted here.")
	}
	if err := assertPublicHTTPSURL(url, "A client ID metadata URL"); err != nil {
		return nil, err
	}
	key := metadataCache + hashHex(url)
	var doc map[string]any
	if cached, found, err := s.cache.Get(ctx, key); err == nil && found {
		_ = json.Unmarshal(cached, &doc)
	}
	fetched := doc == nil
	if fetched {
		var err error
		if doc, err = fetchJSON(ctx, s.settings.httpClient, s.log, url, CodeInvalidClientMetadata); err != nil {
			return nil, err
		}
		if doc["client_id"] != url {
			return nil, refusal(CodeInvalidClientMetadata, "The document's client_id must be its own URL.")
		}
	}
	now := s.clock.Now()
	fields := ClientFields{"name": url}
	if name, ok := doc["client_name"]; ok && name != nil {
		fields["name"] = name
	}
	for k, v := range doc {
		fields[k] = v
	}
	delete(fields, "client_id")
	delete(fields, "client_name")
	delete(fields, "trusted")
	method, ok := doc["token_endpoint_auth_method"]
	if !ok || method == nil {
		method = AuthNone
	}
	fields["type"] = TypeConfidential
	if method == AuthNone {
		fields["type"] = TypePublic
	}
	fields["token_endpoint_auth_method"] = method
	c, err := s.apply(Client{ClientID: url, CreatedAt: now, UpdatedAt: now}, fields, false, true)
	if err != nil {
		var oe *Error
		if errors.As(err, &oe) {
			return nil, refusal(CodeInvalidClientMetadata, oe.Description)
		}
		return nil, err
	}
	if c.TokenEndpointAuthMethod != AuthNone && c.TokenEndpointAuthMethod != AuthPrivateKeyJWT {
		return nil, refusal(CodeInvalidClientMetadata, "A metadata client authenticates with none or private_key_jwt.")
	}
	if fetched {
		if raw, err := json.Marshal(doc); err == nil {
			_ = s.cache.Set(ctx, key, raw, metadataTTL)
		}
	}
	return &c, nil
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// clientCredentials reads how a request identifies its client: client_id and client_secret in the
// body, HTTP Basic (which wins), a signed assertion.
func clientCredentials(r *http.Request, body map[string]any) credentials {
	text := func(k string) string { v, _ := body[k].(string); return v }
	cr := credentials{
		clientID: text("client_id"), secret: text("client_secret"),
		assertion: text("client_assertion"), assertionType: text("client_assertion_type"),
	}
	if id, secret, ok := basicAuth(r.Header.Get("Authorization")); ok {
		cr.clientID, cr.secret, cr.basic = id, secret, true
	}
	return cr
}
