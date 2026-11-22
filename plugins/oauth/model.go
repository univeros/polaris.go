package oauth

import (
	"slices"
	"time"

	"github.com/univeros/polaris.go/store"
)

// Client types and token endpoint authentication methods.
const (
	TypeConfidential = "confidential"
	TypePublic       = "public"

	AuthSecretBasic   = "client_secret_basic"
	AuthSecretPost    = "client_secret_post"
	AuthPrivateKeyJWT = "private_key_jwt"
	AuthNone          = "none"
)

// The grant types a client may be registered for.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantCIBA              = "urn:openid:params:grant-type:ciba"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange"
)

var (
	allGrants      = []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials, GrantDeviceCode, GrantCIBA, GrantTokenExchange}
	allAuthMethods = []string{AuthSecretBasic, AuthSecretPost, AuthPrivateKeyJWT, AuthNone}
	// asymmetricAlgorithms are the JWS algorithms accepted for client assertions and DPoP proofs.
	asymmetricAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"}
)

// Client is a registered OAuth client (polaris_oauth_client), or one described by its client ID
// metadata document (ID empty, nothing stored). Optional strings are "" when unset (NULL).
type Client struct {
	ID                      string
	ClientID                string
	OrganizationID          string
	Name                    string
	Type                    string
	RedirectURIs            []string
	GrantTypes              []string
	Scopes                  []string // empty: any scope the server knows
	TokenEndpointAuthMethod string
	JWKS                    map[string]any // nil: none
	JWKSURI                 string
	DPoPBound               bool
	Trusted                 bool
	LogoURI                 string
	ClientURI               string
	PolicyURI               string
	TosURI                  string
	CreatedBy               string
	DisabledAt              *time.Time
	CreatedAt               time.Time
	UpdatedAt               time.Time

	secretHash string
}

// IsMetadataClient reports whether the client is known by its metadata document.
func (c Client) IsMetadataClient() bool { return c.ID == "" }

// AllowsGrant reports whether the client is registered for grant.
func (c Client) AllowsGrant(grant string) bool { return slices.Contains(c.GrantTypes, grant) }

// AllowsRedirect reports whether uri is exactly one of the client's redirect URIs.
func (c Client) AllowsRedirect(uri string) bool { return slices.Contains(c.RedirectURIs, uri) }

// view is the client's record as the management routes answer it.
func (c Client) view() map[string]any {
	return map[string]any{
		"id":                         c.ID,
		"client_id":                  c.ClientID,
		"organization_id":            null(c.OrganizationID),
		"name":                       c.Name,
		"type":                       c.Type,
		"redirect_uris":              list(c.RedirectURIs),
		"grant_types":                list(c.GrantTypes),
		"scopes":                     list(c.Scopes),
		"token_endpoint_auth_method": c.TokenEndpointAuthMethod,
		"jwks":                       jwksValue(c.JWKS),
		"jwks_uri":                   null(c.JWKSURI),
		"dpop_bound_access_tokens":   c.DPoPBound,
		"trusted":                    c.Trusted,
		"logo_uri":                   null(c.LogoURI),
		"client_uri":                 null(c.ClientURI),
		"policy_uri":                 null(c.PolicyURI),
		"tos_uri":                    null(c.TosURI),
		"created_by":                 null(c.CreatedBy),
		"disabled_at":                timestampPtr(c.DisabledAt),
		"created_at":                 timestamp(c.CreatedAt),
		"updated_at":                 timestamp(c.UpdatedAt),
	}
}

// publicView is what a consent screen or a device page shows about the client.
func (c Client) publicView() map[string]any {
	return map[string]any{
		"client_id":  c.ClientID,
		"name":       c.Name,
		"logo_uri":   null(c.LogoURI),
		"client_uri": null(c.ClientURI),
		"policy_uri": null(c.PolicyURI),
		"tos_uri":    null(c.TosURI),
		"trusted":    c.Trusted,
	}
}

func (c Client) row() (store.Row, error) {
	redirects, err := store.JSONValue(list(c.RedirectURIs))
	if err != nil {
		return nil, err
	}
	grants, err := store.JSONValue(list(c.GrantTypes))
	if err != nil {
		return nil, err
	}
	scopes, err := store.JSONValue(list(c.Scopes))
	if err != nil {
		return nil, err
	}
	var jwks any
	if c.JWKS != nil {
		if jwks, err = store.JSONValue(c.JWKS); err != nil {
			return nil, err
		}
	}
	return store.Row{
		"id": c.ID, "client_id": c.ClientID, "organization_id": null(c.OrganizationID), "name": c.Name,
		"type": c.Type, "secret_hash": null(c.secretHash), "redirect_uris": redirects, "grant_types": grants,
		"scopes": scopes, "token_endpoint_auth_method": c.TokenEndpointAuthMethod, "jwks": jwks,
		"jwks_uri": null(c.JWKSURI), "dpop_bound": c.DPoPBound, "trusted": c.Trusted,
		"logo_uri": null(c.LogoURI), "client_uri": null(c.ClientURI), "policy_uri": null(c.PolicyURI),
		"tos_uri": null(c.TosURI), "created_by": null(c.CreatedBy), "disabled_at": store.Nullable(c.DisabledAt),
		"created_at": c.CreatedAt, "updated_at": c.UpdatedAt,
	}, nil
}

func clientFromRow(r store.Row) Client {
	c := Client{
		ID: r.String("id"), ClientID: r.String("client_id"), OrganizationID: r.String("organization_id"),
		Name: r.String("name"), Type: r.String("type"), secretHash: r.String("secret_hash"),
		RedirectURIs: stringList(r, "redirect_uris"), GrantTypes: stringList(r, "grant_types"), Scopes: stringList(r, "scopes"),
		TokenEndpointAuthMethod: r.String("token_endpoint_auth_method"), JWKSURI: r.String("jwks_uri"),
		DPoPBound: r.Bool("dpop_bound"), Trusted: r.Bool("trusted"), LogoURI: r.String("logo_uri"),
		ClientURI: r.String("client_uri"), PolicyURI: r.String("policy_uri"), TosURI: r.String("tos_uri"),
		CreatedBy: r.String("created_by"), DisabledAt: r.TimePtr("disabled_at"),
	}
	var jwks map[string]any
	if r.JSON("jwks", &jwks) == nil {
		c.JWKS = jwks
	}
	c.CreatedAt, _ = r.Time("created_at")
	c.UpdatedAt, _ = r.Time("updated_at")
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = c.CreatedAt
	}
	return c
}

// stringList reads a JSON list of strings, skipping anything else.
func stringList(r store.Row, col string) []string {
	var raw []any
	_ = r.JSON(col, &raw)
	out := []string{}
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// null is nil for "", s otherwise: an optional column or JSON member.
func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// list is s, or an empty list for nil (JSON [] rather than null).
func list(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func jwksValue(j map[string]any) any {
	if j == nil {
		return nil
	}
	return j
}

// timestamp formats t as the API writes times: RFC 3339 in UTC to the second ("…Z").
func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func timestampPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return timestamp(*t)
}
