package oauth

import "github.com/univeros/polaris.go/schema"

// The plugin's tables.
const (
	TableClients      = "polaris_oauth_client"
	TableConsents     = "polaris_oauth_consent"
	TableCodes        = "polaris_oauth_code"
	TableTokens       = "polaris_oauth_token"
	TableDeviceCodes  = "polaris_oauth_device_code"
	TableCIBARequests = "polaris_oauth_ciba_request"
)

// models are upstream's Polaris\OAuth\Schema definitions, column for column.
func models() []schema.Model {
	str := schema.StringField
	nullable := func(f schema.Field) schema.Field { return f.AsNullable() }
	// A client_id may be a metadata-document URL, whose path is case-sensitive: compared byte for
	// byte (MySQL's default collation would let /App reuse /app's consent).
	clientID := str("clientId", 255).AsCaseSensitive()
	return []schema.Model{
		schema.Table(TableClients,
			str("id", 36).AsPrimary(), clientID, nullable(str("organizationId", 36)),
			str("name", 160), str("type", 16), nullable(str("secretHash", 128)),
			schema.JSONField("redirectUris"), schema.JSONField("grantTypes"), schema.JSONField("scopes"),
			str("tokenEndpointAuthMethod", 32), nullable(schema.JSONField("jwks")), nullable(str("jwksUri", 2048)),
			schema.BoolField("dpopBound").WithDefault(false), schema.BoolField("trusted").WithDefault(false),
			nullable(str("logoUri", 2048)), nullable(str("clientUri", 2048)), nullable(str("policyUri", 2048)),
			nullable(str("tosUri", 2048)), nullable(str("createdBy", 36)), nullable(schema.DateTimeField("disabledAt")),
			schema.DateTimeField("createdAt"), schema.DateTimeField("updatedAt"),
		).Unique([]string{"client_id"}, "polaris_oauth_client_id_unique").
			Index([]string{"organization_id"}, "polaris_oauth_client_org_index"),
		schema.Table(TableConsents,
			str("id", 36).AsPrimary(), str("userId", 36), clientID, nullable(str("organizationId", 36)),
			schema.JSONField("scopes"), schema.DateTimeField("grantedAt"), schema.DateTimeField("updatedAt"),
		).Unique([]string{"user_id", "client_id"}, "polaris_oauth_consent_unique"),
		schema.Table(TableCodes,
			str("id", 36).AsPrimary(), str("codeHash", 128), clientID, str("userId", 36),
			nullable(str("organizationId", 36)), schema.JSONField("scopes"), str("redirectUri", 2048),
			str("codeChallenge", 128), nullable(str("nonce", 255)), nullable(str("resource", 2048)),
			nullable(str("dpopJkt", 128)), nullable(schema.IntField("authTime")), schema.DateTimeField("expiresAt"),
			nullable(schema.DateTimeField("usedAt")), schema.DateTimeField("createdAt"),
		).Unique([]string{"code_hash"}, "polaris_oauth_code_hash_unique"),
		schema.Table(TableTokens,
			str("id", 36).AsPrimary(), str("kind", 8), nullable(str("tokenHash", 128)), clientID,
			nullable(str("userId", 36)), nullable(str("organizationId", 36)), schema.JSONField("scopes"),
			nullable(str("familyId", 36)), nullable(str("resource", 2048)), nullable(str("dpopJkt", 128)),
			nullable(schema.JSONField("actor")), nullable(schema.IntField("authTime")), schema.DateTimeField("expiresAt"),
			nullable(schema.DateTimeField("revokedAt")), schema.DateTimeField("createdAt"),
		).Unique([]string{"token_hash"}, "polaris_oauth_token_hash_unique").
			Index([]string{"user_id", "client_id"}, "polaris_oauth_token_user_index").
			Index([]string{"family_id"}, "polaris_oauth_token_family_index"),
		schema.Table(TableDeviceCodes,
			str("id", 36).AsPrimary(), str("deviceCodeHash", 128), str("userCode", 16), clientID,
			schema.JSONField("scopes"), nullable(str("resource", 2048)), str("status", 16), nullable(str("userId", 36)),
			nullable(str("organizationId", 36)), nullable(schema.IntField("authTime")),
			nullable(schema.DateTimeField("lastPolledAt")), schema.DateTimeField("expiresAt"), schema.DateTimeField("createdAt"),
		).Unique([]string{"device_code_hash"}, "polaris_oauth_device_code_hash_unique").
			Unique([]string{"user_code"}, "polaris_oauth_device_user_code_unique"),
		schema.Table(TableCIBARequests,
			str("id", 36).AsPrimary(), clientID, str("userId", 36), nullable(str("organizationId", 36)),
			schema.JSONField("scopes"), nullable(str("bindingMessage", 160)), nullable(str("resource", 2048)),
			str("status", 16), nullable(schema.IntField("authTime")), nullable(schema.DateTimeField("lastPolledAt")),
			schema.DateTimeField("expiresAt"), schema.DateTimeField("createdAt"),
		).Index([]string{"user_id", "status"}, "polaris_oauth_ciba_user_index"),
	}
}
