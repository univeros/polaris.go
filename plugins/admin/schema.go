package admin

import "github.com/univeros/polaris.go/schema"

// The tables the plugin owns.
const (
	TableGrants = "polaris_admin_grant"
	TableKeys   = "polaris_admin_key"
)

// Models returns polaris_admin_grant and polaris_admin_key, as upstream's Polaris\Admin\Schema
// declares them.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableGrants,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("userId", 36),
			schema.StringField("role", 16),
			schema.StringField("scope", 36),
			schema.StringField("grantedBy", 36).AsNullable(),
			schema.DateTimeField("expiresAt").AsNullable(),
			schema.DateTimeField("createdAt"),
		).Index([]string{"user_id"}, "polaris_admin_grant_user_index"),
		schema.Table(TableKeys,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("name", 120),
			schema.StringField("keyHash", 64),
			schema.StringField("role", 16),
			schema.StringField("scope", 36),
			schema.JSONField("ipAllowlist"),
			schema.DateTimeField("expiresAt").AsNullable(),
			schema.DateTimeField("lastUsedAt").AsNullable(),
			schema.StringField("createdBy", 64).AsNullable(),
			schema.DateTimeField("createdAt"),
		).Unique([]string{"key_hash"}, "polaris_admin_key_hash_unique"),
	}
}
