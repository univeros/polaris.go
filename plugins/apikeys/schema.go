package apikeys

import "github.com/univeros/polaris-go/schema"

// TableKeys is the table the plugin owns.
const TableKeys = "polaris_api_key"

// Models returns polaris_api_key as upstream declares it.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableKeys,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("ownerType", 16),
			schema.StringField("ownerId", 36),
			schema.StringField("organizationId", 36).AsNullable(),
			schema.StringField("createdBy", 36),
			schema.StringField("name", 80),
			schema.StringField("environment", 8),
			schema.StringField("hint", 8),
			schema.StringField("keyHash", 128),
			schema.JSONField("permissions"),
			schema.IntField("rateLimitWindow").AsNullable(),
			schema.IntField("rateLimitMax").AsNullable(),
			schema.JSONField("metadata"),
			schema.StringField("rotatedFromId", 36).AsNullable(),
			schema.DateTimeField("graceUntil").AsNullable(),
			schema.DateTimeField("expiresAt").AsNullable(),
			schema.DateTimeField("lastUsedAt").AsNullable(),
			schema.DateTimeField("revokedAt").AsNullable(),
			schema.DateTimeField("createdAt"),
			schema.DateTimeField("updatedAt"),
		).
			Unique([]string{"key_hash"}, "polaris_api_key_hash_unique").
			Index([]string{"owner_type", "owner_id"}, "polaris_api_key_owner_index").
			Index([]string{"created_by"}, "polaris_api_key_creator_index"),
	}
}
