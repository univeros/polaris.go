package scim

import "github.com/univeros/polaris.go/schema"

// The tables the plugin owns.
const (
	TableConnections = "polaris_scim_connection"
	TableResources   = "polaris_scim_resource"
	TableProvenance  = "polaris_scim_membership_provenance"
)

// Models returns the three tables as upstream declares them.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableConnections,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("organizationId", 36),
			schema.StringField("ssoProviderId", 36).AsNullable(),
			schema.StringField("name", 120),
			schema.StringField("tokenHash", 128),
			schema.StringField("status", 16),
			schema.JSONField("settings"),
			schema.DateTimeField("lastSyncAt").AsNullable(),
			schema.DateTimeField("decommissionedAt").AsNullable(),
			schema.StringField("createdBy", 64).AsNullable(),
			schema.DateTimeField("createdAt"),
		).
			Index([]string{"organization_id"}, "polaris_scim_connection_org_index").
			Index([]string{"token_hash"}, "polaris_scim_connection_token_index"),
		schema.Table(TableResources,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("connectionId", 36),
			schema.StringField("kind", 8),
			schema.StringField("externalId", 255),
			schema.StringField("localId", 36),
			schema.DateTimeField("updatedAt"),
		).Unique([]string{"connection_id", "kind", "local_id"}, "polaris_scim_resource_unique"),
		schema.Table(TableProvenance,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("organizationId", 36),
			schema.StringField("userId", 36),
			schema.StringField("connectionId", 36),
			schema.DateTimeField("createdAt"),
		).Unique([]string{"organization_id", "user_id"}, "polaris_scim_provenance_unique"),
	}
}
