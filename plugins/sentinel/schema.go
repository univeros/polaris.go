package sentinel

import "github.com/univeros/polaris-go/schema"

// The tables the plugin owns.
const (
	TableDecisions = "polaris_sentinel_decision"
	TableIPRules   = "polaris_sentinel_ip_rule"
	TableDevices   = "polaris_sentinel_device"
)

// Models returns the three tables as upstream declares them.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableDecisions,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("kind", 32),
			schema.StringField("email", 320).AsNullable(),
			schema.StringField("ip", 45).AsNullable(),
			schema.IntField("score"),
			schema.StringField("action", 16),
			schema.BoolField("enforced"),
			schema.JSONField("signals"),
			schema.JSONField("reasons"),
			schema.DateTimeField("createdAt"),
		).
			Index([]string{"created_at"}, "polaris_sentinel_decision_created_index").
			Index([]string{"email"}, "polaris_sentinel_decision_email_index").
			Index([]string{"ip"}, "polaris_sentinel_decision_ip_index"),
		schema.Table(TableIPRules,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("cidr", 64),
			schema.StringField("action", 16),
			schema.StringField("note", 255).AsNullable(),
			schema.StringField("createdBy", 64).AsNullable(),
			schema.DateTimeField("createdAt"),
		),
		schema.Table(TableDevices,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("userId", 36),
			schema.StringField("deviceHash", 64),
			schema.StringField("ip", 45).AsNullable(),
			schema.StringField("latitude", 32).AsNullable(),
			schema.StringField("longitude", 32).AsNullable(),
			schema.DateTimeField("lastSeenAt"),
			schema.DateTimeField("createdAt"),
		).Unique([]string{"user_id", "device_hash"}, "polaris_sentinel_device_unique"),
	}
}
