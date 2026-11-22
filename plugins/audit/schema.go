package audit

import "github.com/univeros/polaris.go/schema"

// The tables the plugin owns.
const (
	TableEvents   = "polaris_audit_event"
	TableDrains   = "polaris_audit_drain"
	TableActivity = "polaris_audit_activity"
)

// Models returns the plugin's tables, the columns existing databases hold (a change is a migration).
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableEvents,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("name", 64),
			schema.DateTimeField("occurredAt"),
			schema.StringField("actorType", 16),
			schema.StringField("actorId", 64).AsNullable(),
			schema.StringField("subjectId", 64).AsNullable(),
			schema.StringField("organizationId", 64).AsNullable(),
			schema.StringField("sessionId", 64).AsNullable(),
			schema.StringField("ip", 45).AsNullable(),
			schema.TextField("userAgent").AsNullable(),
			schema.JSONField("data"),
			schema.StringField("requestId", 64).AsNullable(),
			schema.StringField("prevHash", 64).AsNullable(),
			schema.StringField("hash", 64).AsNullable(),
		).
			Index([]string{"name", "occurred_at"}, "polaris_audit_event_name_index").
			Index([]string{"occurred_at"}, "polaris_audit_event_occurred_index").
			Index([]string{"actor_id", "occurred_at"}, "polaris_audit_event_actor_index").
			Index([]string{"subject_id", "occurred_at"}, "polaris_audit_event_subject_index").
			Index([]string{"organization_id", "occurred_at"}, "polaris_audit_event_org_index"),
		schema.Table(TableDrains,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("organizationId", 36),
			schema.StringField("type", 16),
			schema.StringField("endpoint", 2048),
			schema.TextField("secret"),
			schema.JSONField("filter"),
			schema.StringField("status", 16),
			schema.DateTimeField("lastDeliveryAt").AsNullable(),
			schema.TextField("lastError").AsNullable(),
			schema.DateTimeField("createdAt"),
			schema.StringField("createdBy", 36).AsNullable(),
		).Index([]string{"organization_id", "status"}, "polaris_audit_drain_org_index"),
		schema.Table(TableActivity,
			schema.StringField("userId", 36).AsPrimary(),
			schema.DateTimeField("lastActiveAt"),
		),
	}
}
