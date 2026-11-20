package messaging

import "github.com/univeros/polaris.go/schema"

// TableTemplates is the table the plugin owns: organizations' template overrides.
const TableTemplates = "polaris_messaging_template"

// Models returns polaris_messaging_template as upstream declares it.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableTemplates,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("organizationId", 36),
			schema.StringField("key", 64),
			schema.StringField("locale", 8),
			schema.StringField("subject", 255).AsNullable(),
			schema.TextField("text"),
			schema.TextField("html").AsNullable(),
			schema.DateTimeField("updatedAt"),
		).Unique([]string{"organization_id", "key", "locale"}, "polaris_messaging_template_unique"),
	}
}
