package sso

import "github.com/univeros/polaris.go/schema"

// The tables the plugin owns.
const (
	TableProviders = "polaris_sso_provider"
	TableDomains   = "polaris_sso_domain"
	// TableAccounts records the accounts an organization's providers created (decision 68).
	TableAccounts = "polaris_sso_account"
)

// Models returns the tables: providers, domains and provisioned accounts; their columns are the
// schema existing databases hold.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableProviders,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("organizationId", 36),
			schema.StringField("type", 8),
			schema.StringField("name", 120),
			schema.StringField("issuer", 512),
			schema.JSONField("config"),
			schema.JSONField("attributes"),
			schema.JSONField("jit"),
			schema.JSONField("redirectUris"),
			schema.BoolField("enabled"),
			schema.StringField("createdBy", 64).AsNullable(),
			schema.DateTimeField("createdAt"),
			schema.DateTimeField("updatedAt"),
		).Index([]string{"organization_id"}, "polaris_sso_provider_org_index"),
		schema.Table(TableDomains,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("organizationId", 36),
			schema.StringField("providerId", 36),
			schema.StringField("domain", 253),
			schema.StringField("token", 64),
			schema.DateTimeField("verifiedAt").AsNullable(),
			schema.DateTimeField("createdAt"),
		).
			Unique([]string{"domain"}, "polaris_sso_domain_unique").
			Index([]string{"organization_id"}, "polaris_sso_domain_org_index"),
		// Added after v0.5.0 (decision 68): the accounts an organization's providers provisioned
		// just in time. Such an account, or one on a domain the organization verified, is the only
		// existing account a provider signs in. Migrate creates it.
		schema.Table(TableAccounts,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("organizationId", 36),
			schema.StringField("userId", 36),
			schema.StringField("providerId", 36).AsNullable(),
			schema.DateTimeField("createdAt"),
		).Unique([]string{"organization_id", "user_id"}, "polaris_sso_account_unique"),
	}
}
