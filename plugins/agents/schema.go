package agents

import "github.com/univeros/polaris.go/schema"

// The tables the plugin owns.
const (
	TableAgents    = "polaris_agent"
	TableHosts     = "polaris_agent_host"
	TableGrants    = "polaris_agent_grant"
	TableApprovals = "polaris_agent_approval"
	TableReceipts  = "polaris_agent_receipt"
	// TableRegistrations holds the registrations of hosts the server does not know, until a person decides.
	TableRegistrations = "polaris_agent_registration"
)

// Models returns the plugin's six tables (their columns are the schema existing databases hold):
// the agents (each an OAuth
// client by the same id), the hosts that enrol them, the grants with their budgets, the approvals
// a person decides, the receipt chain of every execution, and the registrations of unknown hosts.
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableAgents,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("ownerType", 16),
			schema.StringField("ownerId", 36),
			schema.StringField("organizationId", 36).AsNullable(),
			schema.StringField("name", 160),
			schema.StringField("mode", 16),
			schema.StringField("hostId", 36).AsNullable(),
			schema.StringField("auth", 32),
			schema.JSONField("publicJwk").AsNullable(),
			schema.StringField("status", 16),
			schema.StringField("createdBy", 36),
			schema.DateTimeField("sealedAt").AsNullable(),
			schema.DateTimeField("createdAt"),
			schema.DateTimeField("updatedAt"),
			schema.StringField("keyThumbprint", 64).AsASCII().AsNullable(),
		).
			Unique([]string{"host_id", "key_thumbprint"}, "polaris_agent_host_key_thumbprint_unique").
			Index([]string{"owner_type", "owner_id"}, "polaris_agent_owner_index").
			Index([]string{"organization_id"}, "polaris_agent_org_index"),
		schema.Table(TableHosts,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("ownerType", 16),
			schema.StringField("ownerId", 36),
			schema.StringField("organizationId", 36).AsNullable(),
			schema.StringField("name", 160),
			schema.StringField("enrollmentTokenHash", 128),
			schema.JSONField("defaultCapabilities"),
			schema.StringField("createdBy", 36),
			schema.DateTimeField("revokedAt").AsNullable(),
			schema.DateTimeField("createdAt"),
			schema.JSONField("publicJwk").AsNullable(),
			schema.StringField("jwksUrl", 500).AsNullable(),
			schema.StringField("keyThumbprint", 64).AsNullable(),
		).
			Unique([]string{"enrollment_token_hash"}, "polaris_agent_host_token_unique").
			Unique([]string{"key_thumbprint"}, "polaris_agent_host_key_unique").
			Unique([]string{"jwks_url"}, "polaris_agent_host_jwks_unique").
			Index([]string{"owner_type", "owner_id"}, "polaris_agent_host_owner_index"),
		schema.Table(TableGrants,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("agentId", 36),
			schema.StringField("capability", 80),
			schema.JSONField("constraints"),
			schema.IntField("budgetTotal").AsNullable(),
			schema.IntField("budgetRemaining").AsNullable(),
			schema.StringField("budgetKind", 8).AsNullable(),
			schema.StringField("budgetField", 80).AsNullable(),
			schema.StringField("status", 16),
			schema.StringField("grantedBy", 36).AsNullable(),
			schema.StringField("approvedVia", 32).AsNullable(),
			schema.StringField("approvalId", 36).AsNullable(),
			schema.DateTimeField("expiresAt").AsNullable(),
			schema.DateTimeField("createdAt"),
			schema.DateTimeField("updatedAt"),
		).
			Index([]string{"agent_id", "capability", "status"}, "polaris_agent_grant_lookup_index"),
		schema.Table(TableApprovals,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("agentId", 36),
			schema.JSONField("grantIds"),
			schema.StringField("method", 32),
			schema.StringField("strength", 16),
			schema.StringField("userCode", 16),
			schema.StringField("bindingMessage", 160).AsNullable(),
			schema.StringField("status", 16),
			schema.StringField("decidedBy", 36).AsNullable(),
			schema.DateTimeField("expiresAt"),
			schema.DateTimeField("createdAt"),
			schema.DateTimeField("updatedAt"),
		).
			Index([]string{"user_code", "status"}, "polaris_agent_approval_code_index").
			Index([]string{"agent_id", "status"}, "polaris_agent_approval_agent_index"),
		schema.Table(TableReceipts,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("agentId", 36),
			schema.IntField("seq"),
			schema.StringField("grantId", 36).AsNullable(),
			schema.StringField("capability", 80).AsNullable(),
			schema.StringField("inputHash", 64),
			schema.StringField("outcome", 16),
			schema.IntField("budgetBefore").AsNullable(),
			schema.IntField("budgetAfter").AsNullable(),
			schema.StringField("prevHash", 64).AsNullable(),
			schema.StringField("hash", 64),
			schema.TextField("signature"),
			schema.DateTimeField("createdAt"),
		).
			Unique([]string{"agent_id", "seq"}, "polaris_agent_receipt_seq_unique"),
		schema.Table(TableRegistrations,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("hostId", 36),
			schema.StringField("hostThumbprint", 64).AsASCII(),
			schema.JSONField("hostJwk"),
			schema.StringField("hostName", 160),
			schema.StringField("agentThumbprint", 64).AsASCII(),
			schema.JSONField("agentJwk"),
			schema.StringField("name", 160),
			schema.StringField("mode", 16),
			schema.StringField("reason", 500).AsNullable(),
			schema.StringField("status", 16),
			schema.DateTimeField("expiresAt"),
			schema.DateTimeField("createdAt"),
			schema.DateTimeField("updatedAt"),
		).
			Unique([]string{"host_thumbprint", "agent_thumbprint"}, "polaris_agent_registration_keys_unique").
			Index([]string{"expires_at"}, "polaris_agent_registration_expiry_index"),
	}
}
