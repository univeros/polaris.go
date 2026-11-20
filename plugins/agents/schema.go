package agents

import "github.com/univeros/polaris.go/schema"

// The tables the plugin owns.
const (
	TableAgents    = "polaris_agent"
	TableHosts     = "polaris_agent_host"
	TableGrants    = "polaris_agent_grant"
	TableApprovals = "polaris_agent_approval"
	TableReceipts  = "polaris_agent_receipt"
)

// Models returns the plugin's five tables as upstream declares them: the agents (each an OAuth
// client by the same id), the hosts that enrol them, the grants with their budgets, the approvals
// a person decides and the receipt chain of every execution.
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
		).
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
		).
			Unique([]string{"enrollment_token_hash"}, "polaris_agent_host_token_unique").
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
	}
}
