package admin

import (
	"context"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/plugins/audit"
)

// The admin.* audit names: every operator action is recorded as one.
const (
	AuditUserBanned          = "admin.user_banned"
	AuditUserUnbanned        = "admin.user_unbanned"
	AuditPasswordSet         = "admin.password_set"
	AuditUserDeleted         = "admin.user_deleted"
	AuditUserImpersonated    = "admin.user_impersonated"
	AuditSessionRevoked      = "admin.session_revoked"
	AuditSessionsRevoked     = "admin.sessions_revoked"
	AuditMFAFactorRemoved    = "admin.mfa_factor_removed"
	AuditMFAReset            = "admin.mfa_reset"
	AuditMemberRolesChanged  = "admin.member_roles_changed"
	AuditOrganizationDeleted = "admin.organization_deleted"
	AuditDrainCreated        = "admin.drain_created"
	AuditDrainDeleted        = "admin.drain_deleted"
	AuditDrainTested         = "admin.drain_tested"
	AuditKeyCreated          = "admin.key_created"
	AuditKeyDeleted          = "admin.key_deleted"
	AuditGrantCreated        = "admin.grant_created"
	AuditGrantDeleted        = "admin.grant_deleted"
)

var auditNames = map[string]string{
	AuditUserBanned:          "An operator banned a user",
	AuditUserUnbanned:        "An operator unbanned a user",
	AuditPasswordSet:         "An operator set a user's password",
	AuditUserDeleted:         "An operator deleted (anonymised) a user",
	AuditUserImpersonated:    "An operator started impersonating a user",
	AuditSessionRevoked:      "An operator revoked a session",
	AuditSessionsRevoked:     "An operator revoked every session of a user",
	AuditMFAFactorRemoved:    "An operator removed an MFA factor",
	AuditMFAReset:            "An operator reset a user's MFA",
	AuditMemberRolesChanged:  "An operator changed a member's roles",
	AuditOrganizationDeleted: "An operator deleted an organization",
	AuditDrainCreated:        "An operator created an audit drain",
	AuditDrainDeleted:        "An operator deleted an audit drain",
	AuditDrainTested:         "An operator tested an audit drain",
	AuditKeyCreated:          "An operator created an API key",
	AuditKeyDeleted:          "An operator deleted an API key",
	AuditGrantCreated:        "An operator granted an admin role",
	AuditGrantDeleted:        "An operator revoked an admin role",
}

// Record writes an operator's action to the audit trail: op is the actor (actor type "admin" for a
// user, "api_key" for a key), subjectID the target, the request's client address and user agent
// attached, op's role and scope added to data as actor_role and actor_scope. name must be in the
// audit catalog (a plugin adds its own names with audit.NameProvider).
func (p *Plugin) Record(ctx context.Context, name string, op Principal, subjectID, organizationID string, data map[string]any) error {
	actorType := audit.ActorAdmin
	if op.Type == TypeAPIKey {
		actorType = audit.ActorAPIKey
	}
	merged := make(map[string]any, len(data)+2)
	for k, v := range data {
		merged[k] = v
	}
	merged["actor_role"], merged["actor_scope"] = string(op.Role), op.Scope
	client := endpoint.Client(ctx)
	return p.audit.Record(ctx, audit.Event{
		Name: name, ActorID: op.ID, ActorType: actorType, SubjectID: subjectID, OrganizationID: organizationID,
		IP: client.IP, UserAgent: client.UserAgent, Data: merged,
	})
}
