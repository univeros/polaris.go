package schema

import (
	"errors"
	"fmt"
)

// ErrRedefined is returned by Merge when a plugin declares a table that is already defined.
var ErrRedefined = errors.New("schema: table already defined")

// Core returns core's tables in registry order. Each call builds fresh
// models, so callers may change the result freely.
func Core() []Model {
	return []Model{
		auditLog(),
		emailVerifications(),
		invitations(),
		memberships(),
		membershipRoles(),
		mfaFactors(),
		organizations(),
		otpChallenges(),
		passwordResets(),
		permissions(),
		recoveryCodes(),
		refreshTokens(),
		roles(),
		rolePermissions(),
		users(),
	}
}

// Merge returns core followed by each plugin's models, in order. A plugin cannot redefine a table
// that core or an earlier plugin already defines: plugins own their tables only.
func Merge(core []Model, plugins ...[]Model) ([]Model, error) {
	out := append([]Model{}, core...)
	seen := make(map[string]bool, len(core))
	for _, m := range core {
		seen[m.Table] = true
	}
	for _, models := range plugins {
		for _, m := range models {
			if seen[m.Table] {
				return nil, fmt.Errorf("%w: %s; a plugin cannot redefine it", ErrRedefined, m.Table)
			}
			seen[m.Table] = true
			out = append(out, m)
		}
	}
	return out, nil
}

func id() Field { return StringField("id", 36).AsPrimary() }

func auditLog() Model {
	return Table("auth_audit_log",
		id(),
		StringField("actorUserId", 36).AsNullable(),
		StringField("organizationId", 36).AsNullable(),
		StringField("event", 80),
		StringField("ip", 45).AsNullable(),
		StringField("userAgent", 255).AsNullable(),
		JSONField("metadata"),
		DateTimeField("createdAt"),
	).
		Index([]string{"actor_user_id", "created_at"}, "auth_audit_log_actor_index").
		Index([]string{"organization_id", "created_at"}, "auth_audit_log_org_index").
		Index([]string{"event", "created_at"}, "auth_audit_log_event_index")
}

func emailVerifications() Model {
	return Table("auth_email_verifications",
		id(),
		StringField("userId", 36),
		StringField("email", 320),
		StringField("tokenHash", 64),
		DateTimeField("expiresAt"),
		DateTimeField("consumedAt").AsNullable(),
		StringField("ip", 45).AsNullable(),
		DateTimeField("createdAt"),
	).
		Unique([]string{"token_hash"}, "auth_email_verifications_token_hash_unique").
		Index([]string{"user_id"}, "auth_email_verifications_user_index").
		Index([]string{"expires_at"}, "auth_email_verifications_expires_index")
}

func invitations() Model {
	return Table("auth_invitations",
		id(),
		StringField("organizationId", 36),
		StringField("email", 320),
		JSONField("roleIds"),
		StringField("tokenHash", 64),
		StringField("invitedBy", 36),
		DateTimeField("expiresAt"),
		DateTimeField("acceptedAt").AsNullable(),
		DateTimeField("createdAt"),
	).
		Unique([]string{"token_hash"}, "auth_invitations_token_hash_unique").
		Index([]string{"organization_id"}, "auth_invitations_org_index").
		Index([]string{"email"}, "auth_invitations_email_index")
}

func memberships() Model {
	return Table("auth_memberships",
		id(),
		StringField("userId", 36),
		StringField("organizationId", 36),
		StringField("status", 16).WithDefault("invited"),
		StringField("invitedBy", 36).AsNullable(),
		DateTimeField("joinedAt").AsNullable(),
		DateTimeField("createdAt"),
		DateTimeField("updatedAt"),
	).
		Unique([]string{"user_id", "organization_id"}, "auth_memberships_user_org_unique").
		Index([]string{"organization_id", "status"}, "auth_memberships_org_status_index")
}

func membershipRoles() Model {
	return Table("auth_membership_roles",
		StringField("membershipId", 36).AsPrimary(),
		StringField("roleId", 36).AsPrimary(),
	).
		References([]string{"membership_id"}, "auth_memberships", []string{"id"}).
		References([]string{"role_id"}, "auth_roles", []string{"id"})
}

func mfaFactors() Model {
	return Table("auth_mfa_factors",
		id(),
		StringField("userId", 36),
		StringField("type", 16),
		StringField("label", 80).AsNullable(),
		TextField("secretEncrypted").AsNullable(),
		StringField("phoneE164", 20).AsNullable(),
		StringField("email", 320).AsNullable(),
		BoolField("isDefault").WithDefault(false),
		DateTimeField("confirmedAt").AsNullable(),
		DateTimeField("lastUsedAt").AsNullable(),
		DateTimeField("createdAt"),
		DateTimeField("updatedAt"),
	).
		Index([]string{"user_id", "type"}, "auth_mfa_factors_user_type_index").
		Index([]string{"user_id", "confirmed_at"}, "auth_mfa_factors_user_confirmed_index")
}

func organizations() Model {
	return Table("auth_organizations",
		id(),
		StringField("name", 160),
		StringField("slug", 160),
		StringField("status", 16).WithDefault("active"),
		StringField("createdBy", 36),
		DateTimeField("createdAt"),
		DateTimeField("updatedAt"),
	).
		Unique([]string{"slug"}, "auth_organizations_slug_unique").
		Index([]string{"status"}, "auth_organizations_status_index")
}

func otpChallenges() Model {
	return Table("auth_otp_challenges",
		id(),
		StringField("userId", 36),
		StringField("factorId", 36).AsNullable(),
		StringField("purpose", 20),
		StringField("channel", 16),
		StringField("codeHash", 64).AsNullable(),
		StringField("destination", 320).AsNullable(),
		IntField("attempts").WithDefault(0),
		IntField("maxAttempts").WithDefault(5),
		DateTimeField("expiresAt"),
		DateTimeField("consumedAt").AsNullable(),
		StringField("ip", 45).AsNullable(),
		DateTimeField("createdAt"),
	).
		Index([]string{"user_id", "purpose", "consumed_at"}, "auth_otp_challenges_user_purpose_index").
		Index([]string{"expires_at"}, "auth_otp_challenges_expires_index")
}

func passwordResets() Model {
	return Table("auth_password_resets",
		id(),
		StringField("userId", 36),
		StringField("email", 320),
		StringField("tokenHash", 64),
		DateTimeField("expiresAt"),
		DateTimeField("consumedAt").AsNullable(),
		StringField("ip", 45).AsNullable(),
		DateTimeField("createdAt"),
	).
		Unique([]string{"token_hash"}, "auth_password_resets_token_hash_unique").
		Index([]string{"user_id"}, "auth_password_resets_user_index").
		Index([]string{"expires_at"}, "auth_password_resets_expires_index")
}

func permissions() Model {
	return Table("auth_permissions",
		id(),
		StringField("key", 120),
		StringField("description", 255),
	).
		Unique([]string{"key"}, "auth_permissions_key_unique")
}

func recoveryCodes() Model {
	return Table("auth_recovery_codes",
		id(),
		StringField("userId", 36),
		StringField("codeHash", 64),
		DateTimeField("usedAt").AsNullable(),
		DateTimeField("createdAt"),
	).
		Index([]string{"user_id", "used_at"}, "auth_recovery_codes_user_used_index")
}

func refreshTokens() Model {
	return Table("auth_refresh_tokens",
		id(),
		StringField("userId", 36),
		StringField("organizationId", 36).AsNullable(),
		StringField("familyId", 36),
		StringField("parentId", 36).AsNullable(),
		StringField("tokenHash", 64),
		StringField("userAgent", 255).AsNullable(),
		StringField("ip", 45).AsNullable(),
		BoolField("mfa").WithDefault(false),
		StringField("amr", 64).AsNullable(),
		IntField("authTime").AsNullable(),
		DateTimeField("expiresAt"),
		DateTimeField("lastUsedAt").AsNullable(),
		DateTimeField("revokedAt").AsNullable(),
		StringField("revokedReason", 32).AsNullable(),
		DateTimeField("createdAt"),
	).
		Unique([]string{"token_hash"}, "auth_refresh_tokens_token_hash_unique").
		Index([]string{"user_id", "revoked_at"}, "auth_refresh_tokens_user_index").
		Index([]string{"family_id"}, "auth_refresh_tokens_family_index")
}

func rolePermissions() Model {
	return Table("auth_role_permissions",
		StringField("roleId", 36).AsPrimary(),
		StringField("permissionId", 36).AsPrimary(),
	).
		References([]string{"role_id"}, "auth_roles", []string{"id"}).
		References([]string{"permission_id"}, "auth_permissions", []string{"id"})
}

func roles() Model {
	return Table("auth_roles",
		id(),
		StringField("organizationId", 36).AsNullable(),
		StringField("name", 80),
		StringField("slug", 80),
		StringField("description", 255).AsNullable(),
		BoolField("isSystem").WithDefault(false),
		DateTimeField("createdAt"),
		DateTimeField("updatedAt"),
	).
		Unique([]string{"organization_id", "slug"}, "auth_roles_org_slug_unique")
}

func users() Model {
	return Table("auth_users",
		id(),
		StringField("email", 320),
		DateTimeField("emailVerifiedAt").AsNullable(),
		StringField("passwordHash", 255).AsNullable(),
		StringField("displayName", 120).AsNullable(),
		StringField("status", 16).WithDefault("active"),
		BoolField("mfaEnforced").WithDefault(false),
		IntField("failedLoginCount").WithDefault(0),
		DateTimeField("failedLoginAt").AsNullable(),
		DateTimeField("lockedUntil").AsNullable(),
		DateTimeField("lastLoginAt").AsNullable(),
		DateTimeField("createdAt"),
		DateTimeField("updatedAt"),
	).
		Unique([]string{"email"}, "auth_users_email_unique").
		Index([]string{"status"}, "auth_users_status_index")
}
