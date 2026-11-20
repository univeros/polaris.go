package repository

import (
	"cmp"
	"context"
	"encoding/json"
	"time"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

// Users reads and writes auth_users.
type Users struct{ Table[model.User] }

// ByEmail finds a user by (already normalized) email.
func (r Users) ByEmail(ctx context.Context, email string) (model.User, error) {
	return r.FindOne(ctx, store.Criteria{"email": email})
}

func newUsers(db store.Adapter) Users {
	return Users{Table[model.User]{db: db, name: "auth_users", key: []string{"id"},
		toRow: func(u model.User) store.Row {
			return store.Row{
				"id": u.ID, "email": u.Email, "email_verified_at": tsPtr(u.EmailVerifiedAt),
				"password_hash": store.Nullable(u.PasswordHash), "display_name": store.Nullable(u.DisplayName),
				"status": cmp.Or(u.Status, model.UserStatusActive), "mfa_enforced": u.MFAEnforced,
				"failed_login_count": u.FailedLoginCount, "failed_login_at": tsPtr(u.FailedLoginAt),
				"locked_until": tsPtr(u.LockedUntil), "last_login_at": tsPtr(u.LastLoginAt),
				"created_at": ts(u.CreatedAt), "updated_at": ts(u.UpdatedAt),
			}
		},
		fromRow: func(r *reader) model.User {
			return model.User{
				ID: r.str("id"), Email: r.str("email"), EmailVerifiedAt: r.timePtr("email_verified_at"),
				PasswordHash: r.strPtr("password_hash"), DisplayName: r.strPtr("display_name"),
				Status: r.str("status"), MFAEnforced: r.boolean("mfa_enforced"),
				FailedLoginCount: r.integer("failed_login_count"), FailedLoginAt: r.timePtr("failed_login_at"),
				LockedUntil: r.timePtr("locked_until"), LastLoginAt: r.timePtr("last_login_at"),
				CreatedAt: r.time("created_at"), UpdatedAt: r.time("updated_at"),
			}
		},
	}}
}

// OneTimeTokens is the shared shape of auth_email_verifications and auth_password_resets.
type OneTimeTokens[T any] struct{ Table[T] }

// ByTokenHash finds a challenge by its peppered token hash.
func (r OneTimeTokens[T]) ByTokenHash(ctx context.Context, hash string) (T, error) {
	return r.FindOne(ctx, store.Criteria{"token_hash": hash})
}

// ListByUser returns every challenge of a user.
func (r OneTimeTokens[T]) ListByUser(ctx context.Context, userID string) ([]T, error) {
	return r.list(ctx, store.Criteria{"user_id": userID})
}

// DeleteByUser removes every challenge of a user (user deletion scrubs them).
func (r OneTimeTokens[T]) DeleteByUser(ctx context.Context, userID string) (int64, error) {
	return r.deleteWhere(ctx, store.Criteria{"user_id": userID})
}

// Prune removes consumed challenges, then expired ones (expires_at < now), and returns how many.
func (r OneTimeTokens[T]) Prune(ctx context.Context, now time.Time) (int64, error) {
	return prune(ctx, r.Table, now)
}

func prune[T any](ctx context.Context, t Table[T], now time.Time) (int64, error) {
	consumed, err := t.deleteWhere(ctx, store.Criteria{"consumed_at": store.NotNull()})
	if err != nil {
		return 0, err
	}
	expired, err := t.deleteWhere(ctx, store.Criteria{"expires_at": store.Lt(ts(now))})
	return consumed + expired, err
}

// EmailVerifications reads and writes auth_email_verifications.
type EmailVerifications struct {
	OneTimeTokens[model.EmailVerification]
}

func newEmailVerifications(db store.Adapter) EmailVerifications {
	return EmailVerifications{OneTimeTokens[model.EmailVerification]{Table[model.EmailVerification]{
		db: db, name: "auth_email_verifications", key: []string{"id"},
		toRow: func(v model.EmailVerification) store.Row {
			return oneTimeTokenRow(v.ID, v.UserID, v.Email, v.TokenHash, v.ExpiresAt, v.ConsumedAt, v.IP, v.CreatedAt)
		},
		fromRow: func(r *reader) model.EmailVerification {
			return model.EmailVerification{
				ID: r.str("id"), UserID: r.str("user_id"), Email: r.str("email"), TokenHash: r.str("token_hash"),
				ExpiresAt: r.time("expires_at"), ConsumedAt: r.timePtr("consumed_at"), IP: r.strPtr("ip"),
				CreatedAt: r.time("created_at"),
			}
		},
	}}}
}

// PasswordResets reads and writes auth_password_resets.
type PasswordResets struct {
	OneTimeTokens[model.PasswordReset]
}

func newPasswordResets(db store.Adapter) PasswordResets {
	return PasswordResets{OneTimeTokens[model.PasswordReset]{Table[model.PasswordReset]{
		db: db, name: "auth_password_resets", key: []string{"id"},
		toRow: func(v model.PasswordReset) store.Row {
			return oneTimeTokenRow(v.ID, v.UserID, v.Email, v.TokenHash, v.ExpiresAt, v.ConsumedAt, v.IP, v.CreatedAt)
		},
		fromRow: func(r *reader) model.PasswordReset {
			return model.PasswordReset{
				ID: r.str("id"), UserID: r.str("user_id"), Email: r.str("email"), TokenHash: r.str("token_hash"),
				ExpiresAt: r.time("expires_at"), ConsumedAt: r.timePtr("consumed_at"), IP: r.strPtr("ip"),
				CreatedAt: r.time("created_at"),
			}
		},
	}}}
}

func oneTimeTokenRow(id, userID, email, hash string, expires time.Time, consumed *time.Time, ip *string, created time.Time) store.Row {
	return store.Row{
		"id": id, "user_id": userID, "email": email, "token_hash": hash, "expires_at": ts(expires),
		"consumed_at": tsPtr(consumed), "ip": store.Nullable(ip), "created_at": ts(created),
	}
}

// RefreshTokens reads and writes auth_refresh_tokens.
type RefreshTokens struct{ Table[model.RefreshToken] }

// ByTokenHash finds a token by its peppered hash.
func (r RefreshTokens) ByTokenHash(ctx context.Context, hash string) (model.RefreshToken, error) {
	return r.FindOne(ctx, store.Criteria{"token_hash": hash})
}

// ListByUser returns every token of a user, revoked ones included.
func (r RefreshTokens) ListByUser(ctx context.Context, userID string) ([]model.RefreshToken, error) {
	return r.list(ctx, store.Criteria{"user_id": userID})
}

// ListByUserAndOrganization returns every token of a user minted for an organization context.
func (r RefreshTokens) ListByUserAndOrganization(ctx context.Context, userID, organizationID string) ([]model.RefreshToken, error) {
	return r.list(ctx, store.Criteria{"user_id": userID, "organization_id": organizationID})
}

// ListByFamily returns every rotation of a session.
func (r RefreshTokens) ListByFamily(ctx context.Context, familyID string) ([]model.RefreshToken, error) {
	return r.list(ctx, store.Criteria{"family_id": familyID})
}

// ActiveInFamily returns the session's live (not revoked) token.
func (r RefreshTokens) ActiveInFamily(ctx context.Context, familyID string) (model.RefreshToken, error) {
	return r.FindOne(ctx, store.Criteria{"family_id": familyID, "revoked_at": nil})
}

// FamilyRoot returns the session's first token (no parent).
func (r RefreshTokens) FamilyRoot(ctx context.Context, familyID string) (model.RefreshToken, error) {
	return r.FindOne(ctx, store.Criteria{"family_id": familyID, "parent_id": nil})
}

// ClaimRotation revokes a live token as rotated (revoked_at = last_used_at = now) with one
// conditional UPDATE; false means another request rotated it first.
func (r RefreshTokens) ClaimRotation(ctx context.Context, id string, now time.Time) (bool, error) {
	return r.claim(ctx, store.Criteria{"id": id, "revoked_at": nil},
		store.Data{"revoked_at": ts(now), "revoked_reason": model.RevokedRotated, "last_used_at": ts(now)})
}

// Prune removes tokens that expired, then tokens revoked, before cutoff; it returns how many.
func (r RefreshTokens) Prune(ctx context.Context, cutoff time.Time) (int64, error) {
	expired, err := r.deleteWhere(ctx, store.Criteria{"expires_at": store.Lt(ts(cutoff))})
	if err != nil {
		return 0, err
	}
	revoked, err := r.deleteWhere(ctx, store.Criteria{"revoked_at": store.Lt(ts(cutoff))})
	return expired + revoked, err
}

func newRefreshTokens(db store.Adapter) RefreshTokens {
	return RefreshTokens{Table[model.RefreshToken]{db: db, name: "auth_refresh_tokens", key: []string{"id"},
		toRow: func(t model.RefreshToken) store.Row {
			return store.Row{
				"id": t.ID, "user_id": t.UserID, "organization_id": store.Nullable(t.OrganizationID),
				"family_id": t.FamilyID, "parent_id": store.Nullable(t.ParentID), "token_hash": t.TokenHash,
				"user_agent": store.Nullable(t.UserAgent), "ip": store.Nullable(t.IP), "mfa": t.MFA,
				"amr": store.Nullable(t.AMR), "auth_time": store.Nullable(t.AuthTime), "expires_at": ts(t.ExpiresAt),
				"last_used_at": tsPtr(t.LastUsedAt), "revoked_at": tsPtr(t.RevokedAt),
				"revoked_reason": store.Nullable(t.RevokedReason), "created_at": ts(t.CreatedAt),
			}
		},
		fromRow: func(r *reader) model.RefreshToken {
			return model.RefreshToken{
				ID: r.str("id"), UserID: r.str("user_id"), OrganizationID: r.strPtr("organization_id"),
				FamilyID: r.str("family_id"), ParentID: r.strPtr("parent_id"), TokenHash: r.str("token_hash"),
				UserAgent: r.strPtr("user_agent"), IP: r.strPtr("ip"), MFA: r.boolean("mfa"), AMR: r.strPtr("amr"),
				AuthTime: r.int64Ptr("auth_time"), ExpiresAt: r.time("expires_at"), LastUsedAt: r.timePtr("last_used_at"),
				RevokedAt: r.timePtr("revoked_at"), RevokedReason: r.strPtr("revoked_reason"), CreatedAt: r.time("created_at"),
			}
		},
	}}
}

// AuditLog appends to auth_audit_log.
type AuditLog struct{ Table[model.AuditLogEntry] }

func newAuditLog(db store.Adapter) AuditLog {
	return AuditLog{Table[model.AuditLogEntry]{db: db, name: "auth_audit_log", key: []string{"id"},
		toRow: func(e model.AuditLogEntry) store.Row {
			metadata := string(e.Metadata)
			if metadata == "" {
				metadata = "[]"
			}
			return store.Row{
				"id": e.ID, "actor_user_id": store.Nullable(e.ActorUserID), "organization_id": store.Nullable(e.OrganizationID),
				"event": e.Event, "ip": store.Nullable(e.IP), "user_agent": store.Nullable(e.UserAgent),
				"metadata": metadata, "created_at": ts(e.CreatedAt),
			}
		},
		fromRow: func(r *reader) model.AuditLogEntry {
			return model.AuditLogEntry{
				ID: r.str("id"), ActorUserID: r.strPtr("actor_user_id"), OrganizationID: r.strPtr("organization_id"),
				Event: r.str("event"), IP: r.strPtr("ip"), UserAgent: r.strPtr("user_agent"),
				Metadata: json.RawMessage(r.str("metadata")), CreatedAt: r.time("created_at"),
			}
		},
	}}
}
