package repository

import (
	"cmp"
	"context"
	"time"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

// MFAFactors reads and writes auth_mfa_factors.
type MFAFactors struct{ Table[model.MFAFactor] }

// ListByUser returns every factor of a user, confirmed or not.
func (r MFAFactors) ListByUser(ctx context.Context, userID string) ([]model.MFAFactor, error) {
	return r.list(ctx, store.Criteria{"user_id": userID})
}

// ListByUserAndType returns a user's factors of one type (model.FactorTOTP, ...).
func (r MFAFactors) ListByUserAndType(ctx context.Context, userID, factorType string) ([]model.MFAFactor, error) {
	return r.list(ctx, store.Criteria{"user_id": userID, "type": factorType})
}

// DeleteByUser removes every factor of a user (user deletion scrubs them).
func (r MFAFactors) DeleteByUser(ctx context.Context, userID string) (int64, error) {
	return r.deleteWhere(ctx, store.Criteria{"user_id": userID})
}

func newMFAFactors(db store.Adapter) MFAFactors {
	return MFAFactors{Table[model.MFAFactor]{db: db, name: "auth_mfa_factors", key: []string{"id"},
		toRow: func(f model.MFAFactor) store.Row {
			return store.Row{
				"id": f.ID, "user_id": f.UserID, "type": f.Type, "label": store.Nullable(f.Label),
				"secret_encrypted": store.Nullable(f.SecretEncrypted), "phone_e164": store.Nullable(f.PhoneE164),
				"email": store.Nullable(f.Email), "is_default": f.IsDefault, "confirmed_at": tsPtr(f.ConfirmedAt),
				"last_used_at": tsPtr(f.LastUsedAt), "created_at": ts(f.CreatedAt), "updated_at": ts(f.UpdatedAt),
			}
		},
		fromRow: func(r *reader) model.MFAFactor {
			return model.MFAFactor{
				ID: r.str("id"), UserID: r.str("user_id"), Type: r.str("type"), Label: r.strPtr("label"),
				SecretEncrypted: r.strPtr("secret_encrypted"), PhoneE164: r.strPtr("phone_e164"),
				Email: r.strPtr("email"), IsDefault: r.boolean("is_default"), ConfirmedAt: r.timePtr("confirmed_at"),
				LastUsedAt: r.timePtr("last_used_at"), CreatedAt: r.time("created_at"), UpdatedAt: r.time("updated_at"),
			}
		},
	}}
}

// OTPChallenges reads and writes auth_otp_challenges.
type OTPChallenges struct{ Table[model.OTPChallenge] }

// ListForFactor returns a user's challenges for one factor and purpose.
func (r OTPChallenges) ListForFactor(ctx context.Context, userID, factorID, purpose string) ([]model.OTPChallenge, error) {
	return r.list(ctx, store.Criteria{"user_id": userID, "factor_id": factorID, "purpose": purpose})
}

// SpendAttempt increments attempts only while it is below maxAttempts, so the budget is enforced
// by the database; false means the budget was already spent.
func (r OTPChallenges) SpendAttempt(ctx context.Context, id string, maxAttempts int) (bool, error) {
	return r.claim(ctx, store.Criteria{"id": id, "attempts": store.Lt(maxAttempts)}, store.Data{"attempts": store.Increment{By: 1}})
}

// ClaimConsumption marks an unconsumed challenge consumed at now; false means another request
// consumed it first.
func (r OTPChallenges) ClaimConsumption(ctx context.Context, id string, now time.Time) (bool, error) {
	return r.claim(ctx, store.Criteria{"id": id, "consumed_at": nil}, store.Data{"consumed_at": ts(now)})
}

// DeleteByUser removes every challenge of a user (user deletion scrubs them).
func (r OTPChallenges) DeleteByUser(ctx context.Context, userID string) (int64, error) {
	return r.deleteWhere(ctx, store.Criteria{"user_id": userID})
}

// Prune removes consumed challenges, then expired ones (expires_at < now), and returns how many.
func (r OTPChallenges) Prune(ctx context.Context, now time.Time) (int64, error) {
	return prune(ctx, r.Table, now)
}

func newOTPChallenges(db store.Adapter) OTPChallenges {
	return OTPChallenges{Table[model.OTPChallenge]{db: db, name: "auth_otp_challenges", key: []string{"id"},
		toRow: func(c model.OTPChallenge) store.Row {
			return store.Row{
				"id": c.ID, "user_id": c.UserID, "factor_id": store.Nullable(c.FactorID), "purpose": c.Purpose,
				"channel": c.Channel, "code_hash": store.Nullable(c.CodeHash), "destination": store.Nullable(c.Destination),
				"attempts": c.Attempts, "max_attempts": cmp.Or(c.MaxAttempts, model.DefaultMaxAttempts),
				"expires_at": ts(c.ExpiresAt), "consumed_at": tsPtr(c.ConsumedAt), "ip": store.Nullable(c.IP),
				"created_at": ts(c.CreatedAt),
			}
		},
		fromRow: func(r *reader) model.OTPChallenge {
			return model.OTPChallenge{
				ID: r.str("id"), UserID: r.str("user_id"), FactorID: r.strPtr("factor_id"), Purpose: r.str("purpose"),
				Channel: r.str("channel"), CodeHash: r.strPtr("code_hash"), Destination: r.strPtr("destination"),
				Attempts: r.integer("attempts"), MaxAttempts: r.integer("max_attempts"), ExpiresAt: r.time("expires_at"),
				ConsumedAt: r.timePtr("consumed_at"), IP: r.strPtr("ip"), CreatedAt: r.time("created_at"),
			}
		},
	}}
}

// RecoveryCodes reads and writes auth_recovery_codes.
type RecoveryCodes struct{ Table[model.RecoveryCode] }

// ListUnusedByUser returns a user's codes that were never used.
func (r RecoveryCodes) ListUnusedByUser(ctx context.Context, userID string) ([]model.RecoveryCode, error) {
	return r.list(ctx, store.Criteria{"user_id": userID, "used_at": nil})
}

// ClaimUse marks an unused code used at now; false means another request used it first.
func (r RecoveryCodes) ClaimUse(ctx context.Context, id string, now time.Time) (bool, error) {
	return r.claim(ctx, store.Criteria{"id": id, "used_at": nil}, store.Data{"used_at": ts(now)})
}

func newRecoveryCodes(db store.Adapter) RecoveryCodes {
	return RecoveryCodes{Table[model.RecoveryCode]{db: db, name: "auth_recovery_codes", key: []string{"id"},
		toRow: func(c model.RecoveryCode) store.Row {
			return store.Row{"id": c.ID, "user_id": c.UserID, "code_hash": c.CodeHash, "used_at": tsPtr(c.UsedAt), "created_at": ts(c.CreatedAt)}
		},
		fromRow: func(r *reader) model.RecoveryCode {
			return model.RecoveryCode{ID: r.str("id"), UserID: r.str("user_id"), CodeHash: r.str("code_hash"), UsedAt: r.timePtr("used_at"), CreatedAt: r.time("created_at")}
		},
	}}
}
