// Package maintenance holds the housekeeping jobs a host schedules (a cron, a ticker).
package maintenance

import (
	"context"
	"fmt"
	"time"

	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
)

// DefaultRefreshGrace is how long expired or revoked refresh tokens are kept: reuse detection
// needs the rotated ancestors of a live session for a while.
const DefaultRefreshGrace = 7 * 24 * time.Hour

// PruneExpired deletes rows that can no longer be used (upstream PruneExpiredService): consumed or
// expired (expires_at < now) OTP challenges, email verifications and password resets, and refresh
// tokens that expired, or were revoked, more than refreshGrace before now (≤ 0 means
// DefaultRefreshGrace). Audit rows are never pruned. It returns the rows deleted per table
// (auth_otp_challenges, auth_email_verifications, auth_password_resets, auth_refresh_tokens) and is
// idempotent: a second run deletes nothing.
func PruneExpired(ctx context.Context, db store.Adapter, now time.Time, refreshGrace time.Duration) (map[string]int64, error) {
	if refreshGrace <= 0 {
		refreshGrace = DefaultRefreshGrace
	}
	r := repository.New(db)
	jobs := []struct {
		table string
		prune func(context.Context, time.Time) (int64, error)
		until time.Time
	}{
		{"auth_otp_challenges", r.OTPChallenges.Prune, now},
		{"auth_email_verifications", r.EmailVerifications.Prune, now},
		{"auth_password_resets", r.PasswordResets.Prune, now},
		{"auth_refresh_tokens", r.RefreshTokens.Prune, now.Add(-refreshGrace)},
	}
	deleted := make(map[string]int64, len(jobs))
	for _, j := range jobs {
		n, err := j.prune(ctx, j.until)
		if err != nil {
			return deleted, fmt.Errorf("maintenance: prune %s: %w", j.table, err)
		}
		deleted[j.table] = n
	}
	return deleted, nil
}
