package agent

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// SlowDown is what a 429 or an RFC 8628 slow_down adds to the polling interval.
const SlowDown = 5 * time.Second

// waiter polls for an approval; the clock and the pause are fields so tests run instantly.
type waiter struct {
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// wait polls the agent's grants every approval.Interval seconds until every grant of the approval
// is active (they are returned), one is denied or revoked (ErrApprovalDenied), the next poll would
// land after expires_in or maxAttempts polls are spent (ErrApprovalExpired), or ctx ends. A 429 or
// slow_down refusal adds SlowDown to the interval. A zero interval or expires_in reads as
// the defaults, 5 and 600 seconds.
func (w waiter) wait(ctx context.Context, approval Approval, poll func(context.Context) ([]Grant, error), maxAttempts int) ([]Grant, error) {
	interval := seconds(approval.Interval, 5)
	expiresIn := seconds(approval.ExpiresIn, 600)
	deadline := w.now().Add(expiresIn)
	if maxAttempts <= 0 {
		maxAttempts = int((expiresIn+interval-1)/interval) + 1
	}
	for range maxAttempts {
		if w.now().Add(interval).After(deadline) {
			break // the next poll would land after the approval expired
		}
		if err := w.sleep(ctx, interval); err != nil {
			return nil, fmt.Errorf("agent: waiting for approval %s: %w", approval.ID, err)
		}
		grants, err := poll(ctx)
		if err != nil {
			var refused *Error
			if errors.As(err, &refused) && (refused.Status == 429 || refused.Code == "slow_down") {
				interval += SlowDown
				continue
			}
			return nil, err
		}
		var mine []Grant
		active := 0
		for _, g := range grants {
			if g.ApprovalID != approval.ID || approval.ID == "" {
				continue
			}
			if g.Status == "denied" || g.Status == "revoked" {
				return nil, fmt.Errorf("agent: approval %s: %w", approval.ID, ErrApprovalDenied)
			}
			if g.Status == "active" {
				active++
			}
			mine = append(mine, g)
		}
		if len(mine) > 0 && active == len(mine) {
			return mine, nil
		}
	}
	return nil, fmt.Errorf("agent: approval %s: %w", approval.ID, ErrApprovalExpired)
}

func seconds(n, fallback int) time.Duration {
	if n == 0 {
		n = fallback
	}
	return time.Duration(max(1, n)) * time.Second
}

// sleepContext pauses for d or until ctx ends.
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
