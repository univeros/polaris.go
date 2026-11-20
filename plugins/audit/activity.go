package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/store"
)

// DefaultActivityInterval is how often, at most, a user's last activity is written.
const DefaultActivityInterval = 5 * time.Minute

// Activity keeps last_active_at per user (polaris_audit_activity) from the events a live session
// produces (sign-in, refresh, MFA, organization switch), written at most once per interval: the
// cache remembers the last write.
type Activity struct {
	db       store.Adapter
	cache    cache.Cache
	clock    clock.Clock
	interval time.Duration
	logger   *slog.Logger
}

// NewActivity returns the tracker; an interval ≤ 0 means DefaultActivityInterval.
func NewActivity(db store.Adapter, c cache.Cache, clk clock.Clock, interval time.Duration, logger *slog.Logger) *Activity {
	if interval <= 0 {
		interval = DefaultActivityInterval
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Activity{db: db, cache: c, clock: clk, interval: interval, logger: logger}
}

// Listen is the event listener; a failed write is logged, never returned.
func (a *Activity) Listen(ctx context.Context, e event.Event) {
	var userID string
	switch e := e.(type) {
	case event.UserLoggedIn:
		userID = e.UserID
	case event.TokenRefreshed:
		userID = e.UserID
	case event.MFAVerified:
		userID = e.UserID
	case event.MFAStepUpCompleted:
		userID = e.UserID
	case event.OrganizationSwitched:
		userID = e.UserID
	default:
		return
	}
	if err := a.touch(ctx, userID); err != nil {
		a.logger.ErrorContext(ctx, "Audit activity not recorded", "user", userID, "reason", err.Error())
	}
}

func (a *Activity) touch(ctx context.Context, userID string) error {
	key := "polaris.audit.activity." + userID
	if _, hit, err := a.cache.Get(ctx, key); err != nil || hit {
		return err
	}
	now := a.clock.Now().UTC().Truncate(time.Second)
	n, err := a.db.Update(ctx, TableActivity, store.Criteria{"user_id": userID}, store.Data{"last_active_at": now})
	if err != nil {
		return err
	}
	if n == 0 {
		if err := a.db.Insert(ctx, TableActivity, store.Row{"user_id": userID, "last_active_at": now}); err != nil {
			return err
		}
	}
	return a.cache.Set(ctx, key, []byte(now.Format(dateAtom)), a.interval)
}

// LastActiveAt returns the user's last recorded activity; ok false when none.
func (a *Activity) LastActiveAt(ctx context.Context, userID string) (time.Time, bool, error) {
	r, err := a.db.FindOne(ctx, TableActivity, store.Criteria{"user_id": userID})
	if err != nil || r == nil {
		return time.Time{}, false, err
	}
	t, ok := r.Time("last_active_at")
	return t, ok, nil
}
