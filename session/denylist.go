package session

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
)

const denylistKeyPrefix = "polaris.denylist.user."

// Denylist is the instant access-token revocation of docs/auth/security.md §3: logging out
// everywhere, disabling or erasing a user records a per-user watermark (Unix seconds) in the
// cache, and the denylist middleware rejects any access token of that user issued at or before
// it. One cache read per request, no per-token bookkeeping. Entries live one access-token TTL,
// after which every token they could affect has expired anyway, so a cache wipe only shortens
// the window back to the stateless default. Safe for concurrent use.
type Denylist struct {
	cache cache.Cache
	clock clock.Clock
	ttl   time.Duration
}

// NewDenylist returns a denylist over c whose entries live accessTokenTTL; a nil clk means
// clock.System. Share c between replicas or the watermark only holds on the replica that wrote it.
func NewDenylist(c cache.Cache, clk clock.Clock, accessTokenTTL time.Duration) *Denylist {
	if clk == nil {
		clk = clock.System{}
	}
	return &Denylist{cache: c, clock: clk, ttl: accessTokenTTL}
}

// RevokeAllFor revokes every access token of userID issued up to now.
func (d *Denylist) RevokeAllFor(ctx context.Context, userID string) error {
	stamp := strconv.FormatInt(d.clock.Now().Unix(), 10)
	if err := d.cache.Set(ctx, denylistKeyPrefix+userID, []byte(stamp), d.ttl); err != nil {
		return fmt.Errorf("session: denylist: %w", err)
	}
	return nil
}

// IsRevoked reports whether a token of userID issued at issuedAt falls inside the user's
// watermark. The boundary is fail-closed (issued in the watermark's second is revoked): such a
// token could be the evicted attacker's; a legitimate re-login in that second signs in again.
// An unreadable watermark reads as not revoked.
func (d *Denylist) IsRevoked(ctx context.Context, userID string, issuedAt time.Time) (bool, error) {
	v, ok, err := d.cache.Get(ctx, denylistKeyPrefix+userID)
	if err != nil {
		return false, fmt.Errorf("session: denylist: %w", err)
	}
	if !ok {
		return false, nil
	}
	watermark, err := strconv.ParseInt(string(v), 10, 64)
	return err == nil && issuedAt.Unix() <= watermark, nil
}
