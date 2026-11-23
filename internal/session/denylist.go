package session

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

const (
	denylistKeyPrefix = "polaris.denylist.user."
	ticketKeyPrefix   = "polaris.denylist.mfa."
)

// Denylist is the instant access-token revocation: logging out
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
	return d.stamp(ctx, denylistKeyPrefix+userID)
}

// RevokeTicketsFor revokes the login_mfa tickets of userID issued up to now, and no access token.
func (d *Denylist) RevokeTicketsFor(ctx context.Context, userID string) error {
	return d.stamp(ctx, ticketKeyPrefix+userID)
}

func (d *Denylist) stamp(ctx context.Context, key string) error {
	stamp := strconv.FormatInt(d.clock.Now().Unix(), 10)
	if err := d.cache.Set(ctx, key, []byte(stamp), d.ttl); err != nil {
		return fmt.Errorf("session: denylist: %w", err)
	}
	return nil
}

// IsRevoked reports whether a token of userID issued at issuedAt falls inside the user's
// watermark. The boundary is fail-closed (issued in the watermark's second is revoked): such a
// token could be the evicted attacker's; a legitimate re-login in that second signs in again.
// An unreadable watermark reads as not revoked.
func (d *Denylist) IsRevoked(ctx context.Context, userID string, issuedAt time.Time) (bool, error) {
	return d.stampedAt(ctx, denylistKeyPrefix+userID, issuedAt)
}

// ticketRevoked reports whether a login_mfa ticket of userID was issued before either watermark. The
// watermark's own second passes: a login right after a reset is the account holder's.
func (d *Denylist) ticketRevoked(ctx context.Context, userID string, issuedAt time.Time) (bool, error) {
	for _, prefix := range []string{denylistKeyPrefix, ticketKeyPrefix} {
		if revoked, err := d.stampedAt(ctx, prefix+userID, issuedAt.Add(time.Second)); err != nil || revoked {
			return revoked, err
		}
	}
	return false, nil
}

// stampedAt reports whether key's watermark is at or after issuedAt.
func (d *Denylist) stampedAt(ctx context.Context, key string, issuedAt time.Time) (bool, error) {
	v, ok, err := d.cache.Get(ctx, key)
	if err != nil {
		return false, fmt.Errorf("session: denylist: %w", err)
	}
	if !ok {
		return false, nil
	}
	watermark, err := strconv.ParseInt(string(v), 10, 64)
	return err == nil && issuedAt.Unix() <= watermark, nil
}
