package session

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

const (
	denylistKeyPrefix = "polaris.denylist.user."
	ticketKeyPrefix   = "polaris.denylist.mfa."
	sessionKeyPrefix  = "polaris.denylist.session."

	// sessionGrace is how much longer than an access token a session's entry lives: a refresh or an
	// organization switch that committed before the session ended may sign its token a moment after,
	// and the clocks of two replicas differ.
	sessionGrace = time.Minute

	// writeTimeout bounds a write to the cache, all its keys together, so that a cache that is down
	// holds no caller for longer. The write does not stop with the request: what it records has
	// happened in the database already.
	writeTimeout = 5 * time.Second
)

// Denylist is the instant access-token revocation, in the cache. Ending a user's every session
// (logging out everywhere, disabling, erasing) records a per-user watermark (Unix seconds): the
// denylist middleware rejects any access token of that user issued at or before it. Ending a session
// records the session: the middleware rejects any access token that carries its sid, whenever it was
// issued, as an ended session never opens again. Two cache reads per request, no per-token
// bookkeeping. Entries live one access-token TTL (a session's, one minute more), after which every token
// they could affect has expired anyway, so a cache wipe only shortens the window back to the
// stateless default. Safe for concurrent use.
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
	return d.write(ctx, strconv.FormatInt(d.clock.Now().Unix(), 10), d.ttl, key)
}

// RevokeSessions revokes every access token of the sessions, whenever issued. One that cannot be
// written does not keep the others from it.
func (d *Denylist) RevokeSessions(ctx context.Context, sessionIDs ...string) error {
	keys := make([]string, len(sessionIDs))
	for i, id := range sessionIDs {
		keys[i] = sessionKeyPrefix + id
	}
	return d.write(ctx, "1", d.sessionTTL(), keys...)
}

// sessionTTL is how long a session's entry lives.
func (d *Denylist) sessionTTL() time.Duration { return d.ttl + sessionGrace }

func (d *Denylist) write(ctx context.Context, value string, ttl time.Duration, keys ...string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
	defer cancel()
	var errs []error
	for _, key := range keys {
		errs = append(errs, d.cache.Set(ctx, key, []byte(value), ttl))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("session: denylist: %w", err)
	}
	return nil
}

// IsSessionRevoked reports whether the session ended so recently that an access token of it may
// still be valid. An id that cannot be a cache key is no Polaris session's, and was never recorded.
func (d *Denylist) IsSessionRevoked(ctx context.Context, sessionID string) (bool, error) {
	key := sessionKeyPrefix + sessionID
	if cache.ValidateKey(key) != nil {
		return false, nil
	}
	_, revoked, err := d.cache.Get(ctx, key)
	if err != nil {
		return false, fmt.Errorf("session: denylist: %w", err)
	}
	return revoked, nil
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
