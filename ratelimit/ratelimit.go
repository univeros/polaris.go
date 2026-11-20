// Package ratelimit counts requests in fixed windows and computes the rate-limit headers
// (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset and, when refused, Retry-After).
//
// [CacheStore] is the default [Store], over any cache.Cache. The HTTP middleware applies [Check]
// with a config.RateLimit policy, answers 429 when the result is not allowed, and sets [Headers]
// either way.
package ratelimit

import (
	"context"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
)

// Store counts hits per key in fixed windows. Implementations are safe for concurrent use.
type Store interface {
	// Hit records one hit on key unless the window already holds limit hits.
	Hit(ctx context.Context, key string, limit int, window time.Duration) (Result, error)
}

// Result is the outcome of one hit and the counters the headers report.
type Result struct {
	Allowed   bool
	Limit     int
	Remaining int
	ResetAt   time.Time // end of the current window, whole seconds
}

// RetryAfter is how long until the window resets, never negative, in whole seconds.
func (r Result) RetryAfter(now time.Time) time.Duration {
	return time.Duration(max(0, r.ResetAt.Unix()-now.Unix())) * time.Second
}

// Check applies policy to key (typically the client IP or the user id).
func Check(ctx context.Context, s Store, policy config.RateLimit, key string) (Result, error) {
	return s.Hit(ctx, policy.KeyPrefix+"."+key, policy.Limit, policy.Window)
}

// Headers returns the rate-limit headers for r: X-RateLimit-Limit, -Remaining and -Reset (Unix
// seconds) and, when refused, Retry-After (seconds) with Remaining 0.
func Headers(r Result, now time.Time) http.Header {
	h := http.Header{}
	remaining := r.Remaining
	if !r.Allowed {
		h.Set("Retry-After", itoa(int64(r.RetryAfter(now)/time.Second)))
		remaining = 0
	}
	h.Set("X-RateLimit-Limit", strconv.Itoa(r.Limit))
	h.Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	h.Set("X-RateLimit-Reset", itoa(r.ResetAt.Unix()))
	return h
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// CacheStore is a fixed-window counter per key in a cache.Cache: one bucket per window, the
// counter expiring with the window.
type CacheStore struct {
	cache cache.Cache
	clock clock.Clock
	locks [64]sync.Mutex
}

// NewCacheStore returns a Store over c; a nil clk means the system clock.
func NewCacheStore(c cache.Cache, clk clock.Clock) *CacheStore {
	if clk == nil {
		clk = clock.System{}
	}
	return &CacheStore{cache: c, clock: clk}
}

// Hit implements Store.
//
// The read-then-write is serialised per key inside this process, so concurrent requests cannot
// overspend a budget here. Across processes sharing one cache it is not atomic, as upstream.
func (s *CacheStore) Hit(ctx context.Context, key string, limit int, window time.Duration) (Result, error) {
	seconds := int64(window / time.Second)
	if seconds < 1 {
		return Result{}, fmt.Errorf("ratelimit: window %v is below one second", window)
	}
	now := s.clock.Now().Unix()
	bucket := now / seconds
	resetAt := time.Unix((bucket+1)*seconds, 0).UTC()

	h := fnv.New128a()
	h.Write([]byte(key))
	sum := h.Sum(nil)
	cacheKey := fmt.Sprintf("polaris.rate.%s.%d", hex.EncodeToString(sum), bucket)

	// ponytail: 64 striped locks; a backend with atomic increments can implement Store directly.
	mu := &s.locks[sum[0]%64]
	mu.Lock()
	defer mu.Unlock()

	count := 0
	raw, ok, err := s.cache.Get(ctx, cacheKey)
	if err != nil {
		return Result{}, fmt.Errorf("ratelimit: read counter: %w", err)
	}
	if ok {
		if count, err = strconv.Atoi(string(raw)); err != nil {
			return Result{}, fmt.Errorf("ratelimit: counter %q is not a number: %w", raw, err)
		}
	}
	if count >= limit {
		return Result{Allowed: false, Limit: limit, Remaining: 0, ResetAt: resetAt}, nil
	}
	if err := s.cache.Set(ctx, cacheKey, []byte(strconv.Itoa(count+1)), window); err != nil {
		return Result{}, fmt.Errorf("ratelimit: write counter: %w", err)
	}
	return Result{Allowed: true, Limit: limit, Remaining: max(0, limit-(count+1)), ResetAt: resetAt}, nil
}
