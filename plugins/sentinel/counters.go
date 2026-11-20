package sentinel

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strconv"
	"sync"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
)

// CounterStore counts per key in fixed time windows, for the velocity and credential-stuffing
// signals. The default runs on the graph's cache; a host with Redis can implement it with INCR and
// EXPIRE for counts that are exact across replicas.
type CounterStore interface {
	// Increment adds one to key's current window and answers the new count.
	Increment(ctx context.Context, key string, window time.Duration) (int, error)
	// Count answers key's count in the current window.
	Count(ctx context.Context, key string, window time.Duration) (int, error)
	// Reset forgets key's current window (an operator's unblock).
	Reset(ctx context.Context, key string, window time.Duration) error
}

// CacheCounters is a CounterStore over a cache.Cache: one bucket per key and window, expiring
// with it, the read-then-write serialized per key inside the process.
type CacheCounters struct {
	cache cache.Cache
	clock clock.Clock
	locks [64]sync.Mutex
}

// NewCacheCounters returns counters over c; a nil clk means the system clock.
func NewCacheCounters(c cache.Cache, clk clock.Clock) *CacheCounters {
	if clk == nil {
		clk = clock.System{}
	}
	return &CacheCounters{cache: c, clock: clk}
}

func (s *CacheCounters) bucket(key string, window time.Duration) (string, *sync.Mutex) {
	h := fnv.New128a()
	h.Write([]byte(key))
	sum := h.Sum(nil)
	seconds := max(1, int64(window/time.Second))
	return fmt.Sprintf("polaris.sentinel.%s.%d", hex.EncodeToString(sum), s.clock.Now().Unix()/seconds), &s.locks[sum[0]%64]
}

func (s *CacheCounters) read(ctx context.Context, key string) (int, error) {
	raw, ok, err := s.cache.Get(ctx, key)
	if err != nil || !ok {
		return 0, err
	}
	n, _ := strconv.Atoi(string(raw))
	return n, nil
}

// Increment implements CounterStore.
func (s *CacheCounters) Increment(ctx context.Context, key string, window time.Duration) (int, error) {
	b, mu := s.bucket(key, window)
	// ponytail: per-process striped lock, as ratelimit.CacheStore; across replicas a shared cache
	// can lose concurrent increments (as upstream). Implement CounterStore on INCR for exact counts.
	mu.Lock()
	defer mu.Unlock()
	n, err := s.read(ctx, b)
	if err != nil {
		return 0, err
	}
	n++
	return n, s.cache.Set(ctx, b, []byte(strconv.Itoa(n)), window)
}

// Count implements CounterStore.
func (s *CacheCounters) Count(ctx context.Context, key string, window time.Duration) (int, error) {
	b, _ := s.bucket(key, window)
	return s.read(ctx, b)
}

// Reset implements CounterStore.
func (s *CacheCounters) Reset(ctx context.Context, key string, window time.Duration) error {
	b, _ := s.bucket(key, window)
	return s.cache.Delete(ctx, b)
}

// seenSet is a small set of hashes in the cache (the distinct emails an address tried), its TTL
// refreshed on each addition.
type seenSet struct {
	cache cache.Cache
	locks [64]sync.Mutex
}

const maxTrackedEmails = 200

// add puts member in the set under key and answers the set's size.
func (s *seenSet) add(ctx context.Context, key, member string, ttl time.Duration) (int, error) {
	h := fnv.New128a()
	h.Write([]byte(key))
	sum := h.Sum(nil)
	k := "polaris.sentinel.emails." + hex.EncodeToString(sum)
	mu := &s.locks[sum[0]%64]
	mu.Lock()
	defer mu.Unlock()
	var seen []string
	if raw, ok, err := s.cache.Get(ctx, k); err != nil {
		return 0, err
	} else if ok {
		_ = json.Unmarshal(raw, &seen)
	}
	for _, m := range seen {
		if m == member {
			return len(seen), nil
		}
	}
	if len(seen) >= maxTrackedEmails {
		return len(seen), nil
	}
	seen = append(seen, member)
	raw, _ := json.Marshal(seen)
	return len(seen), s.cache.Set(ctx, k, raw, ttl)
}

func (s *seenSet) reset(ctx context.Context, key string) error {
	h := fnv.New128a()
	h.Write([]byte(key))
	return s.cache.Delete(ctx, "polaris.sentinel.emails."+hex.EncodeToString(h.Sum(nil)))
}
