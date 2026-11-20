package ratelimit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/univeros/polaris-go/cache"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
)

var ctx = context.Background()

// 2026-06-09 12:00:00 UTC, as the upstream middleware test.
var instant = time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)

func newStore() (*CacheStore, *clock.Frozen) {
	clk := clock.NewFrozen(instant)
	return NewCacheStore(cache.NewMemory(clk), clk), clk
}

func TestBudgetsAreCountedPerPolicyAndKey(t *testing.T) {
	store, clk := newStore()
	login := config.RateLimit{Limit: 2, Window: time.Minute, KeyPrefix: "auth.login"}
	register := config.RateLimit{Limit: 5, Window: time.Minute, KeyPrefix: "auth.register"}

	first, err := Check(ctx, store, login, "203.0.113.7")
	if err != nil {
		t.Fatal(err)
	}
	h := Headers(first, clk.Now())
	if h.Get("X-RateLimit-Limit") != "2" || h.Get("X-RateLimit-Remaining") != "1" || h.Get("Retry-After") != "" {
		t.Fatalf("first hit headers = %v", h)
	}
	if _, err := Check(ctx, store, login, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}

	blocked, _ := Check(ctx, store, login, "203.0.113.7")
	if blocked.Allowed {
		t.Fatal("third hit must be refused")
	}
	h = Headers(blocked, clk.Now())
	// The window is [12:00:00, 12:01:00): reset at 12:01:00, 60 s away.
	reset := instant.Add(time.Minute).Unix()
	if h.Get("Retry-After") != "60" || h.Get("X-RateLimit-Remaining") != "0" || h.Get("X-RateLimit-Limit") != "2" || h.Get("X-RateLimit-Reset") != itoa(reset) {
		t.Fatalf("blocked headers = %v", h)
	}

	if other, _ := Check(ctx, store, login, "198.51.100.1"); !other.Allowed {
		t.Fatal("another key has its own budget")
	}
	if reg, _ := Check(ctx, store, register, "203.0.113.7"); !reg.Allowed || reg.Remaining != 4 {
		t.Fatalf("another policy has its own budget: %+v", reg)
	}
}

func TestTheWindowResetsOnTheBucketBoundary(t *testing.T) {
	store, clk := newStore()
	clk.Advance(50 * time.Second)
	r, _ := store.Hit(ctx, "k", 1, time.Minute)
	if !r.Allowed || !r.ResetAt.Equal(instant.Add(time.Minute)) {
		t.Fatalf("first = %+v", r)
	}
	if r, _ = store.Hit(ctx, "k", 1, time.Minute); r.Allowed {
		t.Fatal("over budget")
	}
	if got := r.RetryAfter(clk.Now()); got != 10*time.Second {
		t.Fatalf("retry after = %v", got)
	}
	clk.Advance(10 * time.Second)
	if r, _ = store.Hit(ctx, "k", 1, time.Minute); !r.Allowed || r.Remaining != 0 {
		t.Fatalf("a new window starts at the boundary: %+v", r)
	}
}

func TestRetryAfterNeverGoesNegative(t *testing.T) {
	r := Result{ResetAt: instant}
	if got := r.RetryAfter(instant.Add(time.Hour)); got != 0 {
		t.Fatalf("retry after = %v", got)
	}
	// Sub-second precision of now is floored, as PHP's integer timestamps.
	if got := r.RetryAfter(instant.Add(-1500 * time.Millisecond)); got != 2*time.Second {
		t.Fatalf("retry after = %v", got)
	}
}

func TestRejectsAWindowBelowOneSecond(t *testing.T) {
	store, _ := newStore()
	if _, err := store.Hit(ctx, "k", 1, 500*time.Millisecond); err == nil {
		t.Fatal("want an error")
	}
}

type failing struct{ cache.Cache }

func (failing) Get(context.Context, string) ([]byte, bool, error) {
	return nil, false, errors.New("down")
}

type failingSet struct{ cache.Cache }

func (failingSet) Set(context.Context, string, []byte, time.Duration) error {
	return errors.New("down")
}

func TestPropagatesCacheErrors(t *testing.T) {
	clk := clock.NewFrozen(instant)
	if _, err := NewCacheStore(failing{cache.NewMemory(clk)}, clk).Hit(ctx, "k", 1, time.Minute); err == nil {
		t.Fatal("want the Get error")
	}
	if _, err := NewCacheStore(failingSet{cache.NewMemory(clk)}, clk).Hit(ctx, "k", 1, time.Minute); err == nil {
		t.Fatal("want the Set error")
	}
}

type corrupt struct{ cache.Cache }

func (corrupt) Get(context.Context, string) ([]byte, bool, error) { return []byte("x"), true, nil }

func TestAnUnreadableCounterIsAnError(t *testing.T) {
	clk := clock.NewFrozen(instant)
	if _, err := NewCacheStore(corrupt{cache.NewMemory(clk)}, clk).Hit(ctx, "k", 1, time.Minute); err == nil {
		t.Fatal("want an error")
	}
}

func TestConcurrentHitsNeverExceedTheBudget(t *testing.T) {
	store, _ := newStore()
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			if r, err := store.Hit(ctx, "burst", 10, time.Minute); err == nil && r.Allowed {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if allowed.Load() != 10 {
		t.Fatalf("%d hits allowed, want exactly 10", allowed.Load())
	}
}

func TestNilClockMeansSystemTime(t *testing.T) {
	if r, err := NewCacheStore(cache.NewMemory(nil), nil).Hit(ctx, "k", 1, time.Minute); err != nil || !r.Allowed {
		t.Fatalf("%+v %v", r, err)
	}
}
