package cache

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
)

var ctx = context.Background()

func newMemory() (*Memory, *clock.Frozen) {
	clk := clock.NewFrozen(time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))
	return NewMemory(clk), clk
}

func get(t *testing.T, c Cache, key string) ([]byte, bool) {
	t.Helper()
	v, ok, err := c.Get(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	return v, ok
}

func TestStoresAndFetchesAValue(t *testing.T) {
	c, _ := newMemory()
	if err := c.Set(ctx, "a", []byte("1"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if v, ok := get(t, c, "a"); !ok || string(v) != "1" {
		t.Fatalf("got %q, %v", v, ok)
	}
}

func TestReportsAMiss(t *testing.T) {
	c, _ := newMemory()
	if v, ok := get(t, c, "absent"); ok || v != nil {
		t.Fatalf("got %q, %v", v, ok)
	}
}

func TestDeleteRemovesAKey(t *testing.T) {
	c, _ := newMemory()
	_ = c.Set(ctx, "a", []byte("v"), time.Minute)
	if err := c.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if _, ok := get(t, c, "a"); ok {
		t.Fatal("deleted key still present")
	}
	if err := c.Delete(ctx, "never-set"); err != nil {
		t.Fatal("deleting an absent key is not an error")
	}
}

func TestANonPositiveTTLStoresNothingAndEvicts(t *testing.T) {
	c, _ := newMemory()
	_ = c.Set(ctx, "a", []byte("old"), time.Minute)
	for _, ttl := range []time.Duration{0, -5 * time.Second} {
		if err := c.Set(ctx, "a", []byte("1"), ttl); err != nil {
			t.Fatal(err)
		}
		if _, ok := get(t, c, "a"); ok {
			t.Fatalf("ttl %v: an expired TTL stores nothing", ttl)
		}
	}
}

func TestEntriesExpireWithTheClock(t *testing.T) {
	c, clk := newMemory()
	_ = c.Set(ctx, "a", []byte("v"), 60*time.Second)
	clk.Advance(59 * time.Second)
	if _, ok := get(t, c, "a"); !ok {
		t.Fatal("still fresh before its TTL")
	}
	clk.Advance(time.Second)
	if _, ok := get(t, c, "a"); ok {
		t.Fatal("expired at its TTL")
	}
}

func TestValuesAreCopied(t *testing.T) {
	c, _ := newMemory()
	in := []byte("abc")
	_ = c.Set(ctx, "a", in, time.Minute)
	in[0] = 'X'
	out, _ := get(t, c, "a")
	out[1] = 'Y'
	if again, _ := get(t, c, "a"); string(again) != "abc" {
		t.Fatalf("stored value aliased the caller's slice: %q", again)
	}
}

func TestRejectsInvalidKeys(t *testing.T) {
	c, _ := newMemory()
	for _, key := range []string{"", "a{b}", "a(b", "a/b", `a\b`, "a@b", "a:b"} {
		if _, _, err := c.Get(ctx, key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Get(%q) err = %v", key, err)
		}
		if err := c.Set(ctx, key, nil, time.Minute); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Set(%q) err = %v", key, err)
		}
		if err := c.Delete(ctx, key); !errors.Is(err, ErrInvalidKey) {
			t.Errorf("Delete(%q) err = %v", key, err)
		}
	}
}

func TestExpiredEntriesAreSweptOnWrite(t *testing.T) {
	c, clk := newMemory()
	for i := range sweepFloor - 1 {
		_ = c.Set(ctx, fmt.Sprintf("k%d", i), []byte("v"), time.Second)
	}
	clk.Advance(2 * time.Second)
	_ = c.Set(ctx, "fresh", []byte("v"), time.Minute)
	if n := c.len(); n != 1 {
		t.Fatalf("%d entries after the sweep, want 1", n)
	}
}

func TestIsSafeForConcurrentUse(t *testing.T) {
	c, _ := newMemory()
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			key := fmt.Sprintf("k%d", i%5)
			_ = c.Set(ctx, key, []byte("v"), time.Minute)
			_, _, _ = c.Get(ctx, key)
			_ = c.Delete(ctx, key)
		})
	}
	wg.Wait()
}

func TestNilClockMeansSystemTime(t *testing.T) {
	c := NewMemory(nil)
	_ = c.Set(ctx, "a", []byte("v"), time.Minute)
	if _, ok := get(t, c, "a"); !ok {
		t.Fatal("value missing")
	}
}

func TestAddStoresOnlyWhenAbsent(t *testing.T) {
	c, clk := newMemory()
	if added, err := c.Add(ctx, "a", []byte("1"), time.Minute); err != nil || !added {
		t.Fatalf("first add = %v, %v", added, err)
	}
	if added, _ := c.Add(ctx, "a", []byte("2"), time.Minute); added {
		t.Fatal("a second add of a live key must not store")
	}
	if v, _ := get(t, c, "a"); string(v) != "1" {
		t.Fatalf("value = %q, want the first", v)
	}
	clk.Advance(time.Minute)
	if added, _ := c.Add(ctx, "a", []byte("3"), time.Minute); !added {
		t.Fatal("an expired key is absent")
	}
	if added, _ := c.Add(ctx, "b", []byte("1"), 0); added {
		t.Fatal("a ttl <= 0 stores nothing")
	}
	if _, err := c.Add(ctx, "", nil, time.Minute); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("err = %v", err)
	}
}

// Concurrent adds of one key: exactly one wins.
func TestConcurrentAddsOfOneKeyHaveOneWinner(t *testing.T) {
	c, _ := newMemory()
	var wins sync.WaitGroup
	won := make(chan struct{}, 64)
	for range 64 {
		wins.Go(func() {
			if added, err := c.Add(ctx, "jti", []byte("1"), time.Minute); err == nil && added {
				won <- struct{}{}
			}
		})
	}
	wins.Wait()
	if n := len(won); n != 1 {
		t.Fatalf("%d adds won; want 1", n)
	}
}
