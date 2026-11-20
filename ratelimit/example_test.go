package ratelimit_test

import (
	"context"
	"fmt"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/ratelimit"
)

func ExampleCheck() {
	clk := clock.NewFrozen(time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC))
	store := ratelimit.NewCacheStore(cache.NewMemory(clk), clk)
	login := config.RateLimit{Limit: 1, Window: 5 * time.Minute, KeyPrefix: "auth.login"}

	for range 2 {
		r, err := ratelimit.Check(context.Background(), store, login, "203.0.113.7")
		if err != nil {
			panic(err)
		}
		h := ratelimit.Headers(r, clk.Now())
		fmt.Printf("allowed=%v remaining=%s retry-after=%q\n", r.Allowed, h.Get("X-RateLimit-Remaining"), h.Get("Retry-After"))
	}
	// Output:
	// allowed=true remaining=0 retry-after=""
	// allowed=false remaining=0 retry-after="300"
}
