package agent

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func g(id, status, approvalID string) Grant {
	return Grant{ID: id, Capability: "demo.echo", Status: status, ApprovalID: approvalID}
}

func TestApprovals(t *testing.T) {
	t.Run("testItPollsAtTheIntervalSlowsDownOnA429AndReturnsTheApprovalsGrantsOnceActive", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(1000, 0)}
		pending := []Grant{g("g2", "pending", "ap1"), g("g1", "active", "")}
		active := []Grant{g("g2", "active", "ap1"), g("g1", "active", "")}
		answers := []func() ([]Grant, error){
			func() ([]Grant, error) { return pending, nil },
			func() ([]Grant, error) { return nil, &Error{Status: 429, Code: "request_failed"} },
			func() ([]Grant, error) { return pending, nil },
			func() ([]Grant, error) { return active, nil },
		}
		polls := 0
		a := approvalFixture()
		a.Interval, a.ExpiresIn = 5, 600
		grants, err := clock.waiter().wait(t.Context(), a, func(context.Context) ([]Grant, error) { polls++; return answers[polls-1]() }, 0)
		if err != nil || len(grants) != 1 || grants[0].ID != "g2" {
			t.Fatalf("grants %v, %v", grants, err)
		}
		if want := []time.Duration{5 * time.Second, 5 * time.Second, 10 * time.Second, 10 * time.Second}; !slices.Equal(clock.slept, want) {
			t.Fatalf("slept %v", clock.slept)
		}
	})

	t.Run("testADeniedGrantEndsTheWait", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(1000, 0)}
		for _, status := range []string{"denied", "revoked"} {
			_, err := clock.waiter().wait(t.Context(), approvalFixture(), func(context.Context) ([]Grant, error) { return []Grant{g("g1", status, "ap1")}, nil }, 0)
			if !errors.Is(err, ErrApprovalDenied) {
				t.Fatalf("%s: %v", status, err)
			}
		}
	})

	t.Run("testTheWaitExpiresWithTheApprovalAndNeverExceedsMaxAttempts", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(1000, 0)}
		polls := 0
		pending := func(context.Context) ([]Grant, error) { polls++; return []Grant{g("g1", "pending", "ap1")}, nil }
		a := approvalFixture()
		a.Interval, a.ExpiresIn = 5, 12
		if _, err := clock.waiter().wait(t.Context(), a, pending, 0); !errors.Is(err, ErrApprovalExpired) || polls != 2 {
			t.Fatalf("%v after %d polls", err, polls)
		}
		polls = 0
		a.Interval, a.ExpiresIn = 1, 600
		if _, err := clock.waiter().wait(t.Context(), a, pending, 3); !errors.Is(err, ErrApprovalExpired) || polls != 3 {
			t.Fatalf("bounded: %v after %d polls", err, polls)
		}
	})

	t.Run("testACancelledWaitStopsBeforePollingAndOtherErrorsAreRethrown", func(t *testing.T) {
		clock := &fakeClock{now: time.Unix(1000, 0)}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		polls := 0
		a := approvalFixture()
		a.Interval = 30
		_, err := clock.waiter().wait(ctx, a, func(context.Context) ([]Grant, error) { polls++; return nil, nil }, 0)
		if !errors.Is(err, context.Canceled) || polls != 0 {
			t.Fatalf("%v after %d polls", err, polls)
		}
		gone := &Error{Status: 401, Code: "invalid_jwt"}
		if _, err := clock.waiter().wait(t.Context(), approvalFixture(), func(context.Context) ([]Grant, error) { return nil, gone }, 0); !errors.Is(err, gone) {
			t.Fatalf("rethrown: %v", err)
		}
	})
}

func TestTheWaitSlowsDownOnSlowDownAndDefaultsAMissingIntervalAndExpiry(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1000, 0)}
	calls := 0
	_, err := clock.waiter().wait(t.Context(), Approval{ID: "ap1"}, func(context.Context) ([]Grant, error) {
		calls++
		if calls == 1 {
			return nil, &Error{Status: 400, Code: "slow_down"}
		}
		return []Grant{g("g1", "active", "ap1")}, nil
	}, 0)
	if err != nil || !slices.Equal(clock.slept, []time.Duration{5 * time.Second, 10 * time.Second}) {
		t.Fatalf("%v, slept %v", err, clock.slept)
	}
	if err := sleepContext(t.Context(), time.Millisecond); err != nil {
		t.Fatal(err)
	}
}
