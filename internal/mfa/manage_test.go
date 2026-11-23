package mfa

// Factor management and MFA enforcement, run on memstore and SQLite.

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

const manageAt = "2026-06-09 12:00:00"

func (h *harness) managed(t *testing.T, id string, confirmed, isDefault bool, createdAt string) model.MFAFactor {
	t.Helper()
	f := model.MFAFactor{ID: id, Type: model.FactorTOTP, IsDefault: isDefault, CreatedAt: at(createdAt), UpdatedAt: at(manageAt)}
	if confirmed {
		f.ConfirmedAt = ptr(at(manageAt))
	}
	return h.insertFactor(t, f)
}

func (h *harness) user(t *testing.T, enforced bool) {
	t.Helper()
	must(t, h.repos.Users.Insert(ctx, model.User{ID: "user-1", Email: "ada@example.com", MFAEnforced: enforced, CreatedAt: at(manageAt), UpdatedAt: at(manageAt)}))
}

func TestListReturnsAllFactors(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, manageAt)
		h.managed(t, "a", true, false, manageAt)
		h.managed(t, "b", false, false, manageAt)
		h.insertFactor(t, model.MFAFactor{ID: "c", UserID: "someone-else", Type: model.FactorTOTP})
		fs, err := h.service(t).Factors(ctx, "user-1")
		must(t, err)
		if len(fs) != 2 {
			t.Fatalf("%+v", fs)
		}
	})
}

func TestUpdateRelabelsAndClears(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, manageAt)
		h.managed(t, "a", true, false, manageAt)
		s := h.service(t)
		got, err := s.UpdateFactor(ctx, "user-1", "a", ptr("Work phone"), false)
		must(t, err)
		if *got.Label != "Work phone" || *h.factor(t, "a").Label != "Work phone" {
			t.Fatalf("%+v", got)
		}
		if got, err = s.UpdateFactor(ctx, "user-1", "a", nil, false); err != nil || *got.Label != "Work phone" {
			t.Fatal("a nil label leaves it unchanged")
		}
		if _, err := s.UpdateFactor(ctx, "user-1", "a", ptr(""), false); err != nil || h.factor(t, "a").Label != nil {
			t.Fatal("an empty label clears it")
		}
	})
}

func TestUpdateRejectsALabelOver80Characters(t *testing.T) {
	h := newHarness(t, memDB(), manageAt)
	h.managed(t, "a", true, false, manageAt)
	s := h.service(t)
	if _, err := s.UpdateFactor(ctx, "user-1", "a", ptr(strings.Repeat("é", 80)), false); err != nil {
		t.Fatal("80 characters fit, whatever their bytes:", err)
	}
	_, err := s.UpdateFactor(ctx, "user-1", "a", ptr(strings.Repeat("x", 81)), false)
	var pe *PolicyError
	if !errors.Is(err, ErrInvalidFactorState) || !errors.As(err, &pe) || pe.Message != "A factor label may be at most 80 characters." {
		t.Fatal(err)
	}
}

func TestUpdateMakesDefaultAndUnsetsThePrevious(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, manageAt)
		h.managed(t, "a", true, true, manageAt)
		h.managed(t, "b", true, false, manageAt)
		got, err := h.service(t).UpdateFactor(ctx, "user-1", "b", nil, true)
		must(t, err)
		if !got.IsDefault || !h.factor(t, "b").IsDefault || h.factor(t, "a").IsDefault {
			t.Fatal("the previous default is cleared")
		}
	})
}

func TestCannotDefaultAnUnconfirmedFactor(t *testing.T) {
	h := newHarness(t, memDB(), manageAt)
	h.managed(t, "a", false, false, manageAt)
	_, err := h.service(t).UpdateFactor(ctx, "user-1", "a", nil, true)
	var pe *PolicyError
	if !errors.As(err, &pe) || !errors.Is(err, ErrInvalidFactorState) || pe.Message != "Only a confirmed factor can be the default." {
		t.Fatal(err)
	}
}

func TestUpdateRejectsAForeignFactor(t *testing.T) {
	h := newHarness(t, memDB(), manageAt)
	h.insertFactor(t, model.MFAFactor{ID: "c", UserID: "someone-else", Type: model.FactorTOTP})
	s := h.service(t)
	for _, id := range []string{"missing", "c"} {
		if _, err := s.UpdateFactor(ctx, "user-1", id, ptr("x"), false); !errors.Is(err, ErrFactorNotFound) {
			t.Fatal(err)
		}
		if err := s.RemoveFactor(ctx, "user-1", id); !errors.Is(err, ErrFactorNotFound) {
			t.Fatal(err)
		}
	}
}

func TestRemoveDeletesAndEmits(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, manageAt)
		h.user(t, false)
		h.managed(t, "a", true, false, manageAt)
		h.managed(t, "b", true, false, manageAt)
		must(t, h.service(t).RemoveFactor(ctx, "user-1", "a"))
		if _, err := h.repos.MFAFactors.Get(ctx, "a"); err == nil {
			t.Fatal("removed")
		}
		if ev := ofType[event.MFAFactorRemoved](h.events); len(ev) != 1 || ev[0] != (event.MFAFactorRemoved{UserID: "user-1", FactorID: "a"}) {
			t.Fatalf("%+v", ev)
		}
	})
}

func TestRemovingTheLastConfirmedFactorIsBlockedWhenEnforced(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, manageAt)
		h.user(t, true)
		h.managed(t, "a", true, false, manageAt)
		h.managed(t, "pending", false, false, manageAt)
		err := h.service(t).RemoveFactor(ctx, "user-1", "a")
		var pe *PolicyError
		if !errors.Is(err, ErrLastFactorProtected) || !errors.As(err, &pe) || pe.Message != "Enrol another factor before removing your last one." {
			t.Fatal(err)
		}
		h.factor(t, "a")
	})
}

// Of two concurrent removals of an enforced user's two factors, one is refused.
func TestConcurrentRemovalsLeaveAnEnforcedUserAFactor(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, manageAt)
		h.user(t, true)
		for round := range 10 {
			ids := []string{fmt.Sprintf("a%d", round), fmt.Sprintf("b%d", round)}
			for _, id := range ids {
				h.managed(t, id, true, false, manageAt)
			}
			errs := make([]error, len(ids))
			var wg sync.WaitGroup
			for i, id := range ids {
				wg.Go(func() { errs[i] = h.service(t).RemoveFactor(ctx, "user-1", id) })
			}
			wg.Wait()
			left, err := h.repos.MFAFactors.ListByUser(ctx, "user-1")
			must(t, err)
			if len(left) != 1 || (errs[0] == nil) == (errs[1] == nil) || !errors.Is(errors.Join(errs...), ErrLastFactorProtected) {
				t.Fatalf("round %d: %d factors left, %v", round, len(left), errs)
			}
			must(t, h.repos.MFAFactors.Delete(ctx, left[0]))
		}
	})
}

func TestRemovingTheLastFactorIsBlockedByTheGlobalSwitch(t *testing.T) {
	h := newHarness(t, memDB(), manageAt)
	h.managed(t, "a", true, false, manageAt) // no user row: only the switch enforces
	s := h.service(t, func(c *Config) { c.Auth.MFA.Enforce = true })
	if err := s.RemoveFactor(ctx, "user-1", "a"); !errors.Is(err, ErrLastFactorProtected) {
		t.Fatal(err)
	}
}

func TestRemovingAPendingFactorIsAllowedWhenEnforced(t *testing.T) {
	h := newHarness(t, memDB(), manageAt)
	h.user(t, true)
	h.managed(t, "pending", false, false, manageAt)
	must(t, h.service(t).RemoveFactor(ctx, "user-1", "pending"))
}

func TestRemovingTheLastFactorIsAllowedWhenNotEnforced(t *testing.T) {
	h := newHarness(t, memDB(), manageAt)
	h.user(t, false)
	h.managed(t, "a", true, true, manageAt)
	must(t, h.service(t).RemoveFactor(ctx, "user-1", "a"))
	if fs, _ := h.repos.MFAFactors.ListByUser(ctx, "user-1"); len(fs) != 0 {
		t.Fatal("removed")
	}
}

func TestRemovingADefaultPromotesTheOldestConfirmedFactor(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, manageAt)
		h.user(t, false)
		h.managed(t, "a", true, true, manageAt)
		h.managed(t, "newer", true, false, "2026-06-05 09:00:00")
		h.managed(t, "older", true, false, "2026-06-01 09:00:00")
		h.managed(t, "oldest-pending", false, false, "2026-05-01 09:00:00")
		must(t, h.service(t).RemoveFactor(ctx, "user-1", "a"))
		if !h.factor(t, "older").IsDefault || h.factor(t, "newer").IsDefault || h.factor(t, "oldest-pending").IsDefault {
			t.Fatal("the oldest remaining confirmed factor becomes default")
		}
	})
}

func TestIsEnforced(t *testing.T) {
	h := newHarness(t, memDB(), manageAt)
	s := h.service(t)
	if on, err := s.IsEnforced(ctx, "user-1"); err != nil || on {
		t.Fatal("an unknown user is not enforced")
	}
	h.user(t, true)
	if on, err := s.IsEnforced(ctx, "user-1"); err != nil || !on {
		t.Fatal("the per-user flag enforces")
	}
}
