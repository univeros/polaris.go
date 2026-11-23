package mfa

// Recovery codes and their persistence, run on memstore and SQLite.

import (
	"regexp"
	"slices"
	"sync"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/store"
)

var recoveryFormat = regexp.MustCompile(`^[a-hjkmnp-z2-7]{5}-[a-hjkmnp-z2-7]{5}$`)

func issue(t *testing.T, s *Service, userID string) []string {
	t.Helper()
	codes, err := s.issueRecoveryCodes(ctx, userID)
	must(t, err)
	return codes
}

func remaining(t *testing.T, s *Service, userID string) int {
	t.Helper()
	n, err := s.RemainingRecoveryCodes(ctx, userID)
	must(t, err)
	return n
}

func verifyRecovery(t *testing.T, s *Service, userID, code string) bool {
	t.Helper()
	ok, err := s.VerifyRecoveryCode(ctx, userID, code)
	must(t, err)
	return ok
}

func TestIssuesTenUniqueFormattedCodes(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	codes := issue(t, h.service(t), "user-123")
	if len(codes) != RecoveryCodeCount || len(slices.Compact(slices.Sorted(slices.Values(codes)))) != RecoveryCodeCount {
		t.Fatalf("codes %v", codes)
	}
	for _, c := range codes {
		if !recoveryFormat.MatchString(c) {
			t.Errorf("malformed code %q", c)
		}
	}
}

func TestStoresCodesAsHashesNotPlaintext(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		codes := issue(t, h.service(t), "user-123")
		rows, err := h.repos.RecoveryCodes.ListUnusedByUser(ctx, "user-123")
		must(t, err)
		if len(rows) != RecoveryCodeCount {
			t.Fatalf("%d rows", len(rows))
		}
		hashes := make([]string, len(rows))
		for i, r := range rows {
			hashes[i] = r.CodeHash
			if !r.CreatedAt.Equal(at(otpInstant)) {
				t.Errorf("created_at %v", r.CreatedAt)
			}
		}
		for _, c := range codes {
			if slices.Contains(hashes, c) || !slices.Contains(hashes, h.pepper.Hash("recovery", c)) {
				t.Fatalf("code %q: only its keyed hash is stored", c)
			}
		}
	})
}

func TestVerifyAcceptsAValidCodeAndConsumesIt(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		s := h.service(t)
		codes := issue(t, s, "user-123")
		if !verifyRecovery(t, s, "user-123", codes[3]) {
			t.Fatal("a valid code authenticates")
		}
		if n := remaining(t, s, "user-123"); n != RecoveryCodeCount-1 {
			t.Fatalf("remaining %d", n)
		}
		used := ofType[event.MFARecoveryUsed](h.events)
		if len(used) != 1 || used[0] != (event.MFARecoveryUsed{UserID: "user-123", Remaining: RecoveryCodeCount - 1}) {
			t.Fatalf("%+v", used)
		}
	})
}

func TestVerifyRejectsAnUnknownCode(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		s := h.service(t)
		issue(t, s, "user-123")
		if verifyRecovery(t, s, "user-123", "aaaaa-bbbbb") {
			t.Fatal("an unknown code is refused")
		}
		if n := remaining(t, s, "user-123"); n != RecoveryCodeCount {
			t.Fatalf("a failed verify consumes nothing: remaining %d", n)
		}
		if len(ofType[event.MFARecoveryUsed](h.events)) != 0 {
			t.Fatal("no event")
		}
	})
}

func TestVerifyIsSingleUse(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		s := h.service(t)
		codes := issue(t, s, "user-123")
		if !verifyRecovery(t, s, "user-123", codes[2]) || verifyRecovery(t, s, "user-123", codes[2]) {
			t.Fatal("a code authenticates exactly once")
		}
	})
}

func TestVerifyDoesNotMatchAnotherUsersCode(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		s := h.service(t)
		alice := issue(t, s, "alice")
		issue(t, s, "bob")
		if verifyRecovery(t, s, "bob", alice[0]) {
			t.Fatal("codes are scoped to their owner")
		}
		if !verifyRecovery(t, s, "alice", alice[0]) {
			t.Fatal("the owner's code works")
		}
	})
}

func TestRegenerateInvalidatesThePriorBatchAndIssuesAFreshOne(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		s := h.service(t)
		old := issue(t, s, "user-123")
		fresh, err := s.RegenerateRecoveryCodes(ctx, "user-123")
		must(t, err)
		if len(fresh) != RecoveryCodeCount || remaining(t, s, "user-123") != RecoveryCodeCount {
			t.Fatal("only the fresh batch remains usable")
		}
		if verifyRecovery(t, s, "user-123", old[0]) {
			t.Fatal("a code from the prior batch no longer works")
		}
		if !verifyRecovery(t, s, "user-123", fresh[0]) {
			t.Fatal("a code from the fresh batch works")
		}
		if ev := ofType[event.MFARecoveryRegenerated](h.events); len(ev) != 1 || ev[0].UserID != "user-123" {
			t.Fatalf("%+v", ev)
		}
	})
}

// A new batch is the only one: the codes of an earlier enrolment do not outlive its factors.
func TestANewBatchRetiresTheOneBefore(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		s := h.service(t)
		old, fresh := issue(t, s, "user-123"), issue(t, s, "user-123")
		if remaining(t, s, "user-123") != RecoveryCodeCount || verifyRecovery(t, s, "user-123", old[0]) || !verifyRecovery(t, s, "user-123", fresh[0]) {
			t.Fatal("only the fresh batch remains usable")
		}
	})
}

func TestRemainingCountsOnlyUnusedCodes(t *testing.T) {
	h := newHarness(t, memDB(), otpInstant)
	s := h.service(t)
	codes := issue(t, s, "user-123")
	verifyRecovery(t, s, "user-123", codes[0])
	verifyRecovery(t, s, "user-123", codes[1])
	if n := remaining(t, s, "user-123"); n != RecoveryCodeCount-2 {
		t.Fatalf("remaining %d", n)
	}
}

func TestConcurrentVerifiesOfOneRecoveryCodeSpendItOnce(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(t, db, otpInstant)
		s := h.service(t)
		code := issue(t, s, "user-123")[0]
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 8 {
			wg.Go(func() {
				if ok, err := s.VerifyRecoveryCode(ctx, "user-123", code); err == nil && ok {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			})
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d verifies spent the code", wins)
		}
	})
}
