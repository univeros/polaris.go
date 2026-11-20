package orgs

import (
	"errors"
	"sync"
	"testing"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
)

// race runs every fn at once and returns their errors.
func race(fns ...func() error) []error {
	errs := make([]error, len(fns))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, fn := range fns {
		wg.Go(func() {
			<-start
			errs[i] = fn()
		})
	}
	close(start)
	wg.Wait()
	return errs
}

// wantOneWinner fails unless exactly one call succeeded and every other one was refused with
// kind (never an infrastructure error such as a lock timeout).
func wantOneWinner(t *testing.T, errs []error, kind error) {
	t.Helper()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, kind):
			t.Fatalf("err = %v; want nil or %v", err, kind)
		}
	}
	if ok != 1 {
		t.Fatalf("%d calls succeeded; want exactly 1 (%v)", ok, errs)
	}
}

func TestConcurrentAcceptsSpendAnInvitationOnce(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, owner := f.orgOwnedBy(t, "founder@example.com")
		_, err := f.svc.Invite(ctx, owner, org, "invitee@example.com", []string{"member"})
		must(t, err)
		token := lastInviteToken(t, f)
		invitee := f.user(t, "invitee@example.com")

		accept := func() error { _, err := f.svc.AcceptInvitation(ctx, invitee, token); return err }
		wantOneWinner(t, race(accept, accept, accept, accept), ErrInvalidInvitation)
		if n := len(ofType[event.MemberJoined](f.events)); n != 1 {
			t.Errorf("member.joined dispatched %d times", n)
		}
		if n := f.count(t, "auth_membership_roles", nil); n != 2 { // the owner's and the invitee's
			t.Errorf("membership role links = %d", n)
		}
	})
}

// activeOwners counts the organization's active memberships holding its owner role.
func activeOwners(t *testing.T, f *fixture, org string) int {
	t.Helper()
	links, err := f.r.MembershipRoles.ListByRole(ctx, f.roleID(t, org, "owner"))
	must(t, err)
	n := 0
	for _, l := range links {
		m, err := f.r.Memberships.Get(ctx, l.MembershipID)
		must(t, err)
		if m.Status == model.MembershipStatusActive {
			n++
		}
	}
	return n
}

// Two owners each step down at the same time: one wins, the other hits the last-owner rule, never
// zero owners, whichever owner-changing write they use.
func TestConcurrentOwnerChangesNeverOrphanTheOrganization(t *testing.T) {
	ops := map[string]func(f *fixture, actor, org, target string) error{
		"remove": func(f *fixture, actor, org, target string) error { return f.svc.RemoveMember(ctx, actor, org, target) },
		"demote": func(f *fixture, actor, org, target string) error {
			return f.svc.ChangeMemberRoles(ctx, actor, org, target, []string{"member"})
		},
		"suspend": func(f *fixture, actor, org, target string) error {
			return f.svc.ChangeMemberStatus(ctx, actor, org, target, model.MembershipStatusSuspended)
		},
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			backends(t, func(t *testing.T, f *fixture) {
				for range 5 {
					org, a := f.orgOwnedBy(t, repository.NewID()+"@example.com")
					b := f.member(t, org, repository.NewID()+"@example.com", model.MembershipStatusActive, "owner")
					wantOneWinner(t, race(
						func() error { return op(f, a, org, a) },
						func() error { return op(f, b, org, b) },
					), ErrConflict)
					if n := activeOwners(t, f, org); n != 1 {
						t.Fatalf("active owners = %d; want 1", n)
					}
				}
			})
		})
	}
}

// Mixed writes on one organization: every owner but one may go, never the last.
func TestConcurrentMixedOwnerChangesKeepAnOwner(t *testing.T) {
	backends(t, func(t *testing.T, f *fixture) {
		org, a := f.orgOwnedBy(t, "a@example.com")
		b := f.member(t, org, "b@example.com", model.MembershipStatusActive, "owner")
		c := f.member(t, org, "c@example.com", model.MembershipStatusActive, "owner")
		errs := race(
			func() error { return f.svc.RemoveMember(ctx, a, org, b) },
			func() error { return f.svc.ChangeMemberRoles(ctx, b, org, c, []string{"admin"}) },
			func() error { return f.svc.ChangeMemberStatus(ctx, c, org, a, model.MembershipStatusSuspended) },
		)
		ok := 0
		for _, err := range errs {
			if err == nil {
				ok++
			} else if !errors.Is(err, ErrConflict) && !errors.Is(err, ErrNotFound) && !errors.Is(err, authz.ErrForbidden) {
				t.Fatalf("err = %v", err) // a loser may find its actor demoted, suspended or removed
			}
		}
		if ok == 0 || activeOwners(t, f, org) < 1 {
			t.Fatalf("errs = %v, active owners = %d", errs, activeOwners(t, f, org))
		}
		if f.count(t, "auth_organizations", store.Criteria{"id": org}) != 1 {
			t.Fatal("the lock must not change the organization")
		}
	})
}
