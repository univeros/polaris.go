package session

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// stubbornCache fails the writes of the keys in fail, and those made with a ctx that ended.
type stubbornCache struct {
	*cache.Memory
	fail []string
	sets []string
}

func (c *stubbornCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	c.sets = append(c.sets, key)
	if err := ctx.Err(); err != nil {
		return err
	}
	if slices.Contains(c.fail, key) {
		return errCache
	}
	return c.Memory.Set(ctx, key, value, ttl)
}

// denying is a world with the denylist on, its service and its denylist, over a stubborn cache.
func denying(t *testing.T, db store.Adapter) (*harness, *stubbornCache, *Denylist, *Service) {
	t.Helper()
	h := newHarness(db, "2026-06-07 12:00:00")
	h.auth.AccessToken.Denylist = true
	c := &stubbornCache{Memory: h.cache}
	d := NewDenylist(c, h.clock, h.auth.AccessToken.TTL)
	return h, c, d, denyingService(t, h, d)
}

func denyingService(t *testing.T, h *harness, d *Denylist) *Service {
	t.Helper()
	pepper, err := security.NewPepper("test-application-key-0123456789ab")
	must(t, err)
	s, err := New(Config{DB: h.db, Pepper: pepper, Access: h.issuer, Principals: stubPrincipals{}, Denylist: d, Auth: h.auth, Clock: h.clock, Events: h.events})
	must(t, err)
	return s
}

func issue(t *testing.T, s *Service, userID, orgID string) token.IssuedTokens {
	t.Helper()
	issued, err := s.Issue(ctx, token.SessionPrincipal{UserID: userID, OrganizationID: orgID}, token.ClientContext{})
	must(t, err)
	return issued
}

// listed checks which sessions the denylist refuses.
func listed(t *testing.T, d *Denylist, want map[string]bool) {
	t.Helper()
	for id, want := range want {
		if got, err := d.IsSessionRevoked(ctx, id); got != want || err != nil {
			t.Errorf("session %s refused: %v %v, want %v", id, got, err, want)
		}
	}
}

func TestASessionsEntryOutlivesItsAccessTokens(t *testing.T) {
	clk := clock.NewFrozen(at("2026-06-10 12:00:00"))
	d := NewDenylist(cache.NewMemory(clk), clk, 900*time.Second)
	must(t, d.RevokeSessions(ctx))
	must(t, d.RevokeSessions(ctx, "s1", "s2"))
	listed(t, d, map[string]bool{"s1": true, "s2": true, "s3": false})
	if r, err := d.IsRevoked(ctx, "s1", clk.Now()); r || err != nil {
		t.Errorf("a session's entry read as a user's: %v %v", r, err)
	}
	clk.Advance(900*time.Second + sessionGrace - time.Second)
	listed(t, d, map[string]bool{"s1": true})
	clk.Advance(time.Second)
	listed(t, d, map[string]bool{"s1": false, "s2": false})

	listed(t, d, map[string]bool{"": false, "another:issuer/sid": false}) // no Polaris session's
	broken := NewDenylist(failingCache{}, nil, time.Minute)
	if err := broken.RevokeSessions(ctx, "s"); !errors.Is(err, errCache) {
		t.Error(err)
	}
	if _, err := broken.IsSessionRevoked(ctx, "s"); !errors.Is(err, errCache) {
		t.Error(err)
	}
}

// One entry that cannot be written does not keep the others from it, nor does a caller that left.
func TestAWriteToTheDenylistIsNotCutShort(t *testing.T) {
	clk := clock.NewFrozen(at("2026-06-10 12:00:00"))
	c := &stubbornCache{Memory: cache.NewMemory(clk), fail: []string{sessionKeyPrefix + "s1"}}
	d := NewDenylist(c, clk, time.Minute)
	gone, cancel := context.WithCancel(ctx)
	cancel()
	if err := d.RevokeSessions(gone, "s1", "s2"); !errors.Is(err, errCache) || errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	must(t, d.RevokeAllFor(gone, "user-1"))
	listed(t, d, map[string]bool{"s1": false, "s2": true})
}

// Every way to end sessions records those it ends, and those only; with the denylist off it records
// none.
func TestEndingSessionsRecordsThem(t *testing.T) {
	type world struct{ a, b, moved, other token.IssuedTokens }
	for name, tc := range map[string]struct {
		end  func(s *Service, w world) error
		want func(w world) []string
	}{
		"Logout": {func(s *Service, w world) error { return s.Logout(ctx, w.a.SessionID) }, func(w world) []string { return []string{w.a.SessionID} }},
		"Revoke": {func(s *Service, w world) error {
			_, err := s.Revoke(ctx, "user-1", w.a.SessionID)
			return err
		}, func(w world) []string { return []string{w.a.SessionID} }},
		"Revoke, another user's": {func(s *Service, w world) error {
			_, err := s.Revoke(ctx, "user-1", w.other.SessionID)
			return err
		}, func(world) []string { return nil }},
		"RevokeFamily, unknown": {func(s *Service, _ world) error { return s.RevokeFamily(ctx, "no/such:session", model.RevokedLogout) }, func(world) []string { return nil }},
		"RevokeAllExcept": {func(s *Service, w world) error {
			_, err := s.RevokeAllExcept(ctx, "user-1", w.a.SessionID, model.RevokedPasswordChange)
			return err
		}, func(w world) []string { return []string{w.b.SessionID, w.moved.SessionID} }},
		"RevokeAllExcept, none kept": {func(s *Service, w world) error {
			_, err := s.RevokeAllExcept(ctx, "user-1", "", model.RevokedPasswordChange)
			return err
		}, func(w world) []string { return []string{w.a.SessionID, w.b.SessionID, w.moved.SessionID} }},
		"RevokeAll": {func(s *Service, w world) error {
			_, err := s.RevokeAll(ctx, "user-1", model.RevokedAdmin)
			return err
		}, func(w world) []string { return []string{w.a.SessionID, w.b.SessionID, w.moved.SessionID} }},
		"RevokeAllForOrganization": {func(s *Service, _ world) error {
			return s.RevokeAllForOrganization(ctx, "user-1", "org-1", model.RevokedAdmin)
		}, func(w world) []string { return []string{w.a.SessionID} }},
		"a replayed refresh token": {func(s *Service, w world) error {
			if _, err := s.Refresh(ctx, w.a.RefreshToken, token.ClientContext{}); err != nil {
				return err
			}
			if _, err := s.Refresh(ctx, w.a.RefreshToken, token.ClientContext{}); !errors.Is(err, ErrRefreshReuse) {
				return errors.Join(errors.New("no reuse"), err)
			}
			return nil
		}, func(w world) []string { return []string{w.a.SessionID} }},
	} {
		t.Run(name, func(t *testing.T) {
			backends(t, func(t *testing.T, db store.Adapter) {
				h, c, d, s := denying(t, db)
				w := world{a: issue(t, s, "user-1", "org-1"), b: issue(t, s, "user-1", "org-2"), moved: issue(t, s, "user-1", "org-1"), other: issue(t, s, "user-2", "org-1")}
				// A rotated ancestor in org-1, the live token in org-2.
				_, err := s.Refresh(ctx, w.moved.RefreshToken, token.ClientContext{})
				must(t, err)
				_, err = s.SwitchOrganization(ctx, "user-1", "org-2", w.moved.SessionID)
				must(t, err)
				// Another user's session, ended a moment ago while the denylist was off.
				h.auth.AccessToken.Denylist = false
				off := denyingService(t, h, d)
				stranger := issue(t, off, "user-2", "org-1")
				must(t, off.Logout(ctx, stranger.SessionID))
				if len(c.sets) != 0 {
					t.Errorf("the denylist is off: wrote %v", c.sets)
				}

				must(t, tc.end(s, w))
				listed(t, d, map[string]bool{stranger.SessionID: false})
				ended := tc.want(w)
				want := map[string]bool{}
				for _, id := range []string{w.a.SessionID, w.b.SessionID, w.moved.SessionID, w.other.SessionID} {
					want[id] = slices.Contains(ended, id)
				}
				listed(t, d, want)
				for id, ended := range want {
					if active, _ := split(h.family(t, id)); ended == (len(active) > 0) {
						t.Errorf("session %s: recorded %v, live %v", id, ended, len(active) > 0)
					}
				}
			})
		})
	}
}

// A failing cache is an error, the database keeps what it did, and the same call again records the
// sessions although none has a live token left.
func TestAFailedRecordIsWrittenByTheSameCallAgain(t *testing.T) {
	for name, end := range map[string]func(s *Service, keep, gone token.IssuedTokens) error{
		"Logout": func(s *Service, _, gone token.IssuedTokens) error { return s.Logout(ctx, gone.SessionID) },
		"Revoke": func(s *Service, _, gone token.IssuedTokens) error {
			_, err := s.Revoke(ctx, "user-1", gone.SessionID)
			return err
		},
		"RevokeAllExcept": func(s *Service, keep, _ token.IssuedTokens) error {
			_, err := s.RevokeAllExcept(ctx, "user-1", keep.SessionID, model.RevokedPasswordChange)
			return err
		},
		"RevokeAllForOrganization": func(s *Service, _, _ token.IssuedTokens) error {
			return s.RevokeAllForOrganization(ctx, "user-1", "org-1", model.RevokedAdmin)
		},
		"a replayed refresh token": func(s *Service, _, gone token.IssuedTokens) error {
			if _, err := s.Refresh(ctx, gone.RefreshToken, token.ClientContext{}); !errors.Is(err, ErrRefreshReuse) {
				return err
			}
			return nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			backends(t, func(t *testing.T, db store.Adapter) {
				h, c, d, s := denying(t, db)
				keep, gone := issue(t, s, "user-1", "org-2"), issue(t, s, "user-1", "org-1")
				if name == "a replayed refresh token" {
					_, err := s.Refresh(ctx, gone.RefreshToken, token.ClientContext{})
					must(t, err)
				}
				c.fail = []string{sessionKeyPrefix + gone.SessionID}
				if err := end(s, keep, gone); !errors.Is(err, errCache) {
					t.Fatalf("a failing cache: %v", err)
				}
				if active, _ := split(h.family(t, gone.SessionID)); len(active) != 0 {
					t.Fatal("the session did not end")
				}
				if name == "a replayed refresh token" && len(ofType[event.RefreshReuseDetected](h.events)) != 1 {
					t.Error("a failing cache silenced the theft alert")
				}
				listed(t, d, map[string]bool{gone.SessionID: false})
				c.fail = nil
				must(t, end(s, keep, gone))
				listed(t, d, map[string]bool{gone.SessionID: true, keep.SessionID: false})
			})
		})
	}
}

// Sessions that ended too long ago to have a valid access token are not recorded again.
func TestLongEndedSessionsAreNotRecorded(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h, _, d, s := denying(t, db)
		old, keep := issue(t, s, "user-1", ""), issue(t, s, "user-1", "")
		must(t, s.Logout(ctx, old.SessionID))
		h.clock.Advance(h.auth.AccessToken.TTL + sessionGrace + time.Second)
		listed(t, d, map[string]bool{old.SessionID: false})
		_, err := s.RevokeAllExcept(ctx, "user-1", keep.SessionID, model.RevokedPasswordChange)
		must(t, err)
		listed(t, d, map[string]bool{old.SessionID: false, keep.SessionID: false})
	})
}

// racingIssuer runs before once, as an access token is about to be signed.
type racingIssuer struct {
	Issuer
	before func()
}

func (r *racingIssuer) Issue(c token.Claims) (string, error) {
	if f := r.before; f != nil {
		r.before = nil
		f()
	}
	return r.Issuer.Issue(c)
}

// An access token signed after its session ended, by a refresh, a step-up or an organization switch
// that committed before, is refused, whenever it says it was issued.
func TestATokenSignedAfterItsSessionEndedIsRefused(t *testing.T) {
	for name, sign := range map[string]func(s *Service, i token.IssuedTokens) error{
		"refresh": func(s *Service, i token.IssuedTokens) error {
			_, err := s.Refresh(ctx, i.RefreshToken, token.ClientContext{})
			return err
		},
		"refresh in place": func(s *Service, i token.IssuedTokens) error {
			_, err := s.Refresh(ctx, i.RefreshToken, token.ClientContext{})
			return err
		},
		"step-up": func(s *Service, i token.IssuedTokens) error {
			_, err := s.StepUp(ctx, "user-1", "org-1", i.SessionID)
			return err
		},
		"switch": func(s *Service, i token.IssuedTokens) error {
			_, err := s.SwitchOrganization(ctx, "user-1", "org-2", i.SessionID)
			return err
		},
	} {
		for how, end := range map[string]func(s *Service) error{
			"RevokeAll": func(s *Service) error {
				_, err := s.RevokeAll(ctx, "user-1", model.RevokedLogout)
				return err
			},
			"RevokeAllExcept": func(s *Service) error {
				_, err := s.RevokeAllExcept(ctx, "user-1", "", model.RevokedPasswordChange)
				return err
			},
		} {
			t.Run(name+"/"+how, func(t *testing.T) {
				backends(t, func(t *testing.T, db store.Adapter) {
					h, _, d, s := denying(t, db)
					h.auth.RefreshToken.Rotation = name != "refresh in place"
					issued := issue(t, s, "user-1", "org-1")
					raced := false
					s = denyingService(t, h, d)
					s.access = &racingIssuer{Issuer: h.issuer, before: func() {
						raced = true
						must(t, end(denyingService(t, h, d)))
						h.clock.Advance(sessionGrace - time.Second) // the signature is slow
					}}
					must(t, sign(s, issued))
					if !raced {
						t.Fatal("the race did not happen")
					}
					h.clock.Advance(h.auth.AccessToken.TTL) // the last second of the token
					listed(t, d, map[string]bool{issued.SessionID: true})
				})
			})
		}
	}
}

// A session opened by another connection since the revoking transaction's first read is recorded too
// (MySQL's repeatable read does not show it before the UPDATE ends it).
func TestASessionOpenedSinceTheTransactionBeganIsRecorded(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		if d := db.Dialect(); d != store.Postgres && d != store.MySQL {
			t.Skip("one transaction at a time")
		}
		_, _, d, s := denying(t, db)
		keep := issue(t, s, "user-1", "")
		var late token.IssuedTokens
		must(t, db.Tx(ctx, func(tx context.Context) error {
			if _, err := s.List(tx, "user-1", ""); err != nil {
				return err
			}
			late = issue(t, s, "user-1", "")
			_, err := s.RevokeAllExcept(tx, "user-1", keep.SessionID, model.RevokedPasswordChange)
			return err
		}))
		listed(t, d, map[string]bool{late.SessionID: true, keep.SessionID: false})
	})
}
