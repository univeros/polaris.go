package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

func TestListLogoutAndRevoke(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		a, err := s.Issue(ctx, principal(), token.ClientContext{IP: "198.51.100.1", UserAgent: "A"})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:01:00"))
		b, err := s.Issue(ctx, principal(), token.ClientContext{IP: "198.51.100.2"})
		must(t, err)
		other, err := s.Issue(ctx, token.SessionPrincipal{UserID: "user-2"}, token.ClientContext{})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:05:00"))
		_, err = s.Refresh(ctx, a.RefreshToken, token.ClientContext{})
		must(t, err)

		list, err := s.List(ctx, "user-1", b.SessionID)
		must(t, err)
		if len(list) != 2 {
			t.Fatalf("%+v", list)
		}
		byID := map[string]Info{list[0].ID: list[0], list[1].ID: list[1]}
		ia, ib := byID[a.SessionID], byID[b.SessionID]
		if ia.Current || !ib.Current || *ia.IP != "198.51.100.1" || *ia.UserAgent != "A" || ib.UserAgent != nil ||
			!ia.CreatedAt.Equal(at("2026-06-07 12:00:00")) || !ia.LastUsedAt.Equal(at("2026-06-07 12:05:00")) ||
			!ib.LastUsedAt.Equal(at("2026-06-07 12:01:00")) {
			t.Fatalf("%+v %+v", ia, ib)
		}

		// Another user's session is neither revealed nor revocable.
		if ok, err := s.Revoke(ctx, "user-1", other.SessionID); ok || err != nil {
			t.Fatalf("cross-user revoke %v %v", ok, err)
		}
		if ok, err := s.Revoke(ctx, "user-1", b.SessionID); !ok || err != nil {
			t.Fatalf("revoke %v %v", ok, err)
		}
		must(t, s.Logout(ctx, a.SessionID))
		if list, _ := s.List(ctx, "user-1", ""); len(list) != 0 {
			t.Fatalf("after logout %+v", list)
		}
		if list, _ := s.List(ctx, "user-2", ""); len(list) != 1 {
			t.Fatalf("user-2 %+v", list)
		}
		for _, r := range h.family(t, b.SessionID) {
			if *r.RevokedReason != model.RevokedLogout {
				t.Errorf("reason %s", *r.RevokedReason)
			}
		}
		// Expired sessions are not listed.
		h.clock.Set(at("2026-08-07 12:00:00"))
		if list, _ := s.List(ctx, "user-2", ""); len(list) != 0 {
			t.Fatalf("expired %+v", list)
		}
	})
}

func TestLogoutAllRevokesEverySessionAndWatermarks(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		for range 2 {
			_, err := s.Issue(ctx, principal(), token.ClientContext{})
			must(t, err)
		}
		must(t, s.LogoutAll(ctx, "user-1", token.ClientContext{IP: "203.0.113.1"}))
		ev := ofType[event.SessionsRevoked](h.events)
		if len(ev) != 1 || ev[0].Count != 2 || *ev[0].IP != "203.0.113.1" || ev[0].Reason != model.RevokedLogout || ev[0].UserID != "user-1" {
			t.Fatalf("%+v", ev)
		}
		if list, _ := s.List(ctx, "user-1", ""); len(list) != 0 {
			t.Fatal("sessions survive")
		}
		d := NewDenylist(h.cache, h.clock, h.auth.AccessToken.TTL)
		if revoked, err := d.IsRevoked(ctx, "user-1", h.clock.Now()); !revoked || err != nil {
			t.Fatal("no watermark")
		}
	})
}

func TestRevokeAllExceptKeepsOneAndDoesNotWatermark(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		keep, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		_, err = s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		n, err := s.RevokeAllExcept(ctx, "user-1", keep.SessionID, model.RevokedPasswordChange)
		if n != 1 || err != nil {
			t.Fatalf("%d %v", n, err)
		}
		list, _ := s.List(ctx, "user-1", keep.SessionID)
		if len(list) != 1 || list[0].ID != keep.SessionID {
			t.Fatalf("%+v", list)
		}
		if _, ok, _ := h.cache.Get(ctx, denylistKeyPrefix+"user-1"); ok {
			t.Fatal("keep-current revocation must not watermark")
		}
		if n, err := s.RevokeAll(ctx, "user-1", model.RevokedPasswordChange); n != 2 || err != nil {
			t.Fatalf("revoke all %d %v", n, err)
		}
		if len(h.events.events) != 0 {
			t.Fatal("RevokeAll dispatches no event")
		}
	})
}

// A session issued while the revoking transaction runs is revoked too: RevokeAll writes by user, not
// by the sessions it read. (MySQL's repeatable read shows the transaction the sessions as they were
// when it began; memstore and SQLite run one transaction at a time.)
func TestRevokeAllRevokesTheSessionsIssuedSinceItsTransactionBegan(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		if d := db.Dialect(); d != store.Postgres && d != store.MySQL {
			t.Skip("one transaction at a time")
		}
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		var late token.IssuedTokens
		must(t, db.Tx(ctx, func(tx context.Context) error {
			if _, err := s.List(tx, "user-1", ""); err != nil { // the transaction's first read
				return err
			}
			var err error
			if late, err = s.Issue(ctx, principal(), token.ClientContext{}); err != nil { // another connection
				return err
			}
			_, err = s.RevokeAll(tx, "user-1", model.RevokedAdmin)
			return err
		}))
		if list, err := s.List(ctx, "user-1", ""); err != nil || len(list) != 0 {
			t.Fatalf("live sessions %+v %v", list, err)
		}
		if _, err := s.Refresh(ctx, late.RefreshToken, token.ClientContext{}); err == nil {
			t.Fatal("a session issued before the revocation committed refreshes")
		}
	})
}

func TestRevokeAllForOrganizationFollowsTheLiveContext(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		moved, err := s.Issue(ctx, principal(), token.ClientContext{}) // org-1, then switched to org-2
		must(t, err)
		_, err = s.Refresh(ctx, moved.RefreshToken, token.ClientContext{})
		must(t, err)
		_, err = s.SwitchOrganization(ctx, "user-1", "org-2", moved.SessionID)
		must(t, err)
		stays, err := s.Issue(ctx, principal(), token.ClientContext{}) // org-1
		must(t, err)
		must(t, s.RevokeAllForOrganization(ctx, "user-1", "org-1", model.RevokedAdmin))
		list, _ := s.List(ctx, "user-1", "")
		if len(list) != 1 || list[0].ID != moved.SessionID {
			t.Fatalf("%+v", list)
		}
		for _, r := range h.family(t, stays.SessionID) {
			if *r.RevokedReason != model.RevokedAdmin {
				t.Errorf("reason %s", *r.RevokedReason)
			}
		}
	})
}

// failingCache fails every call.
type failingCache struct{}

var errCache = errors.New("cache down")

func (failingCache) Get(context.Context, string) ([]byte, bool, error)        { return nil, false, errCache }
func (failingCache) Set(context.Context, string, []byte, time.Duration) error { return errCache }
func (failingCache) Delete(context.Context, string) error                     { return errCache }
func (failingCache) Add(context.Context, string, []byte, time.Duration) (bool, error) {
	return false, errCache
}

func TestDenylist(t *testing.T) {
	clk := clock.NewFrozen(at("2026-06-10 12:00:00"))
	now := clk.Now()
	c := cache.NewMemory(clk)
	d := NewDenylist(c, clk, 900*time.Second)
	if r, _ := d.IsRevoked(ctx, "user-1", now); r {
		t.Fatal("unmarked user revoked")
	}
	must(t, d.RevokeAllFor(ctx, "user-1"))
	for _, c := range []struct {
		at   time.Time
		want bool
	}{{now.Add(-5 * time.Minute), true}, {now, true}, {now.Add(time.Second), false}} {
		if r, err := d.IsRevoked(ctx, "user-1", c.at); r != c.want || err != nil {
			t.Errorf("issued %v: %v %v", c.at, r, err)
		}
	}
	if r, _ := d.IsRevoked(ctx, "user-2", now); r {
		t.Error("other user revoked")
	}
	// Entries live one access TTL.
	clk.Advance(900 * time.Second)
	if r, _ := d.IsRevoked(ctx, "user-1", now); r {
		t.Error("watermark outlived the access TTL")
	}
	// A corrupted watermark reads as not revoked.
	must(t, c.Set(ctx, denylistKeyPrefix+"user-1", []byte("not-a-timestamp"), time.Hour))
	if r, err := d.IsRevoked(ctx, "user-1", now); r || err != nil {
		t.Errorf("corrupted: %v %v", r, err)
	}
	// Cache failures surface.
	broken := NewDenylist(failingCache{}, nil, time.Minute)
	if err := broken.RevokeAllFor(ctx, "u"); !errors.Is(err, errCache) {
		t.Error(err)
	}
	if _, err := broken.IsRevoked(ctx, "u", now); !errors.Is(err, errCache) {
		t.Error(err)
	}
}

func rsaKeys(t *testing.T) (pub, priv string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(t, err)
	pub = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	priv = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return pub, priv
}

// The MFA login ticket: minted, authenticated, refused when foreign or misused.
func TestMFATickets(t *testing.T) {
	pub, priv := rsaKeys(t)
	otherPub, otherPriv := rsaKeys(t)
	clk := clock.NewFrozen(at("2026-06-09 12:00:00"))
	cfg := token.Config{PublicKey: pub, PrivateKey: priv, KeyID: "test-kid-1", Issuer: "https://auth.polaris.test",
		Audience: "https://api.polaris.test", TTL: 900 * time.Second, Clock: clk}
	tickets, err := NewMFATickets(cfg, 300*time.Second)
	must(t, err)

	ticket, err := tickets.Issue("user-123")
	must(t, err)
	if sub, err := tickets.Authenticate(ticket); sub != "user-123" || err != nil {
		t.Fatalf("%q %v", sub, err)
	}
	access, err := token.New(cfg)
	must(t, err)
	if _, err := access.Parse(ticket); !errors.Is(err, token.ErrInvalidToken) {
		t.Fatal("a ticket must never pass as an access token")
	}

	reject := func(name, raw string) {
		t.Helper()
		if _, err := tickets.Authenticate(raw); !errors.Is(err, token.ErrInvalidToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	claims, err := token.AccessClaims{Subject: "user-123", ID: "jti-1"}.Claims()
	must(t, err)
	raw, err := access.Issue(claims)
	must(t, err)
	reject("access token", raw)
	raw, err = access.Issue(token.Claims{}.With("sub", "user-123").With("jti", "jti-1").With("purpose", "step_up"))
	must(t, err)
	reject("foreign purpose", raw)
	raw, err = access.Issue(token.Claims{}.With("jti", "jti-1").With("purpose", PurposeLoginMFA))
	must(t, err)
	reject("no subject", raw)
	for name, factors := range map[string]any{"factors not a list": "f-1", "factors not strings": []any{1}} {
		raw, err = access.Issue(token.Claims{}.With("sub", "user-123").With("jti", "jti-1").With("purpose", PurposeLoginMFA).With("mfa_factors", factors))
		must(t, err)
		reject(name, raw)
	}

	// A restricted ticket names its factors; an unrestricted one names none (any factor).
	if _, factors, err := tickets.AuthenticateFactors(ticket); factors != nil || err != nil {
		t.Fatalf("unrestricted: %v %v", factors, err)
	}
	restricted, err := tickets.IssueFor("user-123", []string{"f-2", "f-3"})
	must(t, err)
	if sub, factors, err := tickets.AuthenticateFactors(restricted); sub != "user-123" || !slices.Equal(factors, []string{"f-2", "f-3"}) || err != nil {
		t.Fatalf("restricted: %q %v %v", sub, factors, err)
	}
	if none, err := tickets.IssueFor("user-123", nil); err != nil {
		t.Fatal(err)
	} else if _, factors, err := tickets.AuthenticateFactors(none); factors == nil || len(factors) != 0 || err != nil {
		t.Fatalf("restricted to no factor (recovery codes only): %v %v", factors, err)
	}

	foreignCfg := cfg
	foreignCfg.PublicKey, foreignCfg.PrivateKey = otherPub, otherPriv
	foreign, err := NewMFATickets(foreignCfg, 300*time.Second)
	must(t, err)
	reject("other key", func() string { r, _ := foreign.Issue("user-123"); return r }())

	clk.Set(at("2026-06-09 12:06:00"))
	reject("expired", ticket)

	if _, err := NewMFATickets(token.Config{}, time.Minute); !errors.Is(err, token.ErrInvalidConfig) {
		t.Errorf("bad config: %v", err)
	}
}

func TestUserPrincipals(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		r := repository.New(db)
		now := at("2026-06-07 12:00:00")
		must(t, r.Users.Insert(ctx, model.User{ID: "u-1", Email: "a@example.com", EmailVerifiedAt: &now, CreatedAt: now, UpdatedAt: now}))
		p := UserPrincipals{Users: r.Users}
		got, err := p.Resolve(ctx, "u-1", "org-1")
		must(t, err)
		if !got.EmailVerified || got.OrganizationID != "org-1" || got.Roles != nil {
			t.Fatalf("%+v", got)
		}
		if got, _ := p.Resolve(ctx, "nobody", ""); got.EmailVerified || got.UserID != "nobody" {
			t.Fatalf("%+v", got)
		}
	})
}

// A rotation in flight does not survive a revocation: revoking waits for it and revokes its child.
func TestARevocationEndsARotationInFlight(t *testing.T) {
	for name, revoke := range map[string]func(s *Service, sessionID string) error{
		"all": func(s *Service, _ string) error {
			_, err := s.RevokeAll(ctx, "user-1", model.RevokedPasswordChange)
			return err
		},
		"all but another": func(s *Service, _ string) error {
			_, err := s.RevokeAllExcept(ctx, "user-1", repository.NewID(), model.RevokedPasswordChange)
			return err
		},
		"the family": func(s *Service, sessionID string) error { return s.RevokeFamily(ctx, sessionID, model.RevokedLogout) },
		"one": func(s *Service, sessionID string) error {
			_, err := s.Revoke(ctx, "user-1", sessionID)
			return err
		},
		"the organization's": func(s *Service, _ string) error {
			return s.RevokeAllForOrganization(ctx, "user-1", principal().OrganizationID, model.RevokedAdmin)
		},
	} {
		t.Run(name, func(t *testing.T) {
			backends(t, func(t *testing.T, db store.Adapter) {
				if d := db.Dialect(); d != store.Postgres && d != store.MySQL {
					t.Skip("one transaction at a time")
				}
				h := newHarness(db, "2026-06-07 12:00:00")
				s := h.service(t)
				issued, err := s.Issue(ctx, principal(), token.ClientContext{})
				must(t, err)
				var rotated token.IssuedTokens
				done := make(chan error, 1)
				must(t, db.Tx(ctx, func(tx context.Context) error { // the rotation's transaction, held open
					if rotated, err = s.Refresh(tx, issued.RefreshToken, token.ClientContext{}); err != nil {
						return err
					}
					go func() { done <- revoke(s, issued.SessionID) }()
					time.Sleep(300 * time.Millisecond) // the revocation reaches its lock
					return nil
				}))
				must(t, <-done)
				if _, err := s.Refresh(ctx, rotated.RefreshToken, token.ClientContext{}); !errors.Is(err, ErrInvalidGrant) {
					t.Fatalf("the rotated token outlived the revocation: %v", err)
				}
				if list, err := s.List(ctx, "user-1", ""); err != nil || len(list) != 0 {
					t.Fatalf("live sessions %+v %v", list, err)
				}
			})
		})
	}
}

// A rotation that loses to a revocation is an ended session, not a stolen token.
func TestARotationThatLosesToARevocationIsNoReuse(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		if d := db.Dialect(); d != store.Postgres && d != store.MySQL {
			t.Skip("one transaction at a time")
		}
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		done := make(chan error, 1)
		must(t, db.Tx(ctx, func(tx context.Context) error {
			if _, err := s.RevokeAll(tx, "user-1", model.RevokedLogout); err != nil {
				return err
			}
			go func() {
				_, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
				done <- err
			}()
			time.Sleep(300 * time.Millisecond) // the rotation read the live token and waits
			return nil
		}))
		if err := <-done; !errors.Is(err, ErrInvalidGrant) || errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("refresh: %v", err)
		}
		if n := len(ofType[event.RefreshReuseDetected](h.events)); n != 0 {
			t.Fatalf("%d reuse alerts", n)
		}
	})
}

func TestADisabledOrUnknownAccountOpensNoSession(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		if _, err := db.Update(ctx, "auth_users", store.Criteria{"id": "user-1"}, store.Data{"status": model.UserStatusDisabled}); err != nil {
			t.Fatal(err)
		}
		s := h.service(t)
		if _, err := s.Issue(ctx, principal(), token.ClientContext{}); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("issue: %v", err)
		}
		if _, err := s.Issue(ctx, token.SessionPrincipal{UserID: repository.NewID()}, token.ClientContext{}); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("issue without an account: %v", err)
		}
		if list, err := s.List(ctx, "user-1", ""); err != nil || len(list) != 0 {
			t.Fatalf("live sessions %+v %v", list, err)
		}
	})
}

// Sessions refreshing back to back neither outlive a revocation nor deadlock with it.
func TestNoSessionRefreshingBackToBackOutlivesARevocation(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		if d := db.Dialect(); d != store.Postgres && d != store.MySQL {
			t.Skip("one transaction at a time")
		}
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		for range 10 {
			var refreshing sync.WaitGroup
			started := make(chan struct{}, 4)
			for range 4 {
				issued, err := s.Issue(ctx, principal(), token.ClientContext{})
				must(t, err)
				refreshing.Go(func() {
					secret := issued.RefreshToken
					for i := 0; ; i++ {
						next, err := s.Refresh(ctx, secret, token.ClientContext{})
						if i == 2 {
							started <- struct{}{}
						}
						if i == 2000 {
							t.Error("a session outlived the revocation")
							return
						}
						if err != nil {
							if !errors.Is(err, ErrInvalidGrant) || errors.Is(err, ErrRefreshReuse) {
								t.Errorf("refresh: %v", err)
							}
							return
						}
						secret = next.RefreshToken
					}
				})
			}
			for range 4 {
				<-started
			}
			if _, err := s.RevokeAll(ctx, "user-1", model.RevokedPasswordChange); err != nil {
				t.Errorf("revoke: %v", err)
			}
			refreshing.Wait()
			if list, err := s.List(ctx, "user-1", ""); err != nil || len(list) != 0 {
				t.Fatalf("live sessions %+v %v", list, err)
			}
		}
	})
}

// raceDB runs before once, when the next transaction begins or the next update outside one runs.
type raceDB struct {
	store.Adapter
	before func()
}

func (r *raceDB) race() {
	if f := r.before; f != nil {
		r.before = nil
		f()
	}
}

func (r *raceDB) Tx(ctx context.Context, fn func(ctx context.Context) error) error {
	r.race()
	return r.Adapter.Tx(ctx, fn)
}

func (r *raceDB) Update(ctx context.Context, table string, c store.Criteria, d store.Data) (int64, error) {
	r.race()
	return r.Adapter.Update(ctx, table, c, d)
}

// A step-up, an organization switch and a refresh without rotation write to the session as it is
// when they write: one that ended since they read it mints nothing, one that was refreshed since
// keeps what they changed.
func TestAChangeToASessionIsMadeToItsLiveToken(t *testing.T) {
	for name, change := range map[string]func(s *Service, issued token.IssuedTokens) error{
		"step-up": func(s *Service, issued token.IssuedTokens) error {
			_, err := s.StepUp(ctx, "user-1", "org-1", issued.SessionID)
			return err
		},
		"switch": func(s *Service, issued token.IssuedTokens) error {
			_, err := s.SwitchOrganization(ctx, "user-1", "org-2", issued.SessionID)
			return err
		},
		"refresh in place": func(s *Service, issued token.IssuedTokens) error {
			_, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			backends(t, func(t *testing.T, db store.Adapter) {
				h := newHarness(db, "2026-06-07 12:00:00")
				s := h.service(t)
				racing := &raceDB{Adapter: db}
				h.db = racing
				h.auth.RefreshToken.Rotation = name != "refresh in place"
				raced := h.service(t)

				issued, err := s.Issue(ctx, principal(), token.ClientContext{})
				must(t, err)
				racing.before = func() {
					if _, err := s.RevokeAll(ctx, "user-1", model.RevokedLogout); err != nil {
						t.Error(err)
					}
				}
				if err := change(raced, issued); !errors.Is(err, ErrInvalidGrant) {
					t.Fatalf("an ended session: %v", err)
				}
				if name == "refresh in place" {
					return
				}

				issued, err = s.Issue(ctx, principal(), token.ClientContext{})
				must(t, err)
				var rotated token.IssuedTokens
				racing.before = func() {
					if rotated, err = s.Refresh(ctx, issued.RefreshToken, token.ClientContext{}); err != nil {
						t.Error(err)
					}
				}
				must(t, change(raced, issued))
				if rotated.RefreshToken == "" {
					t.Fatal("the race did not happen")
				}
				active, _ := split(h.family(t, issued.SessionID))
				if len(active) != 1 || (name == "step-up") != active[0].MFA || (name == "switch") != (*active[0].OrganizationID == "org-2") {
					t.Fatalf("live token %+v", active)
				}
			})
		})
	}
}

// A refresh that rotates keeps what a step-up or an organization switch wrote since it read the
// token, in the new refresh token and in the access token.
func TestARotationKeepsAChangeMadeMeanwhile(t *testing.T) {
	for name, change := range map[string]func(s *Service, sessionID string) error{
		"step-up": func(s *Service, sessionID string) error {
			_, err := s.StepUp(ctx, "user-1", "org-1", sessionID)
			return err
		},
		"switch": func(s *Service, sessionID string) error {
			_, err := s.SwitchOrganization(ctx, "user-1", "org-2", sessionID)
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			backends(t, func(t *testing.T, db store.Adapter) {
				h := newHarness(db, "2026-06-07 12:00:00")
				s := h.service(t)
				issued, err := s.Issue(ctx, principal(), token.ClientContext{})
				must(t, err)
				racing := &raceDB{Adapter: db, before: func() { must(t, change(s, issued.SessionID)) }}
				h.db = racing
				_, err = h.service(t).Refresh(ctx, issued.RefreshToken, token.ClientContext{})
				must(t, err)
				if racing.before != nil {
					t.Fatal("the race did not happen")
				}
				active, _ := split(h.family(t, issued.SessionID))
				if len(active) != 1 || (name == "step-up") != active[0].MFA || (name == "switch") != (*active[0].OrganizationID == "org-2") {
					t.Fatalf("live token %+v", active)
				}
				last := len(h.issuer.claims) - 1
				if mfa, org := h.issuer.claim(last, "mfa"), h.issuer.claim(last, "org"); (name == "step-up") != (mfa == true) || (name == "switch") != (org == "org-2") {
					t.Fatalf("access token: mfa %v, org %v", mfa, org)
				}
			})
		})
	}
}

// A session past its end mints nothing, whatever access token is still valid.
func TestAnExpiredSessionMintsNothing(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		h.clock.Set(issued.RefreshExpiresAt)
		if _, err := s.StepUp(ctx, "user-1", "org-1", issued.SessionID); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("step-up: %v", err)
		}
		if _, err := s.SwitchOrganization(ctx, "user-1", "org-2", issued.SessionID); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("switch: %v", err)
		}
	})
}

// A refresh whose token is gone by the time it looks again is refused, not failed.
func TestARefreshOfATokenDeletedMeanwhileIsRefused(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		issued, err := h.service(t).Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		h.db = &raceDB{Adapter: db, before: func() {
			if _, err := db.Delete(ctx, "auth_refresh_tokens", store.Criteria{"user_id": "user-1"}); err != nil {
				t.Error(err)
			}
		}}
		if _, err := h.service(t).Refresh(ctx, issued.RefreshToken, token.ClientContext{}); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("refresh: %v", err)
		}
	})
}

// A ticket issued before the password changed dies with it; the session that changed it lives.
func TestRevokingTheOtherSessionsEndsTheTicketsIssuedBefore(t *testing.T) {
	pub, priv := rsaKeys(t)
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		tickets, err := NewMFATickets(token.Config{PublicKey: pub, PrivateKey: priv, KeyID: "k", Issuer: "https://auth.polaris.test", TTL: time.Minute, Clock: h.clock}, 300*time.Second)
		must(t, err)
		d := NewDenylist(h.cache, h.clock, h.auth.AccessToken.TTL)
		keep, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		ticket, err := tickets.Issue("user-1")
		must(t, err)
		h.clock.Advance(2 * time.Second)
		if _, _, err := tickets.AuthenticateLive(ctx, ticket, d); err != nil {
			t.Fatal(err)
		}
		_, err = s.RevokeAllExcept(ctx, "user-1", keep.SessionID, model.RevokedPasswordChange)
		must(t, err)
		if _, _, err := tickets.AuthenticateLive(ctx, ticket, d); !errors.Is(err, token.ErrInvalidToken) {
			t.Fatalf("a ticket of the old password: %v", err)
		}
		if revoked, err := d.IsRevoked(ctx, "user-1", h.clock.Now()); revoked || err != nil {
			t.Fatalf("the kept session's access token is watermarked: %v", err)
		}
		fresh, err := tickets.Issue("user-1")
		must(t, err)
		if _, _, err := tickets.AuthenticateLive(ctx, fresh, d); err != nil {
			t.Fatalf("a new ticket: %v", err)
		}
	})
}
