package session

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
