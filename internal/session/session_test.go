package session

// The session service (issue, refresh, revoke) run on memstore and SQLite, plus the
// concurrent-refresh race.

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/token"
)

func TestNewRequiresDependencies(t *testing.T) {
	_, err := New(Config{})
	if !errors.Is(err, ErrInvalidConfig) || err.Error() != "session: invalid configuration: Config.DB, Config.Pepper, Config.Access, Config.Principals, Config.Denylist required" {
		t.Fatal(err)
	}
}

func TestIssueCreatesARefreshFamilyAndBindsTheAccessToken(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		issued, err := h.service(t).Issue(ctx, principal(), token.ClientContext{IP: "198.51.100.4", UserAgent: "Test/1.0"})
		must(t, err)
		if issued.RefreshToken == "" || issued.AccessExpiresIn != 900 || !issued.RefreshExpiresAt.Equal(at("2026-07-07 12:00:00")) {
			t.Fatalf("%+v", issued)
		}
		rows := h.family(t, issued.SessionID)
		if len(rows) != 1 || rows[0].RevokedAt != nil || rows[0].ParentID != nil || *rows[0].IP != "198.51.100.4" ||
			*rows[0].UserAgent != "Test/1.0" || *rows[0].OrganizationID != "org-1" || *rows[0].AMR != "pwd" || rows[0].MFA {
			t.Fatalf("%+v", rows)
		}
		// Only the keyed hash is stored, never the secret.
		if rows[0].TokenHash == issued.RefreshToken || len(rows[0].TokenHash) != 64 || len(issued.RefreshToken) != 43 {
			t.Fatalf("hash %q secret %q", rows[0].TokenHash, issued.RefreshToken)
		}
		if h.issuer.claim(0, "sub") != "user-1" || h.issuer.claim(0, "sid") != issued.SessionID || h.issuer.claim(0, "org") != "org-1" ||
			!slices.Equal(strs(h.issuer.claim(0, "amr")), []string{"pwd"}) {
			t.Fatal("access claims")
		}
	})
}

func TestRefreshRotatesTheTokenWithinTheSameFamily(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{IP: "198.51.100.4", UserAgent: "Test/1.0"})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:05:00"))
		rotated, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{UserAgent: "Test/2.0"})
		must(t, err)
		if rotated.RefreshToken == issued.RefreshToken || rotated.SessionID != issued.SessionID || !rotated.RefreshExpiresAt.Equal(issued.RefreshExpiresAt) {
			t.Fatalf("%+v", rotated)
		}
		active, revoked := split(h.family(t, issued.SessionID))
		if len(active) != 1 || len(revoked) != 1 || *revoked[0].RevokedReason != model.RevokedRotated ||
			*active[0].ParentID != revoked[0].ID || !revoked[0].LastUsedAt.Equal(at("2026-06-07 12:05:00")) {
			t.Fatalf("active %+v revoked %+v", active, revoked)
		}
		// The client context falls back to the session's per field.
		if *active[0].IP != "198.51.100.4" || *active[0].UserAgent != "Test/2.0" {
			t.Fatalf("client context %+v", active[0])
		}
		if n := len(ofType[event.TokenRefreshed](h.events)); n != 1 {
			t.Fatalf("%d refreshed events", n)
		}
		// The refreshed access token re-resolves the authorization context.
		if !slices.Equal(strs(h.issuer.claim(0, "roles")), []string{}) || !slices.Equal(strs(h.issuer.claim(1, "roles")), []string{"member"}) {
			t.Fatal("roles not re-resolved")
		}
		// The rotated secret no longer works; the new one does.
		if _, err := s.Refresh(ctx, rotated.RefreshToken, token.ClientContext{}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRefreshCarriesTheSessionsAuthContextForward(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		authTime := at("2026-06-07 12:00:00").Unix()
		p := principal()
		p.MFA, p.AMR, p.AuthTime = true, []string{"pwd", "otp"}, &authTime
		issued, err := s.Issue(ctx, p, token.ClientContext{})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:05:00"))
		rotated, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:10:00"))
		_, err = s.Refresh(ctx, rotated.RefreshToken, token.ClientContext{})
		must(t, err)
		for i := 1; i <= 2; i++ {
			if h.issuer.claim(i, "mfa") != true || !slices.Equal(strs(h.issuer.claim(i, "amr")), []string{"pwd", "otp"}) || h.issuer.claim(i, "auth_time") != authTime {
				t.Errorf("rotation %d lost the auth context", i)
			}
		}
	})
}

func TestStepUpUpgradesTheSessionsStoredAuthContext(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		access, err := s.StepUp(ctx, "user-1", "org-1", issued.SessionID)
		must(t, err)
		if access == "" || len(h.family(t, issued.SessionID)) != 1 {
			t.Fatal("step-up must not touch the refresh family")
		}
		stamp := at("2026-06-07 12:00:00").Unix()
		if h.issuer.claim(1, "sub") != "user-1" || h.issuer.claim(1, "sid") != issued.SessionID || h.issuer.claim(1, "mfa") != true ||
			!slices.Equal(strs(h.issuer.claim(1, "amr")), []string{"pwd", "otp"}) || h.issuer.claim(1, "auth_time") != stamp {
			t.Fatal("step-up claims")
		}
		h.clock.Set(at("2026-06-07 12:10:00"))
		_, err = s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
		must(t, err)
		if h.issuer.claim(2, "mfa") != true || !slices.Equal(strs(h.issuer.claim(2, "amr")), []string{"pwd", "otp"}) || h.issuer.claim(2, "auth_time") != stamp {
			t.Fatal("a refresh after step-up keeps the strong-auth context")
		}
	})
}

func TestRotationDisabledKeepsTheSameTokenValid(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		h.auth.RefreshToken.Rotation = false
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:05:00"))
		refreshed, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
		must(t, err)
		rows := h.family(t, issued.SessionID)
		if refreshed.RefreshToken != issued.RefreshToken || len(rows) != 1 || rows[0].RevokedAt != nil || rows[0].LastUsedAt == nil {
			t.Fatalf("%+v", rows)
		}
		if n := len(ofType[event.TokenRefreshed](h.events)); n != 1 {
			t.Fatalf("%d refreshed events", n)
		}
	})
}

func TestSwitchOrganizationRescopesTheSession(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		access, err := s.SwitchOrganization(ctx, "user-1", "org-2", issued.SessionID)
		must(t, err)
		switches := ofType[event.OrganizationSwitched](h.events)
		if access == "" || len(switches) != 1 || switches[0].UserID != "user-1" || *switches[0].FromOrganizationID != "org-1" || switches[0].ToOrganizationID != "org-2" {
			t.Fatalf("%+v", switches)
		}
		if h.issuer.claim(1, "org") != "org-2" || *h.family(t, issued.SessionID)[0].OrganizationID != "org-2" {
			t.Fatal("not re-scoped")
		}
		_, err = s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
		must(t, err)
		if h.issuer.claim(2, "org") != "org-2" {
			t.Fatal("refresh left the switched org")
		}
	})
}

// A session an organization's identity provider opened (amr sso) stays that organization's: it
// does not switch, a step-up does not turn it into the account holder's, and it never carries the
// superadmin override.
func TestAnIdentityProvidersSessionStaysBoundToItsOrganization(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		p := principal()
		p.AMR, p.Roles, p.Scope = []string{token.AMRSSO}, []string{"superadmin"}, []string{"users.manage"}
		issued, err := s.Issue(ctx, p, token.ClientContext{})
		must(t, err)
		if roles := strs(h.issuer.claim(0, "roles")); len(roles) != 0 || h.issuer.claim(0, "scope") != nil {
			t.Fatalf("the override rode along: %v %v", roles, h.issuer.claim(0, "scope"))
		}
		if _, err := s.SwitchOrganization(ctx, "user-1", "org-2", issued.SessionID); !errors.Is(err, ErrOrganizationBound) {
			t.Fatalf("switch: %v", err)
		}
		if *h.family(t, issued.SessionID)[0].OrganizationID != "org-1" {
			t.Fatal("the session moved")
		}
		_, err = s.SwitchOrganization(ctx, "user-1", "org-1", issued.SessionID)
		must(t, err)
		_, err = s.StepUp(ctx, "user-1", "org-1", issued.SessionID)
		must(t, err)
		if amr := *h.family(t, issued.SessionID)[0].AMR; amr != "sso,otp" {
			t.Fatalf("a step-up unbound the session: amr %q", amr)
		}
		if _, err := s.SwitchOrganization(ctx, "user-1", "org-2", issued.SessionID); !errors.Is(err, ErrOrganizationBound) {
			t.Fatalf("switch after a step-up: %v", err)
		}
		_, err = s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
		must(t, err)
		last := len(h.issuer.claims) - 1
		if amr := strs(h.issuer.claim(last, "amr")); h.issuer.claim(last, "org") != "org-1" || !slices.Contains(amr, token.AMRSSO) {
			t.Fatalf("after a refresh: amr %v org %v", amr, h.issuer.claim(last, "org"))
		}
	})
}

func TestStepUpAndSwitchRejectAnEndedSession(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		must(t, s.RevokeFamily(ctx, issued.SessionID, model.RevokedLogout))
		if _, err := s.StepUp(ctx, "user-1", "org-1", issued.SessionID); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("step-up: %v", err)
		}
		if _, err := s.SwitchOrganization(ctx, "user-1", "org-2", issued.SessionID); !errors.Is(err, ErrInvalidGrant) {
			t.Errorf("switch: %v", err)
		}
		// A logged-out token is a plain invalid grant: no reuse alert.
		if _, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{}); !errors.Is(err, ErrInvalidGrant) || errors.Is(err, ErrRefreshReuse) {
			t.Errorf("refresh: %v", err)
		}
		if len(ofType[event.RefreshReuseDetected](h.events)) != 0 {
			t.Error("reuse alert for a logged-out token")
		}
	})
}

func TestReuseDetectionDisabledRejectsWithoutRevokingTheFamily(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		h.auth.RefreshToken.ReuseDetection = false
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:05:00"))
		_, err = s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:06:00"))
		_, err = s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
		if !errors.Is(err, ErrInvalidGrant) || errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("err %v", err)
		}
		if active, _ := split(h.family(t, issued.SessionID)); len(active) != 1 || len(ofType[event.RefreshReuseDetected](h.events)) != 0 {
			t.Fatal("family revoked or alert fired")
		}
	})
}

func TestSlidingExtendsExpiryUpToTheMaxLifetimeCap(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		h.auth.RefreshToken.Sliding, h.auth.RefreshToken.TTL, h.auth.RefreshToken.MaxLifetime = true, 100*time.Second, 150*time.Second
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:00:30"))
		first, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
		must(t, err)
		if !first.RefreshExpiresAt.Equal(at("2026-06-07 12:02:10")) {
			t.Fatalf("first %v", first.RefreshExpiresAt)
		}
		h.clock.Set(at("2026-06-07 12:01:00"))
		second, err := s.Refresh(ctx, first.RefreshToken, token.ClientContext{})
		must(t, err)
		if !second.RefreshExpiresAt.Equal(at("2026-06-07 12:02:30")) {
			t.Fatalf("second %v", second.RefreshExpiresAt)
		}
	})
}

func TestReplayingARotatedTokenRevokesTheWholeFamilyAndAlerts(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{IP: "198.51.100.4", UserAgent: "Test/1.0"})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:05:00"))
		rotated, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{})
		must(t, err)
		h.clock.Set(at("2026-06-07 12:06:00"))
		_, err = s.Refresh(ctx, issued.RefreshToken, token.ClientContext{IP: "203.0.113.9", UserAgent: "Replay/1.0"})
		if !errors.Is(err, ErrRefreshReuse) || !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("err %v", err)
		}
		rows := h.family(t, issued.SessionID)
		for _, r := range rows {
			if r.RevokedAt == nil {
				t.Fatal("a family token survived")
			}
			if r.ParentID == nil && *r.RevokedReason != model.RevokedRotated {
				t.Error("the rotated token's reason must stand")
			}
			if r.ParentID != nil && *r.RevokedReason != model.RevokedReuseDetected {
				t.Errorf("child reason %s", *r.RevokedReason)
			}
		}
		alerts := ofType[event.RefreshReuseDetected](h.events)
		if len(alerts) != 1 || alerts[0].UserID != "user-1" || alerts[0].FamilyID != issued.SessionID || *alerts[0].IP != "203.0.113.9" || *alerts[0].UserAgent != "Replay/1.0" {
			t.Fatalf("%+v", alerts)
		}
		// The rotated child is dead too.
		if _, err := s.Refresh(ctx, rotated.RefreshToken, token.ClientContext{}); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("child: %v", err)
		}
	})
}

func TestRefreshRejectsUnknownAndExpiredTokens(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		if _, err := s.Refresh(ctx, "not-a-real-token", token.ClientContext{}); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("unknown: %v", err)
		}
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		h.clock.Set(at("2026-08-06 12:00:00"))
		if _, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{}); !errors.Is(err, ErrInvalidGrant) || errors.Is(err, ErrRefreshReuse) {
			t.Fatalf("expired: %v", err)
		}
		// Expiry is exclusive: a token at exactly expires_at is expired.
		issued, err = s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		h.clock.Set(issued.RefreshExpiresAt)
		if _, err := s.Refresh(ctx, issued.RefreshToken, token.ClientContext{}); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("at expiry: %v", err)
		}
	})
}

func TestMintWithoutSession(t *testing.T) {
	h := newHarness(memstore.New(schema.Core()...), "2026-06-07 12:00:00")
	s := h.service(t)
	_, err := s.Mint(context.Background(), principal(), "", token.Claims{}.With("impersonated_by", "admin-1").With("sub", "evil"))
	must(t, err)
	if _, ok := h.issuer.claims[0].Get("sid"); ok || h.issuer.claim(0, "impersonated_by") != "admin-1" || h.issuer.claim(0, "sub") != "user-1" {
		t.Fatal("mint claims")
	}
	if _, err := s.Mint(context.Background(), token.SessionPrincipal{}, "", token.Claims{}); !errors.Is(err, token.ErrInvalidClaims) {
		t.Fatalf("empty subject: %v", err)
	}
}

// Of concurrent presentations of one secret exactly one rotates; the losers take the replay path,
// which revokes the family (the safe answer to a genuine race).
func TestConcurrentRefreshRotatesOnce(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		h := newHarness(db, "2026-06-07 12:00:00")
		s := h.service(t)
		issued, err := s.Issue(ctx, principal(), token.ClientContext{})
		must(t, err)
		const n = 8
		var wg sync.WaitGroup
		errs := make([]error, n)
		for i := range n {
			wg.Go(func() { _, errs[i] = s.Refresh(ctx, issued.RefreshToken, token.ClientContext{}) })
		}
		wg.Wait()
		ok, reused := 0, 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrRefreshReuse):
				reused++
			default:
				t.Errorf("unexpected %v", err)
			}
		}
		if ok != 1 || reused != n-1 {
			t.Fatalf("ok %d reused %d", ok, reused)
		}
		if len(h.family(t, issued.SessionID)) != 2 {
			t.Fatal("exactly one child token")
		}
		if active, _ := split(h.family(t, issued.SessionID)); len(active) != 0 {
			t.Fatal("the race must revoke the family")
		}
	})
}
