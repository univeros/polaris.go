package polaris_test

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store/sqlstore"
)

const revocationPassword = "correct horse battery staple"

// revocation is a server with the denylist on and a user with two sessions.
type revocation struct {
	*polaristest.Server
	t           *testing.T
	userID      string
	mine, other polaris.Tokens
}

func newRevocation(t *testing.T, denylist bool, opts ...polaristest.Option) *revocation {
	t.Helper()
	ctx := context.Background()
	opts = append(opts, polaristest.WithAuth(func(a *config.Auth) { a.AccessToken.Denylist = denylist }))
	r := &revocation{Server: polaristest.New(t, opts...), t: t}
	u, err := r.Users().Create(ctx, polaris.NewUser{Email: "ada@example.com", Password: revocationPassword, EmailVerified: true})
	ok(t, err)
	r.userID = u.ID
	r.mine, r.other = r.signIn(u.ID, ""), r.signIn(u.ID, "")
	return r
}

func (r *revocation) signIn(userID, orgID string) polaris.Tokens {
	r.t.Helper()
	tokens, err := r.Sessions().Issue(context.Background(), polaris.SignIn{UserID: userID, OrganizationID: orgID})
	ok(r.t, err)
	return tokens
}

func (r *revocation) call(method, path, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.Handler().ServeHTTP(w, req)
	return w
}

// answers checks that access gets code wherever the pipeline authenticates it: on host routes and
// on Polaris's own.
func (r *revocation) answers(access string, code int) {
	r.t.Helper()
	h := http.HandlerFunc(whoami)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"Require()":    serveWith(r.Require()(h), access),
		"Protect":      serveWith(r.Protect(h), access),
		"Authenticate": serveWith(r.Authenticate(h), access),
		"GET /auth/me": r.call(http.MethodGet, "/auth/me", access, ""),
	} {
		if w.Code != code {
			r.t.Errorf("%s: %d, want %d", name, w.Code, code)
		}
		if code == http.StatusUnauthorized && !strings.Contains(w.Body.String(), "session_ended") {
			r.t.Errorf("%s: %s, want session_ended", name, w.Body)
		}
	}
}

// Ending one session ends its access token with the denylist on, and no other one; with it off an
// access token is stateless, as it always was.
func TestEndingASessionEndsItsAccessToken(t *testing.T) {
	ctx := context.Background()
	status := func(t *testing.T, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusOK {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
	for name, end := range map[string]func(t *testing.T, r *revocation){
		"Sessions.Revoke": func(t *testing.T, r *revocation) { ok(t, r.Sessions().Revoke(ctx, r.other.SessionID)) },
		"POST /auth/logout": func(t *testing.T, r *revocation) {
			status(t, r.call(http.MethodPost, "/auth/logout", r.other.AccessToken, "{}"))
		},
		"DELETE /auth/sessions/{id}": func(t *testing.T, r *revocation) {
			status(t, r.call(http.MethodDelete, "/auth/sessions/"+r.other.SessionID, r.mine.AccessToken, ""))
		},
		"POST /auth/password/change": func(t *testing.T, r *revocation) {
			status(t, r.call(http.MethodPost, "/auth/password/change", r.mine.AccessToken,
				`{"current_password":"`+revocationPassword+`","new_password":"a different strong password 9"}`))
		},
		"a replayed refresh token": func(t *testing.T, r *revocation) {
			rotated, err := r.Sessions().Refresh(ctx, r.other.RefreshToken)
			ok(t, err)
			r.answers(rotated.AccessToken, http.StatusOK)
			if _, err := r.Sessions().Refresh(ctx, r.other.RefreshToken); !errors.Is(err, polaris.ErrInvalidCredentials) {
				t.Fatalf("replay: %v", err)
			}
			want := http.StatusOK
			if r.Graph().Auth().AccessToken.Denylist {
				want = http.StatusUnauthorized
			}
			r.answers(rotated.AccessToken, want)
		},
	} {
		t.Run(name, func(t *testing.T) {
			for _, denylist := range []bool{true, false} {
				r := newRevocation(t, denylist)
				eve, err := r.Users().Create(ctx, polaris.NewUser{Email: "eve@example.com", EmailVerified: true})
				ok(t, err)
				stranger := r.signIn(eve.ID, "")
				r.answers(r.other.AccessToken, http.StatusOK)
				end(t, r)
				if _, err := r.Sessions().Refresh(ctx, r.other.RefreshToken); err == nil {
					t.Error("control: the ended session still refreshes")
				}
				ended := http.StatusOK
				if denylist {
					ended = http.StatusUnauthorized
				}
				r.answers(r.other.AccessToken, ended)
				r.answers(r.mine.AccessToken, http.StatusOK)
				r.answers(stranger.AccessToken, http.StatusOK)
				refreshed, err := r.Sessions().Refresh(ctx, r.mine.RefreshToken)
				ok(t, err)
				r.answers(refreshed.AccessToken, http.StatusOK)
			}
		})
	}
}

func TestRevokeAllEndsEveryAccessToken(t *testing.T) {
	r := newRevocation(t, true)
	ok(t, r.Sessions().RevokeAll(context.Background(), r.userID))
	r.answers(r.mine.AccessToken, http.StatusUnauthorized)
	r.answers(r.other.AccessToken, http.StatusUnauthorized)
}

// Suspending a member ends the sessions whose context is that organization, and their access tokens.
func TestSuspendingAMemberEndsTheAccessTokensOfThatOrganization(t *testing.T) {
	ctx := context.Background()
	r := newRevocation(t, true)
	owner, err := r.Users().Create(ctx, polaris.NewUser{Email: "owner@example.com", EmailVerified: true})
	ok(t, err)
	var orgs [2]polaris.Organization
	for i, name := range []string{"Acme", "Globex"} {
		orgs[i], err = r.Orgs().Create(ctx, owner.ID, name, "")
		ok(t, err)
		ok(t, r.Orgs().AddMember(ctx, orgs[i].ID, r.userID))
	}
	acme, globex := r.signIn(r.userID, orgs[0].ID), r.signIn(r.userID, orgs[1].ID)
	moved := r.signIn(r.userID, orgs[0].ID) // began in Acme, is in Globex now
	_, err = r.Sessions().Refresh(ctx, moved.RefreshToken)
	ok(t, err)
	w := r.call(http.MethodPost, "/auth/switch-org", moved.AccessToken, `{"organization_id":"`+orgs[1].ID+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("switch: %d %s", w.Code, w.Body)
	}
	ok(t, r.Graph().Orgs().SetMemberStatus(ctx, owner.ID, orgs[0].ID, r.userID, model.MembershipStatusSuspended))
	r.answers(acme.AccessToken, http.StatusUnauthorized)
	for _, tokens := range []polaris.Tokens{globex, moved, r.mine} {
		r.answers(tokens.AccessToken, http.StatusOK)
	}
}

// switchedCache is a cache whose writes fail while down.
type switchedCache struct {
	cache.Cache
	down bool
}

var errCacheDown = errors.New("cache down")

func (c *switchedCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if c.down {
		return errCacheDown
	}
	return c.Cache.Set(ctx, key, value, ttl)
}

// A cache that fails is an error, and the same call again writes the entry, although the session has
// no live token left. With the denylist off the cache is not asked.
func TestAFailedRevocationIsRetried(t *testing.T) {
	ctx := context.Background()
	for _, denylist := range []bool{true, false} {
		c := &switchedCache{Cache: cache.NewMemory(nil)}
		r := newRevocation(t, denylist, polaristest.WithConfig(func(cfg *polaris.Config) { cfg.Cache = c }))
		c.down = true
		err := r.Sessions().Revoke(ctx, r.other.SessionID)
		if !denylist {
			ok(t, err)
			continue
		}
		if err == nil {
			t.Fatal("a failed cache write is no error")
		}
		if _, err := r.Sessions().Refresh(ctx, r.other.RefreshToken); err == nil {
			t.Error("the session did not end in the database")
		}
		c.down = false
		ok(t, r.Sessions().Revoke(ctx, r.other.SessionID))
		r.answers(r.other.AccessToken, http.StatusUnauthorized)
		r.answers(r.mine.AccessToken, http.StatusOK)
	}
}

// Inside the host's transaction the entry is written by the call, as the per-user one is.
func TestARevocationInTheHostsTransactionEndsTheAccessToken(t *testing.T) {
	ctx := context.Background()
	for name, in := range map[string]func(r *revocation, f func(ctx context.Context) error) error{
		"Store.Tx": func(r *revocation, f func(ctx context.Context) error) error { return r.DB.Tx(ctx, f) },
		"WithTx": func(r *revocation, f func(ctx context.Context) error) error {
			tx, err := r.DB.DB().BeginTx(ctx, &sql.TxOptions{})
			if err != nil {
				return err
			}
			return errors.Join(f(sqlstore.WithTx(ctx, tx)), tx.Commit())
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRevocation(t, true)
			ok(t, in(r, func(ctx context.Context) error { return r.Sessions().Revoke(ctx, r.other.SessionID) }))
			r.answers(r.other.AccessToken, http.StatusUnauthorized)
			r.answers(r.mine.AccessToken, http.StatusOK)
		})
	}
}
