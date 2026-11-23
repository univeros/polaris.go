package anonymous_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/anonymous"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/token"
)

var now = time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)

type recorder struct {
	mu     sync.Mutex
	events []event.Event
}

func (r *recorder) Dispatch(_ context.Context, e event.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

type env struct {
	p      *polaris.Polaris
	guests *anonymous.Guests
	plugin *anonymous.Plugin
	clk    *clock.Frozen
	db     *memstore.Store
	events *recorder
	client token.ClientContext
}

func boot(t *testing.T, cfg anonymous.Config, hooks ...polaris.Hooks) env {
	t.Helper()
	return bootOn(t, func(db store.Adapter) store.Adapter { return db }, cfg, hooks...)
}

// bootOn boots with the database wrapped by wrap (a failing adapter).
func bootOn(t *testing.T, wrap func(store.Adapter) store.Adapter, cfg anonymous.Config, hooks ...polaris.Hooks) env {
	t.Helper()
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	clk := clock.NewFrozen(now)
	db := memstore.New(append(schema.Core(), anonymous.Models()...)...)
	plugin := anonymous.New(cfg)
	events := &recorder{}
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: wrap(db), Clock: clk, Events: events, Plugins: []polaris.Plugin{plugin},
		Hooks: append(hooks, polaris.Hooks{})[0],
	})
	if err != nil {
		t.Fatal(err)
	}
	return env{p: p, guests: plugin.Guests(), plugin: plugin, clk: clk, db: db, events: events, client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}}
}

func (e env) signIn(t *testing.T) (token.IssuedTokens, model.User) {
	t.Helper()
	tokens, user, err := e.guests.SignIn(context.Background(), e.client)
	if err != nil {
		t.Fatal(err)
	}
	return tokens, user
}

// account inserts a verified user and opens a session for it.
func (e env) account(t *testing.T, email string) (model.User, token.IssuedTokens) {
	t.Helper()
	ctx := context.Background()
	at := e.clk.Now()
	user := model.User{ID: repository.NewID(), Email: email, EmailVerifiedAt: &at, Status: model.UserStatusActive, CreatedAt: at, UpdatedAt: at}
	if err := e.p.Graph().Repos().Users.Insert(ctx, user); err != nil {
		t.Fatal(err)
	}
	tokens, err := e.p.Graph().Sessions().Issue(ctx, token.SessionPrincipal{UserID: user.ID, AMR: []string{"magic_link"}}, e.client)
	if err != nil {
		t.Fatal(err)
	}
	return user, tokens
}

func (e env) liveSessions(t *testing.T, userID string) int64 {
	t.Helper()
	n, err := e.db.Count(context.Background(), "auth_refresh_tokens", store.Criteria{"user_id": userID, "revoked_at": nil})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func (e env) status(t *testing.T, userID string) string {
	t.Helper()
	u, err := e.p.Graph().Repos().Users.Get(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return u.Status
}

func refused(t *testing.T, err, want error, msg string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: %v, want %v", msg, err, want)
	}
}

func TestPlugin(t *testing.T) {
	ctx := context.Background()

	t.Run("testEverythingIsWiredThroughTheGraph", func(t *testing.T) {
		e := boot(t, anonymous.Config{})
		g := e.p.Graph()
		if !slices.ContainsFunc(g.Schema(), func(m schema.Model) bool { return m.Table == anonymous.TableGuests }) {
			t.Fatal("no table")
		}
		var routes []string
		for _, rt := range g.Manifest().Routes() {
			if slices.Contains(rt.Tags, "anonymous") {
				routes = append(routes, rt.Method+" "+rt.Path+" "+string(rt.Auth))
			}
		}
		slices.Sort(routes)
		if !slices.Equal(routes, []string{"POST /anonymous/convert bearer", "POST /anonymous/sign-in public"}) {
			t.Fatalf("routes %v", routes)
		}
		if anonymous.Of(g) != e.plugin || anonymous.SentinelRoutes["/anonymous/sign-in"] != "sign_up" {
			t.Fatal("plugin lookup")
		}
		for _, bad := range []time.Duration{-time.Hour, time.Hour} {
			_, err := polaris.New(polaris.Config{
				Secrets: e.p.Graph().Config().Secrets, Auth: g.Auth(), DB: e.db,
				Plugins: []polaris.Plugin{anonymous.New(anonymous.Config{PruneAfter: bad})},
			})
			if err == nil || !strings.Contains(err.Error(), "Config.PruneAfter") {
				t.Fatalf("PruneAfter %s: %v", bad, err)
			}
		}
	})

	t.Run("testAGuestIsAPasswordlessUserWithAPlaceholderEmailAndAnAnonymousSession", func(t *testing.T) {
		e := boot(t, anonymous.Config{})
		tokens, user := e.signIn(t)
		tok, err := e.p.Graph().Tokens().Parse(tokens.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := tok.Claim("amr").([]any); !slices.Equal(got, []any{"anonymous"}) || tok.Organization() != "" {
			t.Fatalf("claims %v", tok.Claims())
		}
		if user.Email != user.ID+"@anonymous.invalid" {
			t.Fatalf("email %s", user.Email)
		}
		stored, err := e.p.Graph().Repos().Users.Get(ctx, user.ID)
		if err != nil || stored.PasswordHash != nil || stored.EmailVerifiedAt != nil || stored.Status != model.UserStatusActive {
			t.Fatalf("stored %+v %v", stored, err)
		}
		if is, _ := e.guests.IsGuest(ctx, user.ID); !is {
			t.Fatal("not a guest")
		}
		var logged []event.UserLoggedIn
		for _, ev := range e.events.events {
			if l, ok := ev.(event.UserLoggedIn); ok {
				logged = append(logged, l)
			}
		}
		if len(logged) != 1 || !slices.Equal(logged[0].AMR, []string{"anonymous"}) || *logged[0].IP != "203.0.113.7" {
			t.Fatalf("logged %+v", logged)
		}
	})

	t.Run("testConversionHandsBothIdsToTheHostThenEndsAndDisablesTheGuest", func(t *testing.T) {
		var converted [][2]string
		e := boot(t, anonymous.Config{OnConvert: func(_ context.Context, guestID, userID string) error {
			converted = append(converted, [2]string{guestID, userID})
			return nil
		}})
		guest, guestUser := e.signIn(t)
		other, otherUser := e.signIn(t)
		ada, session := e.account(t, "ada@example.com")

		_, err := e.guests.Convert(ctx, ada.ID, session.AccessToken)
		refused(t, err, anonymous.ErrNotAGuest, "a real account is not a guest")
		_, err = e.guests.Convert(ctx, guestUser.ID, "not-a-token")
		refused(t, err, anonymous.ErrTokenInvalid, "not a token")
		_, err = e.guests.Convert(ctx, guestUser.ID, guest.AccessToken)
		refused(t, err, anonymous.ErrTokenInvalid, "not into itself")
		_, err = e.guests.Convert(ctx, guestUser.ID, other.AccessToken)
		refused(t, err, anonymous.ErrTokenInvalid, "not into another guest")
		impersonation, err := e.p.Graph().Sessions().Mint(context.Background(), token.SessionPrincipal{UserID: ada.ID}, "", token.Claims{})
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.guests.Convert(ctx, guestUser.ID, impersonation)
		refused(t, err, anonymous.ErrTokenInvalid, "only a live session")
		_, expired := e.account(t, "expired@example.com")
		if _, err := e.db.Update(ctx, "auth_refresh_tokens", store.Criteria{"family_id": expired.SessionID}, store.Data{"expires_at": e.clk.Now()}); err != nil {
			t.Fatal(err)
		}
		_, err = e.guests.Convert(ctx, guestUser.ID, expired.AccessToken)
		refused(t, err, anonymous.ErrTokenInvalid, "an expired session")
		if len(converted) != 0 {
			t.Fatal("the hook ran")
		}

		userID, err := e.guests.Convert(ctx, guestUser.ID, session.AccessToken)
		if err != nil || userID != ada.ID {
			t.Fatalf("convert %s %v", userID, err)
		}
		if len(converted) != 1 || converted[0] != [2]string{guestUser.ID, ada.ID} {
			t.Fatalf("hook %v", converted)
		}
		row, _ := e.db.FindOne(ctx, anonymous.TableGuests, store.Criteria{"user_id": guestUser.ID})
		if row.String("converted_user_id") != ada.ID || row["converted_at"] == nil {
			t.Fatalf("row %v", row)
		}
		if e.status(t, guestUser.ID) != model.UserStatusDisabled || e.liveSessions(t, guestUser.ID) != 0 {
			t.Fatal("the guest stays live")
		}
		_, err = e.guests.Convert(ctx, guestUser.ID, session.AccessToken)
		refused(t, err, anonymous.ErrNotAGuest, "once")

		if err := e.p.Graph().Sessions().RevokeFamily(ctx, session.SessionID, model.RevokedLogout); err != nil {
			t.Fatal(err)
		}
		_, err = e.guests.Convert(ctx, otherUser.ID, session.AccessToken)
		refused(t, err, anonymous.ErrTokenInvalid, "the account's session ended")
	})

	t.Run("testAFailingHookConvertsNothing", func(t *testing.T) {
		boom := errors.New("the host could not move the data")
		e := boot(t, anonymous.Config{OnConvert: func(context.Context, string, string) error { return boom }})
		_, guest := e.signIn(t)
		_, session := e.account(t, "ada@example.com")
		_, err := e.guests.Convert(ctx, guest.ID, session.AccessToken)
		if !errors.Is(err, boom) {
			t.Fatalf("convert %v", err)
		}
		row, _ := e.db.FindOne(ctx, anonymous.TableGuests, store.Criteria{"user_id": guest.ID})
		if row["converted_at"] != nil || row["converted_user_id"] != nil {
			t.Fatalf("row %v", row)
		}
		if e.status(t, guest.ID) != model.UserStatusActive || e.liveSessions(t, guest.ID) != 1 {
			t.Fatal("the guest cannot retry")
		}
	})

	t.Run("testPruneDeletesTheUnconvertedGuestsOlderThanThePolicy", func(t *testing.T) {
		e := boot(t, anonymous.Config{})
		_, old := e.signIn(t)
		_, kept := e.signIn(t)
		_, session := e.account(t, "ada@example.com")
		if _, err := e.guests.Convert(ctx, kept.ID, session.AccessToken); err != nil {
			t.Fatal(err)
		}
		e.clk.Advance(31 * 24 * time.Hour)
		_, recent := e.signIn(t)

		n, err := e.plugin.Prune(ctx)
		if err != nil || n != 1 {
			t.Fatalf("pruned %d %v", n, err)
		}
		if _, err := e.p.Graph().Repos().Users.Get(ctx, old.ID); !errors.Is(err, repository.ErrNotFound) {
			t.Fatalf("user stays: %v", err)
		}
		if c, _ := e.db.Count(ctx, "auth_refresh_tokens", store.Criteria{"user_id": old.ID}); c != 0 {
			t.Fatal("sessions stay")
		}
		for id, want := range map[string]bool{old.ID: false, kept.ID: true, recent.ID: true} {
			if is, _ := e.guests.IsGuest(ctx, id); is != want {
				t.Fatalf("guest %s: %v", id, is)
			}
		}
		var deleted []event.UserDeleted
		for _, ev := range e.events.events {
			if d, ok := ev.(event.UserDeleted); ok {
				deleted = append(deleted, d)
			}
		}
		if len(deleted) != 1 || deleted[0] != (event.UserDeleted{UserID: old.ID, ActorUserID: anonymous.ActorSystem}) {
			t.Fatalf("deleted %+v", deleted)
		}
		if n, err := e.guests.Prune(ctx); n != 0 || err != nil {
			t.Fatalf("again %d %v", n, err)
		}
	})
}

// A guest is an account: the host's hooks see it created and, when pruned, deleted (before its
// row goes, inside the pruning transaction).
func TestGuestsRunTheHostsAccountHooks(t *testing.T) {
	ctx := context.Background()
	var created, deleted []string
	e := boot(t, anonymous.Config{}, polaris.Hooks{
		OnUserCreated: func(_ context.Context, u polaris.User) error { created = append(created, u.ID); return nil },
		OnUserDeleted: func(_ context.Context, id string) error { deleted = append(deleted, id); return nil },
	})
	_, guest := e.signIn(t)
	if len(created) != 1 || created[0] != guest.ID {
		t.Fatalf("created %v", created)
	}
	e.clk.Advance(31 * 24 * time.Hour)
	if n, err := e.plugin.Prune(ctx); n != 1 || err != nil || len(deleted) != 1 || deleted[0] != guest.ID {
		t.Fatalf("pruned %d %v, deleted %v", n, err, deleted)
	}
}

// Concurrent conversions of one guest run the hook once and convert it once.
func TestConcurrentConversionsConvertOnce(t *testing.T) {
	ctx := context.Background()
	var hooks atomic.Int32
	e := boot(t, anonymous.Config{OnConvert: func(context.Context, string, string) error { hooks.Add(1); return nil }})
	_, guest := e.signIn(t)
	_, session := e.account(t, "ada@example.com")
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := e.guests.Convert(ctx, guest.ID, session.AccessToken); err == nil {
				wins.Add(1)
			} else if !errors.Is(err, anonymous.ErrNotAGuest) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins.Load() != 1 || hooks.Load() != 1 {
		t.Fatalf("wins %d hooks %d", wins.Load(), hooks.Load())
	}
}

// failingUpdates fails every Update of table while armed.
type failingUpdates struct {
	store.Adapter
	table string
	armed atomic.Bool
}

func (f *failingUpdates) Update(ctx context.Context, table string, c store.Criteria, d store.Data) (int64, error) {
	if f.armed.Load() && table == f.table {
		return 0, errors.New("the database refused the write")
	}
	return f.Adapter.Update(ctx, table, c, d)
}

// A conversion is one transaction: when ending the guest fails after OnConvert ran, nothing is
// recorded, the guest keeps its session and a retry converts it (decision 61).
func TestAConversionWhoseEndingFailsConvertsNothingAndCanBeRetried(t *testing.T) {
	ctx := context.Background()
	failing := &failingUpdates{table: "auth_refresh_tokens"} // the last step, after OnConvert
	var hooks atomic.Int32
	e := bootOn(t, func(db store.Adapter) store.Adapter { failing.Adapter = db; return failing },
		anonymous.Config{OnConvert: func(context.Context, string, string) error { hooks.Add(1); return nil }})
	_, guest := e.signIn(t)
	ada, session := e.account(t, "ada@example.com")

	failing.armed.Store(true)
	if _, err := e.guests.Convert(ctx, guest.ID, session.AccessToken); err == nil {
		t.Fatal("the guest could not be disabled, yet the conversion was reported done")
	}
	failing.armed.Store(false)
	row, _ := e.db.FindOne(ctx, anonymous.TableGuests, store.Criteria{"user_id": guest.ID})
	if row["converted_at"] != nil {
		t.Fatalf("a conversion that did not end the guest was recorded: %v", row)
	}
	if e.status(t, guest.ID) != model.UserStatusActive || e.liveSessions(t, guest.ID) != 1 {
		t.Fatal("a failed conversion half-ended the guest")
	}

	userID, err := e.guests.Convert(ctx, guest.ID, session.AccessToken)
	if err != nil || userID != ada.ID {
		t.Fatalf("retry: %q %v", userID, err)
	}
	if e.status(t, guest.ID) != model.UserStatusDisabled || e.liveSessions(t, guest.ID) != 0 || hooks.Load() != 2 {
		t.Fatalf("after the retry: status %s, %d live sessions, %d hook runs", e.status(t, guest.ID), e.liveSessions(t, guest.ID), hooks.Load())
	}
}
