package anonymous_test

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/anonymous"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
)

const (
	// flowFixtures is the recorded fixture set's file-name prefix under internal/apispec/fixtures/anonymous.
	flowFixtures = "Polaris.Anonymous.Tests.Functional.AnonymousFlowTest"
	password     = "correct horse battery staple"
)

func data(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	return d
}

func status(t *testing.T, resp *http.Response, want int, msg string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s: status %d, want %d", msg, resp.StatusCode, want)
	}
}

func errorCode(t *testing.T, resp *http.Response) any { return contracttest.JSON(t, resp)["error"] }

// login registers, verifies and logs email in: its access token.
func login(t *testing.T, srv *polaristest.Server, c *contracttest.Client, email string) string {
	t.Helper()
	c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var reg event.UserRegistered
	for _, e := range srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			reg = r
		}
	}
	c.Post("/auth/email/verify", map[string]any{"token": reg.VerificationToken})
	access, _ := data(t, c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return access
}

func amr(t *testing.T, srv *polaristest.Server, access string) []any {
	t.Helper()
	tok, err := srv.Graph().Tokens().Parse(access)
	if err != nil {
		t.Fatal(err)
	}
	list, _ := tok.Claim("amr").([]any)
	return list
}

func TestAnonymousFlow(t *testing.T) {
	t.Run("testAGuestSignsInAndConvertsIntoTheAccountItSignsUpFor", func(t *testing.T) {
		var mu sync.Mutex
		var converted [][2]string
		plugin := anonymous.New(anonymous.Config{OnConvert: func(_ context.Context, guestID, userID string) error {
			mu.Lock()
			defer mu.Unlock()
			converted = append(converted, [2]string{guestID, userID})
			return nil
		}})
		srv := polaristest.New(t, polaristest.WithPlugins(plugin))
		c := contracttest.NewClient(t, srv.Handler(), contracttest.For(t, contracttest.Fixtures(t, "anonymous"), flowFixtures, "testAGuestSignsInAndConvertsIntoTheAccountItSignsUpFor"))

		resp := c.Post("/anonymous/sign-in", map[string]any{})
		status(t, resp, 201, "sign-in")
		guest := data(t, resp)
		user, _ := guest["user"].(map[string]any)
		guestID, _ := user["id"].(string)
		guestAccess, _ := guest["access_token"].(string)
		if user["email"] != guestID+"@anonymous.invalid" || user["email_verified"] != false {
			t.Fatalf("guest %v", user)
		}
		if got := amr(t, srv, guestAccess); !slices.Equal(got, []any{"anonymous"}) {
			t.Fatalf("amr %v", got)
		}

		status(t, c.Post("/anonymous/convert", map[string]any{"access_token": "x"}), 401, "no bearer")
		asGuest := contracttest.Bearer(guestAccess)
		if code := errorCode(t, c.Post("/anonymous/convert", map[string]any{}, asGuest)); code != "anonymous_invalid_input" {
			t.Fatalf("empty body: %v", code)
		}
		if code := errorCode(t, c.Post("/anonymous/convert", map[string]any{"access_token": guestAccess}, asGuest)); code != "anonymous_token_invalid" {
			t.Fatalf("into itself: %v", code)
		}

		ada := login(t, srv, c, "ada@example.com")
		if code := errorCode(t, c.Post("/anonymous/convert", map[string]any{"access_token": guestAccess}, contracttest.Bearer(ada))); code != "anonymous_not_a_guest" {
			t.Fatalf("a real account: %v", code)
		}
		resp = c.Post("/anonymous/convert", map[string]any{"access_token": ada}, asGuest)
		status(t, resp, 200, "convert")
		d := data(t, resp)
		if d["guest_id"] != guestID || d["status"] != "converted" {
			t.Fatalf("converted %v", d)
		}
		if len(converted) != 1 || converted[0] != [2]string{guestID, d["user_id"].(string)} {
			t.Fatalf("hook %v", converted)
		}
		status(t, c.Post("/auth/token/refresh", map[string]any{"refresh_token": guest["refresh_token"]}), 401, "the guest's session ended")
		again := c.Post("/anonymous/convert", map[string]any{"access_token": ada}, asGuest)
		status(t, again, 403, "once")
		if code := errorCode(t, again); code != "anonymous_not_a_guest" {
			t.Fatalf("once: %v", code)
		}
	})
}

// A conversion revokes the guest's sessions and watermarks the denylist: with
// AUTH_ACCESS_TOKEN_DENYLIST on, the guest's access token is refused at once; without it, the
// stateless token answers until it expires (the account it names is disabled, so it holds no
// permission).
func TestAConvertedGuestsAccessTokenEndsWithTheDenylist(t *testing.T) {
	for _, denylist := range []bool{true, false} {
		srv := polaristest.New(t, polaristest.WithPlugins(anonymous.New(anonymous.Config{})),
			polaristest.WithAuth(func(a *config.Auth) { a.AccessToken.Denylist = denylist }))
		c := contracttest.NewClient(t, srv.Handler(), nil)
		guest := data(t, c.Post("/anonymous/sign-in", map[string]any{}))
		asGuest := contracttest.Bearer(guest["access_token"].(string))
		ada := login(t, srv, c, "ada@example.com")
		status(t, c.Post("/anonymous/convert", map[string]any{"access_token": ada}, asGuest), 200, "convert")
		me := c.Get("/auth/me", asGuest)
		if denylist {
			status(t, me, 401, "denylist on: the guest's access token is refused")
			continue
		}
		status(t, me, 200, "denylist off: the stateless token lives until it expires")
		if d := data(t, me); d["status"] != "disabled" {
			t.Fatalf("me %v", d)
		}
	}
}

// downCache fails every write while down.
type downCache struct {
	cache.Cache
	down atomic.Bool
}

func (c *downCache) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if c.down.Load() {
		return errors.New("cache down")
	}
	return c.Cache.Set(ctx, key, value, ttl)
}

// A prune ends the guest's access tokens as a conversion does. It is recorded while the guest's
// sessions are known, so a cache that cannot be written prunes nothing and the next prune does, and
// after the host's hook, so one that fails leaves the guest its session.
func TestAPrunedGuestsAccessTokenEndsWithTheDenylist(t *testing.T) {
	ctx := context.Background()
	for _, denylist := range []bool{true, false} {
		c := &downCache{Cache: cache.NewMemory(nil)}
		var refuse atomic.Bool
		plugin := anonymous.New(anonymous.Config{})
		srv := polaristest.New(t, polaristest.WithPlugins(plugin),
			polaristest.WithAuth(func(a *config.Auth) { a.AccessToken.Denylist = denylist }),
			polaristest.WithConfig(func(cfg *polaris.Config) {
				cfg.Cache = c
				cfg.Hooks.OnUserDeleted = func(context.Context, string) error {
					if refuse.Load() {
						return errors.New("the host refused")
					}
					return nil
				}
			}))
		client := contracttest.NewClient(t, srv.Handler(), nil)
		guest := data(t, client.Post("/anonymous/sign-in", map[string]any{}))
		id := guest["user"].(map[string]any)["id"]
		recent := data(t, client.Post("/anonymous/sign-in", map[string]any{}))
		asGuest := contracttest.Bearer(guest["access_token"].(string))
		old := srv.Graph().Clock().Now().Add(-2 * anonymous.DefaultPruneAfter)
		if _, err := srv.Graph().DB().Update(ctx, anonymous.TableGuests, store.Criteria{"user_id": id}, store.Data{"created_at": old}); err != nil {
			t.Fatal(err)
		}

		refuse.Store(true)
		if n, err := plugin.Prune(ctx); n != 0 || err == nil {
			t.Fatalf("the hook refused: pruned %d, %v", n, err)
		}
		status(t, client.Get("/auth/me", asGuest), 200, "a guest the host refused to prune")
		refuse.Store(false)

		c.down.Store(true)
		if n, err := plugin.Prune(ctx); n != 0 || err == nil {
			t.Fatalf("cache down: pruned %d, %v", n, err)
		}
		c.down.Store(false)
		status(t, client.Get("/auth/me", asGuest), 200, "a guest that was not pruned")
		if n, err := plugin.Prune(ctx); n != 1 || err != nil {
			t.Fatalf("pruned %d, %v", n, err)
		}

		// The tokens a refresh signed as the prune began carry a later iat: the session's entry refuses them.
		tok, err := srv.Graph().Tokens().Parse(guest["access_token"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if refused, err := srv.Graph().Denylist().Refuses(ctx, tok); err != nil || refused != denylist {
			t.Fatalf("denylist %v: refused %v, %v", denylist, refused, err)
		}
		sid, _ := tok.Claim("sid").(string)
		if _, recorded, err := c.Get(ctx, "polaris.denylist.session."+sid); err != nil || recorded != denylist {
			t.Fatalf("denylist %v: session recorded %v, %v", denylist, recorded, err)
		}
		if denylist {
			status(t, client.Get("/auth/me", asGuest), 401, "the pruned guest's access token")
		}
		status(t, client.Get("/auth/me", contracttest.Bearer(recent["access_token"].(string))), 200, "another guest's")
	}
}

func TestEveryFixtureIsCovered(t *testing.T) {
	left, err := contracttest.Uncovered(contracttest.Fixtures(t, "anonymous"), []string{flowFixtures + "::testAGuestSignsInAndConvertsIntoTheAccountItSignsUpFor"})
	if err != nil || len(left) > 0 {
		t.Fatalf("uncovered %v (%v)", left, err)
	}
}
