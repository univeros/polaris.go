package anonymous_test

import (
	"context"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/plugins/anonymous"
	"github.com/univeros/polaris-go/polaristest"
)

const (
	flowClass = `Polaris\Anonymous\Tests\Functional\AnonymousFlowTest`
	password  = "correct horse battery staple"
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
		c := contracttest.NewClient(t, srv.Handler(), contracttest.For(t, contracttest.UpstreamFixtures(t, "anonymous"), flowClass, "testAGuestSignsInAndConvertsIntoTheAccountItSignsUpFor"))

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

func TestEveryFixtureIsCovered(t *testing.T) {
	left, err := contracttest.Uncovered(contracttest.UpstreamFixtures(t, "anonymous"), []string{flowClass + "::testAGuestSignsInAndConvertsIntoTheAccountItSignsUpFor"})
	if err != nil || len(left) > 0 {
		t.Fatalf("uncovered %v (%v)", left, err)
	}
}
