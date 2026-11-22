package passkey_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/passkey"
	"github.com/univeros/polaris.go/polaristest"
)

// The environment of the recorded passkey flow.
const (
	// flowFixtures is the recorded fixture set's file-name prefix under internal/apispec/fixtures/passkey.
	flowFixtures = "Polaris.Passkey.Tests.Functional.PasskeyFlowTest"
	password     = "correct horse battery staple"
	origin       = "https://auth.polaris.test"
)

func data(t testing.TB, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	return d
}

func list(t testing.TB, resp *http.Response) []any {
	t.Helper()
	l, _ := contracttest.JSON(t, resp)["data"].([]any)
	return l
}

func status(t testing.TB, resp *http.Response, want int, msg ...string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d %v", resp.Request.Method, resp.Request.URL, resp.StatusCode, want, msg)
	}
}

// problem asserts a passkey problem document.
func problem(t testing.TB, resp *http.Response, want int, code string) {
	t.Helper()
	status(t, resp, want, code)
	body := contracttest.JSON(t, resp)
	if resp.Header.Get("Content-Type") != "application/problem+json" || body["error"] != code ||
		body["type"] != "https://polaris.univeros.io/problems/passkey/"+strings.TrimPrefix(code, "passkey_") {
		t.Fatalf("problem %v", body)
	}
}

// login registers, verifies and logs email in: the access token.
func login(t testing.TB, srv *polaristest.Server, c *contracttest.Client, email string) string {
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

func claims(t testing.TB, srv *polaristest.Server, access string) (amr []any, mfa any) {
	t.Helper()
	tok, err := srv.Graph().Tokens().Parse(access)
	if err != nil {
		t.Fatal(err)
	}
	amr, _ = tok.Claim("amr").([]any)
	return amr, tok.Claim("mfa")
}

func TestPasskeyFlow(t *testing.T) {
	t.Run("testAPasskeyRegistersSignsInAndIsASecondFactor", func(t *testing.T) {
		srv := polaristest.New(t, polaristest.WithPlugins(passkey.New(passkey.Config{Origins: []string{origin}, RPName: "Polaris tests"})))
		c := contracttest.NewClient(t, srv.Handler(), contracttest.For(t, contracttest.Fixtures(t, "passkey"), flowFixtures, "testAPasskeyRegistersSignsInAndIsASecondFactor"))
		access := login(t, srv, c, "ada@example.com")
		as := contracttest.Bearer(access)
		authenticator := passkey.NewAuthenticator(t)

		status(t, c.Post("/passkey/register/options", nil), 401)
		options := data(t, c.Post("/passkey/register/options", nil, as))
		if rp := options["rp"].(map[string]any); rp["id"] != "auth.polaris.test" || rp["name"] != "Polaris tests" {
			t.Fatalf("rp %v", rp)
		}
		problem(t, c.Post("/passkey/register/verify", nil, as), 422, "passkey_invalid_input")
		problem(t, c.Post("/passkey/register/verify", map[string]any{"credential": authenticator.Create(options, "https://evil.example", true)}, as), 403, "passkey_origin_mismatch")
		registered := c.Post("/passkey/register/verify", map[string]any{"credential": authenticator.Create(options, origin, true), "name": "MacBook"}, as)
		status(t, registered, 201, "an origin mismatch is refused before the challenge is spent")
		problem(t, c.Post("/passkey/register/verify", map[string]any{"credential": authenticator.Create(options, origin, true)}, as), 422, "passkey_challenge_invalid")
		reg := data(t, registered)
		pk := reg["passkey"].(map[string]any)
		if pk["name"] != "MacBook" || pk["backed_up"] != true || len(reg["recovery_codes"].([]any)) == 0 {
			t.Fatalf("registered %v", reg)
		}
		factors := data(t, c.Get("/auth/mfa/factors", as))["factors"].([]any)
		if factors[0].(map[string]any)["type"] != "passkey" {
			t.Fatal("core lists the factor")
		}

		listed := list(t, c.Get("/passkey/list", as))
		if listed[0].(map[string]any)["id"] != pk["id"] {
			t.Fatalf("list %v", listed)
		}
		if data(t, c.Patch("/passkey/"+pk["id"].(string), map[string]any{"name": "Work laptop"}, as))["name"] != "Work laptop" {
			t.Fatal("rename")
		}

		request := data(t, c.Post("/passkey/authenticate/options", nil))
		if allow, _ := request["allowCredentials"].([]any); allow == nil || len(allow) != 0 {
			t.Fatal("conditional UI: discoverable")
		}
		problem(t, c.Post("/passkey/authenticate/verify", map[string]any{"credential": "garbage"}), 422, "passkey_invalid_input")
		problem(t, c.Post("/passkey/authenticate/verify", map[string]any{"credential": passkey.NewAuthenticator(t).Get(request, origin, pk["id"].(string), true, 0)}), 422, "passkey_credential_invalid")
		request = data(t, c.Post("/passkey/authenticate/options", nil))
		me := data(t, c.Get("/auth/me", as))["id"].(string)
		signedIn := data(t, c.Post("/passkey/authenticate/verify", map[string]any{"credential": authenticator.Get(request, origin, me, true, 1)}))
		if signedIn["token_type"] != "Bearer" || signedIn["user"].(map[string]any)["email"] != "ada@example.com" {
			t.Fatalf("signed in %v", signedIn)
		}
		if amr, mfa := claims(t, srv, signedIn["access_token"].(string)); !slices.Equal(amr, []any{"passkey"}) || mfa != true {
			t.Fatalf("amr %v mfa %v", amr, mfa)
		}
		problem(t, c.Post("/passkey/authenticate/verify", map[string]any{"credential": authenticator.Get(request, origin, me, true, 2)}), 422, "passkey_challenge_invalid")

		gate := data(t, c.Post("/auth/login", map[string]any{"email": "ada@example.com", "password": password}))
		if gate["mfa_required"] != true {
			t.Fatal("the passkey gates the password login")
		}
		ticket := contracttest.Bearer(gate["mfa_token"].(string))
		request = data(t, c.Post("/passkey/authenticate/options", nil))
		status(t, c.Post("/auth/mfa/verify", map[string]any{"factor_id": pk["factor_id"], "code": passkey.NewAuthenticator(t).GetJSON(request, origin, me, true, 0)}, ticket), 422, "another passkey is a wrong code")
		request = data(t, c.Post("/passkey/authenticate/options", nil))
		verified := c.Post("/auth/mfa/verify", map[string]any{"factor_id": pk["factor_id"], "code": authenticator.GetJSON(request, origin, me, true, 2)}, ticket)
		status(t, verified, 200)
		session := data(t, verified)["access_token"].(string)
		if amr, _ := claims(t, srv, session); !slices.Equal(amr, []any{"pwd", "otp"}) {
			t.Fatalf("core's post-MFA session: %v", amr)
		}

		request = data(t, c.Post("/passkey/authenticate/options", nil))
		status(t, c.Post("/auth/mfa/step-up", map[string]any{"factor_id": pk["factor_id"], "code": authenticator.GetJSON(request, origin, me, true, 3)}, contracttest.Bearer(session)), 200, "step-up with the passkey")
		problem(t, c.Delete("/passkey/"+me, contracttest.Bearer(session)), 404, "passkey_not_found")
		if got := data(t, c.Delete("/passkey/"+pk["id"].(string), contracttest.Bearer(session))); got["status"] != "deleted" {
			t.Fatalf("delete %v", got)
		}
		if left := list(t, c.Get("/passkey/list", contracttest.Bearer(session))); len(left) != 0 {
			t.Fatal(left)
		}
		if left := data(t, c.Get("/auth/mfa/factors", contracttest.Bearer(session)))["factors"].([]any); len(left) != 0 {
			t.Fatal("the factor went with it")
		}
	})
}

// Every passkey fixture has a Go test.
func TestEveryFixtureIsReplayed(t *testing.T) {
	missing, err := contracttest.Uncovered(contracttest.Fixtures(t, "passkey"), []string{flowFixtures + "::testAPasskeyRegistersSignsInAndIsASecondFactor"})
	if err != nil || len(missing) > 0 {
		t.Fatalf("fixtures without a Go test: %v %v", missing, err)
	}
}
