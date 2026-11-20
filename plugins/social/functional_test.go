package social_test

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/plugins/social"
	"github.com/univeros/polaris.go/polaristest"
)

// The environment of upstream's SocialTestCase and RecordedProviders.
const (
	flowClass = `Polaris\Social\Tests\Functional\SocialFlowTest`
	password  = "correct horse battery staple"
	base      = "https://auth.polaris.test"
	done      = "https://app.polaris.test/signed-in"
)

type flow struct {
	t   *testing.T
	srv *polaristest.Server
	c   *contracttest.Client
	idp *social.Recorded
}

func newFlow(t *testing.T, method string) *flow {
	t.Helper()
	f := &flow{t: t, idp: social.NewRecorded(t)}
	f.srv = polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), social.New(social.RecordedConfig(t, base, f.idp))))
	f.c = contracttest.NewClient(t, f.srv.Handler(), contracttest.For(t, contracttest.UpstreamFixtures(t, "social"), flowClass, method)).KeepCookies()
	return f
}

func data(t testing.TB, resp *http.Response) map[string]any {
	t.Helper()
	d, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	return d
}

func status(t testing.TB, resp *http.Response, want int, msg ...string) {
	t.Helper()
	if resp.StatusCode != want {
		t.Fatalf("%s %s: status %d, want %d %v", resp.Request.Method, resp.Request.URL, resp.StatusCode, want, msg)
	}
}

// problem asserts a social problem document.
func problem(t testing.TB, resp *http.Response, want int, code string) {
	t.Helper()
	status(t, resp, want, code)
	body := contracttest.JSON(t, resp)
	if resp.Header.Get("Content-Type") != "application/problem+json" || body["error"] != code ||
		body["type"] != "https://polaris.univeros.io/problems/social/"+strings.TrimPrefix(code, "social_") {
		t.Fatalf("problem %v", body)
	}
}

func param(raw, name string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Query().Get(name)
}

// login registers, verifies and logs email in: the access token.
func (f *flow) login(email string) string {
	f.t.Helper()
	f.c.Post("/auth/register", map[string]any{"email": email, "password": password})
	var reg event.UserRegistered
	for _, e := range f.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			reg = r
		}
	}
	f.c.Post("/auth/email/verify", map[string]any{"token": reg.VerificationToken})
	access, _ := data(f.t, f.c.Post("/auth/login", map[string]any{"email": email, "password": password}))["access_token"].(string)
	return access
}

// start begins a sign-in (or, with access, a link) and keeps its nonce for the minted id_token.
func (f *flow) start(provider string, access ...string) string {
	f.t.Helper()
	var resp *http.Response
	if len(access) == 0 {
		resp = f.c.Post("/social/"+provider+"/start", nil)
	} else {
		resp = f.c.Post("/social/"+provider+"/link", nil, contracttest.Bearer(access[0]))
	}
	status(f.t, resp, 200)
	started := data(f.t, resp)
	u, _ := started["url"].(string)
	f.idp.SetNonce(param(u, "nonce"))
	state, _ := started["state"].(string)
	return state
}

// signIn runs start, callback and exchange: the exchanged data.
func (f *flow) signIn(provider string) map[string]any {
	f.t.Helper()
	callback := f.c.Get("/social/" + provider + "/callback?code=good&state=" + f.start(provider))
	return data(f.t, f.c.Post("/social/exchange", map[string]any{"code": param(callback.Header.Get("Location"), "code")}))
}

func (f *flow) amr(access string) []any {
	f.t.Helper()
	tok, err := f.srv.Graph().Tokens().Parse(access)
	if err != nil {
		f.t.Fatal(err)
	}
	list, _ := tok.Claim("amr").([]any)
	return list
}

func TestSocialFlow(t *testing.T) {
	t.Run("testGoogleSignsUpThenSignsIn", func(t *testing.T) {
		f := newFlow(t, "testGoogleSignsUpThenSignsIn")
		problem(t, f.c.Post("/social/nope/start", nil), 404, "social_provider_not_found")
		problem(t, f.c.Post("/social/google/start", map[string]any{"redirect_uri": "https://evil.example/"}), 422, "social_redirect_not_allowed")
		problem(t, f.c.Get("/social/google/callback?code=good&state=unknown"), 422, "social_state_invalid")
		state := f.start("google")
		callback := f.c.Get("/social/google/callback?code=good&state=" + state)
		status(t, callback, 302)
		if !strings.HasPrefix(callback.Header.Get("Location"), done+"?code=") {
			t.Fatalf("location %q", callback.Header.Get("Location"))
		}
		problem(t, f.c.Get("/social/google/callback?code=good&state="+state), 422, "social_state_invalid")
		problem(t, f.c.Post("/social/exchange", nil), 422, "social_invalid_input")
		problem(t, f.c.Post("/social/exchange", map[string]any{"code": "nope"}), 422, "social_code_invalid")
		code := param(callback.Header.Get("Location"), "code")
		session := data(t, f.c.Post("/social/exchange", map[string]any{"code": code}))
		user, _ := session["user"].(map[string]any)
		if session["token_type"] != "Bearer" || user["email"] != "ada@example.com" || user["email_verified"] != true {
			t.Fatalf("session %v", session)
		}
		access, _ := session["access_token"].(string)
		if got := f.amr(access); !slices.Equal(got, []any{"social:google"}) {
			t.Fatalf("amr %v", got)
		}
		problem(t, f.c.Post("/social/exchange", map[string]any{"code": code}), 422, "social_code_invalid")
		if data(t, f.c.Get("/auth/me", contracttest.Bearer(access)))["display_name"] != "Ada Lovelace" {
			t.Fatal("not signed up from the profile")
		}
		again := f.signIn("google")
		if again["user"].(map[string]any)["id"] != user["id"] {
			t.Fatal("not signed in by the linked account")
		}
	})

	t.Run("testTheAccountsAreManagedFromTheSession", func(t *testing.T) {
		f := newFlow(t, "testTheAccountsAreManagedFromTheSession")
		session := f.signIn("google")
		access, _ := session["access_token"].(string)
		as := contracttest.Bearer(access)

		status(t, f.c.Get("/social/accounts"), 401)
		accounts, _ := contracttest.JSON(t, f.c.Get("/social/accounts", as))["data"].([]any)
		first, _ := accounts[0].(map[string]any)
		if first["provider"] != "google" || first["provider_account_id"] != social.GoogleSub || first["email"] != "ada@example.com" ||
			first["email_verified"] != true || first["profile"].(map[string]any)["name"] != "Ada Lovelace" || first["access_token_enc"] != nil {
			t.Fatalf("accounts %v", accounts)
		}
		tok := data(t, f.c.Post("/social/google/token", nil, as))
		if tok["access_token"] != "ya29.a0AfB_byC-recorded-google-access-token" || tok["scopes"].([]any)[0] != "openid" {
			t.Fatalf("token %v", tok)
		}
		problem(t, f.c.Post("/social/github/token", nil, as), 404, "social_not_linked")
		problem(t, f.c.Delete("/social/google", as), 409, "social_last_credential")

		status(t, f.c.Post("/social/github/link", nil), 401)
		state := f.start("github", access)
		callback := f.c.Get("/social/github/callback?code=good&state=" + state)
		status(t, callback, 302)
		linked := data(t, f.c.Post("/social/exchange", map[string]any{"code": param(callback.Header.Get("Location"), "code")}))
		acct, _ := linked["account"].(map[string]any)
		if linked["status"] != "linked" || acct["provider"] != "github" || acct["email"] != "grace@example.com" || acct["email_verified"] != true {
			t.Fatalf("linked %v", linked)
		}
		if all, _ := contracttest.JSON(t, f.c.Get("/social/accounts", as))["data"].([]any); len(all) != 2 {
			t.Fatalf("accounts %v", all)
		}
		if got := data(t, f.c.Delete("/social/google", as)); got["status"] != "unlinked" {
			t.Fatalf("unlink %v", got)
		}
		problem(t, f.c.Delete("/social/google", as), 404, "social_not_linked")
		if again := f.signIn("google"); again["user"].(map[string]any)["id"] != session["user"].(map[string]any)["id"] {
			t.Fatal("google is trusted: its verified email links the user again")
		}
	})

	t.Run("testAppleAnswersByFormPostOneTapVerifiesOfflineAndAnyOAuth2ServerSignsIn", func(t *testing.T) {
		f := newFlow(t, "testAppleAnswersByFormPostOneTapVerifiesOfflineAndAnyOAuth2ServerSignsIn")
		state := f.start("apple")
		callback := f.c.Post("/social/apple/callback", map[string]any{"code": "good", "state": state,
			"user": `{"name":{"firstName":"Alan","lastName":"Turing"},"email":"alan@example.com"}`})
		status(t, callback, 302)
		alan := data(t, f.c.Post("/social/exchange", map[string]any{"code": param(callback.Header.Get("Location"), "code")}))
		if alan["user"].(map[string]any)["email"] != "alan@example.com" {
			t.Fatalf("alan %v", alan)
		}
		if data(t, f.c.Get("/auth/me", contracttest.Bearer(alan["access_token"].(string))))["display_name"] != "Alan Turing" {
			t.Fatal("the name from the first callback")
		}

		problem(t, f.c.Post("/social/google/one-tap", nil), 422, "social_invalid_input")
		problem(t, f.c.Post("/social/google/one-tap", map[string]any{"credential": "not.a.jwt"}), 403, "social_provider_error")
		ada := data(t, f.c.Post("/social/google/one-tap", map[string]any{"credential": f.idp.Mint("https://accounts.google.com", "google-client", social.GoogleSub, "ada@example.com", true, "Ada Lovelace")}))
		if u := ada["user"].(map[string]any); u["email"] != "ada@example.com" || u["email_verified"] != true {
			t.Fatalf("one tap %v", ada)
		}

		if linus := f.signIn("microsoft"); linus["user"].(map[string]any)["email"] != "linus@example.com" {
			t.Fatalf("microsoft %v", linus)
		}
		eve := f.signIn("acme")
		if eve["user"].(map[string]any)["email"] != "eve@example.com" || !slices.Equal(f.amr(eve["access_token"].(string)), []any{"social:acme"}) {
			t.Fatalf("acme %v", eve)
		}
	})

	t.Run("testAnUntrustedProviderLinksOnlyFromASession", func(t *testing.T) {
		f := newFlow(t, "testAnUntrustedProviderLinksOnlyFromASession")
		grace := f.login("grace@example.com")
		problem(t, f.c.Get("/social/github/callback?code=good&state="+f.start("github")), 409, "social_account_exists")
		state := f.start("github", grace)
		linked := data(t, f.c.Post("/social/exchange", map[string]any{"code": param(f.c.Get("/social/github/callback?code=good&state="+state).Header.Get("Location"), "code")}))
		if linked["status"] != "linked" || linked["account"].(map[string]any)["provider"] != "github" {
			t.Fatalf("linked %v", linked)
		}
		if signedIn := f.signIn("github"); signedIn["user"].(map[string]any)["email"] != "grace@example.com" {
			t.Fatalf("signed in %v", signedIn)
		}
		if got := data(t, f.c.Delete("/social/github", contracttest.Bearer(grace))); got["status"] != "unlinked" {
			t.Fatalf("unlink %v", got)
		}
	})
}

// Every social fixture has a Go test (port of ContractCoverageTest).
func TestEveryFixtureIsReplayed(t *testing.T) {
	covered := []string{
		flowClass + "::testGoogleSignsUpThenSignsIn",
		flowClass + "::testTheAccountsAreManagedFromTheSession",
		flowClass + "::testAppleAnswersByFormPostOneTapVerifiesOfflineAndAnyOAuth2ServerSignsIn",
		flowClass + "::testAnUntrustedProviderLinksOnlyFromASession",
	}
	missing, err := contracttest.Uncovered(contracttest.UpstreamFixtures(t, "social"), covered)
	if err != nil || len(missing) > 0 {
		t.Fatalf("fixtures without a Go test: %v %v", missing, err)
	}
}
