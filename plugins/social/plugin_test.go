package social

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// The unit tests: the service through the graph, the recorded providers answering.

const unitBase = "https://app.example/auth"

type harness struct {
	t      *testing.T
	p      *Plugin
	srv    *polaristest.Server
	rec    *Recorded
	client token.ClientContext
	ctx    context.Context
}

func newHarness(t *testing.T, mutate ...func(*Config)) *harness {
	t.Helper()
	return newHarnessOn(t, NewRecorded(t), mutate...)
}

func newHarnessOn(t *testing.T, rec *Recorded, mutate ...func(*Config)) *harness {
	t.Helper()
	cfg := RecordedConfig(t, unitBase, rec)
	cfg.Providers["okta"] = Provider{ClientID: "okta-client", ClientSecret: "okta-secret", Issuer: "https://acme.okta.example"}
	for _, m := range mutate {
		m(&cfg)
	}
	p := New(cfg)
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), p))
	return &harness{t: t, p: p, srv: srv, rec: rec, client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}, ctx: context.Background()}
}

// restart starts a flow and keeps its nonce for the minted id_token.
func (h *harness) restart(provider string) started {
	h.t.Helper()
	s, err := h.p.start(h.ctx, provider, "", nil, "")
	if err != nil {
		h.t.Fatal(err)
	}
	h.rec.SetNonce(queryParam(s.URL, "nonce"))
	return s
}

// callback answers the provider's callback in the browser that started the flow.
func (h *harness) callback(provider string, params map[string]any) (string, error) {
	state, _ := params["state"].(string)
	return h.p.callback(h.ctx, provider, params, h.browser(state), h.client)
}

// browser is a callback request from the browser that started state: it presents the binding
// cookie the start handed out (read back from the flow's cache entry, without spending it).
func (h *harness) browser(state string) *http.Request {
	h.t.Helper()
	r := httptest.NewRequest(http.MethodGet, unitBase+"/social/x/callback", nil)
	sealed, ok, err := h.srv.Graph().Cache().Get(h.ctx, cacheKey("state", state))
	if err != nil || !ok {
		return r
	}
	raw, err := h.srv.Graph().Encrypter().Decrypt(string(sealed))
	var entry stateEntry
	if err != nil || json.Unmarshal([]byte(raw), &entry) != nil {
		return r
	}
	r.AddCookie(&http.Cookie{Name: bindingCookie(state, h.p.settings.https()), Value: entry.Binding})
	return r
}

// signIn runs a whole flow: the exchanged outcome.
func (h *harness) signIn(provider, linkUserID string) map[string]any {
	h.t.Helper()
	s, err := h.p.start(h.ctx, provider, "", nil, linkUserID)
	if err != nil {
		h.t.Fatal(err)
	}
	h.rec.SetNonce(queryParam(s.URL, "nonce"))
	redirect, err := h.callback(provider, map[string]any{"code": "good", "state": s.State})
	if err != nil {
		h.t.Fatalf("callback: %v", err)
	}
	out, err := h.p.exchange(h.ctx, queryParam(redirect, "code"))
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *harness) user(email string, verified bool) model.User {
	h.t.Helper()
	g := h.srv.Graph()
	hash, err := g.Hasher().Hash("correct horse battery staple")
	if err != nil {
		h.t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	u := model.User{ID: repository.NewID(), Email: email, PasswordHash: &hash, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if verified {
		u.EmailVerifiedAt = &now
	}
	if err := g.Repos().Users.Insert(h.ctx, u); err != nil {
		h.t.Fatal(err)
	}
	return u
}

func (h *harness) count(name string) int {
	n := 0
	for _, got := range h.srv.Events.Names() {
		if got == name {
			n++
		}
	}
	return n
}

func (h *harness) accounts(userID string) []account {
	h.t.Helper()
	all, err := h.p.accountsOf(h.ctx, userID)
	if err != nil {
		h.t.Fatal(err)
	}
	return all
}

func queryParam(raw, name string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Query().Get(name)
}

func refused(t *testing.T, err error, want kind, msg string) {
	t.Helper()
	r, ok := asRefusal(err)
	if !ok || r.kind != want {
		t.Fatalf("%s: got %v, want %s", msg, err, want)
	}
}

func userOf(outcome map[string]any) map[string]any {
	u, _ := outcome["user"].(map[string]any)
	return u
}

func TestEverythingIsWiredThroughTheGraph(t *testing.T) {
	h := newHarness(t)
	g := h.srv.Graph()
	if !slices.ContainsFunc(g.Schema(), func(m schema.Model) bool { return m.Table == TableAccounts }) {
		t.Fatal("the table joins the schema")
	}
	var routes []string
	for _, r := range g.Manifest().Routes() {
		if r.Plugin == ID {
			step := ""
			if r.StepUp {
				step = " step_up"
			}
			routes = append(routes, r.Method+" "+r.Path+" "+string(r.Auth)+step)
		}
	}
	want := []string{"POST /social/{provider}/start public", "GET /social/{provider}/callback public", "POST /social/{provider}/callback public",
		"POST /social/exchange public", "POST /social/google/one-tap public", "GET /social/accounts bearer",
		"POST /social/{provider}/link bearer step_up", "DELETE /social/{provider} bearer step_up", "POST /social/{provider}/token bearer step_up"}
	slices.Sort(routes)
	slices.Sort(want)
	if !slices.Equal(routes, want) {
		t.Fatalf("routes %v", routes)
	}
	if len(h.p.AuditNames()) != 6 || h.p.settings.callbackURL("google") != unitBase+"/social/google/callback" {
		t.Fatal("audit names, callback")
	}
	_, err := h.p.provider(h.ctx, "nope")
	refused(t, err, kindProviderNotFound, "unknown provider")

	for _, id := range Catalog {
		def, ok := catalog(id, "")
		if !ok {
			t.Fatalf("%s missing", id)
		}
		prov := &provider{id: id, def: def, clientID: "client-" + id, out: h.p.out}
		challenge := ""
		if !def.NoPKCE {
			challenge = "ch4llenge"
		}
		u := prov.authorizationURL("https://app.example/cb", "st4te", nil, challenge, "n0nce")
		if !strings.HasPrefix(u, def.AuthorizationURL) || !strings.Contains(u, prov.clientIDParam()+"=client-"+id) || !strings.Contains(u, "state=st4te") {
			t.Fatalf("%s: %s", id, u)
		}
		if strings.Contains(u, "nonce=n0nce") != def.oidc() || strings.Contains(u, "code_challenge=ch4llenge") != !def.NoPKCE {
			t.Fatalf("%s: nonce or PKCE: %s", id, u)
		}
		_ = def.Profile(map[string]any{"sub": "x", "id": "x", "data": map[string]any{"id": "x", "user": []any{}}, "owner": []any{}})
	}
	apple, _ := catalog("apple", "")
	if u := (&provider{def: apple, clientID: "c"}).authorizationURL("https://app.example/cb", "s", nil, "", "n"); !strings.Contains(u, "response_mode=form_post") {
		t.Fatal(u)
	}
	if ms, _ := catalog("microsoft", ""); ms.IssuerPattern == nil || ms.Issuer != "" {
		t.Fatal("a common tenant accepts every tenant's issuer")
	}
	if ms, _ := catalog("microsoft", "contoso"); ms.Issuer != "https://login.microsoftonline.com/contoso/v2.0" {
		t.Fatal(ms.Issuer)
	}
}

func TestConfigurationErrorsNameTheirFix(t *testing.T) {
	rec := NewRecorded(t)
	cases := map[string]func(*Config){
		"BaseURL":     func(c *Config) { c.BaseURL = "/auth" },
		"Proxy":       func(c *Config) { c.Proxy = "auth.example" },
		"StateTTL":    func(c *Config) { c.StateTTL = -time.Second },
		"ClientID":    func(c *Config) { c.Providers["google"] = Provider{} },
		"not in the":  func(c *Config) { c.Providers["nope"] = Provider{ClientID: "x"} },
		"Apple needs": func(c *Config) { c.Providers["apple"] = Provider{ClientID: "x", PrivateKey: "junk"} },
		"Definition":  func(c *Config) { c.Providers["acme"] = Provider{ClientID: "x", Definition: &Definition{}} },
		"is empty":    func(c *Config) { c.Providers = nil },
		"Apple needs ": func(c *Config) {
			c.Providers["apple"] = Provider{ClientID: "x", TeamID: "t", KeyID: "k", PrivateKey: string(readTestdata(t, "idp-rsa.pem"))}
		},
	}
	for want, mutate := range cases {
		cfg := RecordedConfig(t, unitBase, rec)
		mutate(&cfg)
		p := New(cfg)
		g := polaristest.New(t).Graph()
		if err := p.Init(g); err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Fatalf("%s: %v", want, err)
		}
	}
}

func TestGoogleSignsUpSignsInAndLinksAnExistingUserBecauseItIsTrusted(t *testing.T) {
	h := newHarness(t)
	g := h.srv.Graph()
	_, err := h.p.start(h.ctx, "google", "https://evil.example/", nil, "")
	refused(t, err, kindRedirectNotAllowed, "redirect")
	s := h.restart("google")
	if !strings.HasPrefix(s.URL, "https://accounts.google.com/o/oauth2/v2/auth?client_id=google-client&redirect_uri=https%3A%2F%2Fapp.example%2Fauth%2Fsocial%2Fgoogle%2Fcallback") ||
		!strings.Contains(s.URL, "code_challenge_method=S256") {
		t.Fatal(s.URL)
	}
	_, err = h.callback("google", map[string]any{"code": "good", "state": "unknown"})
	refused(t, err, kindStateInvalid, "unknown state")
	_, err = h.callback("github", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindStateInvalid, "another provider's state")
	s = h.restart("google")
	_, err = h.callback("google", map[string]any{"error": "access_denied", "state": s.State})
	refused(t, err, kindProviderError, "provider error")
	s = h.restart("google")
	_, err = h.callback("google", map[string]any{"state": s.State})
	refused(t, err, kindProviderError, "no code")
	_, err = h.callback("google", map[string]any{})
	refused(t, err, kindStateInvalid, "no state")

	s = h.restart("google")
	redirect, err := h.callback("google", map[string]any{"code": "good", "state": s.State})
	if err != nil || !strings.HasPrefix(redirect, RecordedRedirect+"?code=") || !strings.HasSuffix(redirect, "&state="+s.State) {
		t.Fatalf("%q %v", redirect, err)
	}
	form := h.rec.requested()[0].Form
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "good" || form.Get("redirect_uri") != unitBase+"/social/google/callback" ||
		form.Get("client_id") != "google-client" || form.Get("client_secret") != "google-secret" || form.Get("code_verifier") == "" {
		t.Fatalf("token request %v", form)
	}
	data, err := h.p.exchange(h.ctx, queryParam(redirect, "code"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.p.exchange(h.ctx, queryParam(redirect, "code"))
	refused(t, err, kindCodeInvalid, "once")
	if data["token_type"] != "Bearer" || userOf(data)["email"] != "ada@example.com" || userOf(data)["email_verified"] != true {
		t.Fatalf("%v", data)
	}
	ada, err := g.Repos().Users.ByEmail(h.ctx, "ada@example.com")
	if err != nil || *ada.DisplayName != "Ada Lovelace" || ada.PasswordHash != nil || ada.EmailVerifiedAt == nil {
		t.Fatalf("signed up %+v %v", ada, err)
	}
	accts := h.accounts(ada.ID)
	if len(accts) != 1 || accts[0].ProviderAccountID != GoogleSub || accts[0].Profile["name"] != "Ada Lovelace" || strings.Contains(accts[0].AccessTokenEnc, "ya29") {
		t.Fatalf("accounts %+v", accts)
	}
	if access, _ := h.p.open(accts[0].AccessTokenEnc); access != "ya29.a0AfB_byC-recorded-google-access-token" {
		t.Fatal("encrypted at rest, readable back")
	}
	if h.count(EventSignedUp) != 1 || h.count(EventSignedIn) != 0 {
		t.Fatal(h.srv.Events.Names())
	}

	if again := h.signIn("google", ""); userOf(again)["id"] != ada.ID || h.count(EventSignedIn) != 1 {
		t.Fatal("signed in by the linked account")
	}

	grace := h.user("grace@example.com", true)
	h.rec.On(googleUserinfo, map[string]any{"sub": "g-grace", "email": "grace@example.com", "email_verified": true, "name": "Grace"})
	h.rec.Claims["google"] = map[string]any{"sub": "g-grace", "email": "grace@example.com"}
	if linked := h.signIn("google", ""); userOf(linked)["id"] != grace.ID || h.accounts(grace.ID)[0].Provider != "google" {
		t.Fatal("a trusted provider with a verified email links to the existing user")
	}

	bob := h.user("bob@example.com", true)
	h.rec.On(googleUserinfo, map[string]any{"sub": "g-bob", "email": "bob@example.com", "email_verified": false, "name": "Bob"})
	h.rec.Claims["google"] = map[string]any{"sub": "g-bob", "email": "bob@example.com", "email_verified": false}
	s = h.restart("google")
	_, err = h.callback("google", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindAccountExists, "not verified: no link")
	if len(h.accounts(bob.ID)) != 0 {
		t.Fatal("linked")
	}

	mallory := h.user("carol@example.com", false)
	stolen, err := g.Sessions().Issue(h.ctx, token.SessionPrincipal{UserID: mallory.ID}, h.client)
	if err != nil {
		t.Fatal(err)
	}
	h.rec.On(googleUserinfo, map[string]any{"sub": "g-carol", "email": "carol@example.com", "email_verified": true, "name": "Carol"})
	h.rec.Claims["google"] = map[string]any{"sub": "g-carol", "email": "carol@example.com", "email_verified": true}
	if claimed := h.signIn("google", ""); userOf(claimed)["id"] != mallory.ID {
		t.Fatal("the mailbox is proven now: the account is carol's")
	}
	carol, _ := g.Repos().Users.Get(h.ctx, mallory.ID)
	if carol.PasswordHash != nil || carol.EmailVerifiedAt == nil {
		t.Fatal("whoever registered the address without proving it lost the password")
	}
	if live, _ := g.DB().FindOne(h.ctx, "auth_refresh_tokens", store.Criteria{"family_id": stolen.SessionID, "revoked_at": nil}); live != nil {
		t.Fatal("and the sessions")
	}

	disabled := bob
	disabled.Status = model.UserStatusDisabled
	if err := g.Repos().Users.Update(h.ctx, bob, disabled); err != nil {
		t.Fatal(err)
	}
	h.rec.Claims["google"] = map[string]any{"sub": "g-bob", "email": "bob@example.com", "email_verified": true}
	h.rec.On(googleUserinfo, map[string]any{"sub": "g-bob", "email": "bob@example.com", "email_verified": true, "name": "Bob"})
	s = h.restart("google")
	_, err = h.callback("google", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindAccountDisabled, "disabled")
}

func TestGitHubIsNotTrustedAndLinksFromASession(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.AllowDifferentEmails = nil })
	grace := h.user("grace@example.com", true)
	s := h.restart("github")
	_, err := h.callback("github", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindAccountExists, "the email exists; GitHub is not trusted to link it")
	if h.count(EventRejected) != 1 {
		t.Fatal(h.srv.Events.Names())
	}

	started, err := h.p.start(h.ctx, "github", "", nil, grace.ID)
	if err != nil || strings.Contains(started.URL, "code_challenge") {
		t.Fatalf("GitHub does no PKCE: %v %v", started, err)
	}
	redirect, err := h.callback("github", map[string]any{"code": "good", "state": started.State})
	if err != nil {
		t.Fatal(err)
	}
	outcome, _ := h.p.exchange(h.ctx, queryParam(redirect, "code"))
	acct, _ := outcome["account"].(map[string]any)
	if outcome["status"] != "linked" || acct["provider_account_id"] != "583231" || acct["email"] != "grace@example.com" || acct["email_verified"] != true ||
		acct["profile"].(map[string]any)["name"] != "Grace Hopper" {
		t.Fatalf("the verified primary email from /user/emails: %v", outcome)
	}
	tok, err := h.p.providerToken(h.ctx, grace.ID, "github")
	if err != nil || tok["access_token"] != "gho_recordedGitHubAccessToken0123456789" || tok["expires_at"] != nil || !slices.Equal(tok["scopes"].([]string), []string{"read:user", "user:email"}) {
		t.Fatalf("token %v %v", tok, err)
	}
	if signedIn := h.signIn("github", ""); userOf(signedIn)["id"] != grace.ID {
		t.Fatal("linked: it signs in now")
	}

	bob := h.user("bob@example.com", true)
	started, _ = h.p.start(h.ctx, "github", "", nil, bob.ID)
	_, err = h.callback("github", map[string]any{"code": "good", "state": started.State})
	refused(t, err, kindAccountLinked, "grace's GitHub account")
	h.rec.On("https://api.github.com/user", map[string]any{"id": 999, "login": "bobby", "email": nil})
	h.rec.On("https://api.github.com/user/emails", []any{map[string]any{"email": "bobby@elsewhere.example", "primary": true, "verified": true}})
	started, _ = h.p.start(h.ctx, "github", "", nil, bob.ID)
	_, err = h.callback("github", map[string]any{"code": "good", "state": started.State})
	refused(t, err, kindEmailMismatch, "email mismatch")

	h = newHarnessOn(t, h.rec, func(c *Config) { c.AllowDifferentEmails = []string{"github"} })
	bob = h.user("bob@example.com", true)
	if out := h.signIn("github", bob.ID); out["status"] != "linked" {
		t.Fatal("allowed for GitHub")
	}
	refused(t, h.p.unlink(h.ctx, bob.ID, "google"), kindNotLinked, "not linked")
	if err := h.p.unlink(h.ctx, bob.ID, "github"); err != nil || len(h.accounts(bob.ID)) != 0 || h.count(EventUnlinked) != 1 {
		t.Fatalf("unlink %v", err)
	}
	_, err = h.p.start(h.ctx, "github", "", nil, "gone-user")
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnlinkingTheLastCredentialIsRefused(t *testing.T) {
	h := newHarness(t)
	ada, _ := userOf(h.signIn("google", ""))["id"].(string)
	refused(t, h.p.unlink(h.ctx, ada, "google"), kindLastCredential, "no password, one provider")
	if out := h.signIn("github", ada); out["status"] != "linked" {
		t.Fatal("linked from the session")
	}
	if err := h.p.unlink(h.ctx, ada, "google"); err != nil {
		t.Fatal(err)
	}
	if all := h.accounts(ada); len(all) != 1 || all[0].Provider != "github" {
		t.Fatalf("%+v", all)
	}
	// A link from a session whose user is gone is refused.
	s, _ := h.p.start(h.ctx, "acme", "", nil, "01900000-0000-7000-8000-000000000000")
	_, err := h.callback("acme", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindTokenInvalid, "the session's user is gone")
}

func TestAppleAndMicrosoftReadTheIdToken(t *testing.T) {
	h := newHarness(t)
	s := h.restart("apple")
	if !strings.Contains(s.URL, "response_mode=form_post") {
		t.Fatal(s.URL)
	}
	redirect, err := h.callback("apple", map[string]any{"code": "good", "state": s.State, "user": `{"name":{"firstName":"Alan","lastName":"Turing"},"email":"alan@example.com"}`})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := h.p.exchange(h.ctx, queryParam(redirect, "code"))
	alan, _ := h.srv.Graph().Repos().Users.Get(h.ctx, userOf(data)["id"].(string))
	if alan.Email != "alan@example.com" || *alan.DisplayName != "Alan Turing" || alan.EmailVerifiedAt == nil {
		t.Fatalf("the name from the first callback, the email from the id_token: %+v", alan)
	}
	secret := h.rec.requested()[0].Form.Get("client_secret")
	jws, err := jose.ParseSignedCompact(secret, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := jws.Verify(&h.p.providers["apple"].apple.PublicKey)
	if err != nil || !strings.Contains(string(payload), `"iss":"TEAM123"`) || !strings.Contains(string(payload), `"sub":"com.example.app"`) || jws.Signatures[0].Header.KeyID != "KEY123" {
		t.Fatalf("the client secret is a JWT under the team key: %s %v", payload, err)
	}

	if linus := h.signIn("microsoft", ""); userOf(linus)["email"] != "linus@example.com" {
		t.Fatal("a tenant issuer under the common endpoint")
	}
	h.rec.Claims["microsoft"] = map[string]any{"nonce": "stale"}
	s = h.restart("microsoft")
	_, err = h.callback("microsoft", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindProviderError, "a wrong nonce")
	h.rec.Claims["microsoft"] = map[string]any{"iss": "https://evil.example"}
	s = h.restart("microsoft")
	_, err = h.callback("microsoft", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindProviderError, "a wrong issuer")
	if h.count(EventRejected) != 2 {
		t.Fatal(h.srv.Events.Names())
	}
	if appleName(map[string]any{"name": map[string]any{"firstName": "Ada"}}) != "Ada" || appleName("not json") != "" || appleName(nil) != "" {
		t.Fatal("apple name")
	}
}

func TestOneTapVerifiesTheIdTokenOfflineAgainstTheRecordedKeys(t *testing.T) {
	h := newHarness(t)
	credential := h.rec.Mint(recordedGoogleSite, "google-client", GoogleSub, "ada@example.com", true, "Ada Lovelace")
	data, err := h.p.idTokenSignIn(h.ctx, "google", credential, h.client)
	if err != nil || userOf(data)["email"] != "ada@example.com" {
		t.Fatalf("%v %v", data, err)
	}
	var urls []string
	for _, r := range h.rec.requested() {
		urls = append(urls, r.URL)
	}
	if !slices.Equal(urls, []string{"https://accounts.google.com/.well-known/openid-configuration", "https://www.googleapis.com/oauth2/v3/certs"}) {
		t.Fatalf("discovery and the keys, nothing else: %v", urls)
	}
	if _, err := h.p.idTokenSignIn(h.ctx, "google", h.rec.Mint(recordedGoogleSite, "google-client", GoogleSub, "ada@example.com", true, ""), h.client); err != nil || len(h.rec.requested()) != 2 {
		t.Fatalf("the keys are cached: %v", err)
	}
	ada := userOf(data)["id"].(string)
	_, err = h.p.providerToken(h.ctx, ada, "google")
	refused(t, err, kindNoRefresh, "One Tap stores no provider token")
	h.signIn("google", "")
	h.rec.SetNonce("")
	if _, err := h.p.idTokenSignIn(h.ctx, "google", h.rec.Mint(recordedGoogleSite, "google-client", GoogleSub, "ada@example.com", true, ""), h.client); err != nil {
		t.Fatal(err)
	}
	if tok, err := h.p.providerToken(h.ctx, ada, "google"); err != nil || tok["access_token"] != "ya29.a0AfB_byC-recorded-google-access-token" {
		t.Fatalf("and does not clobber the one a callback stored: %v %v", tok, err)
	}

	parts := strings.Split(credential, ".")
	_, err = h.p.idTokenSignIn(h.ctx, "google", parts[0]+"."+parts[1]+"."+parts[2][:len(parts[2])-4]+"AAAA", h.client)
	refused(t, err, kindProviderError, "tampered")
	_, err = h.p.idTokenSignIn(h.ctx, "google", h.rec.Mint(recordedGoogleSite, "another-client", GoogleSub, "ada@example.com", true, ""), h.client)
	refused(t, err, kindProviderError, "another audience")
	_, err = h.p.idTokenSignIn(h.ctx, "github", credential, h.client)
	refused(t, err, kindInvalidInput, "not OpenID Connect")
	_, err = h.p.idTokenSignIn(h.ctx, "apple", "", h.client)
	refused(t, err, kindInvalidInput, "Apple: empty")
	_, err = h.p.idTokenSignIn(h.ctx, "nope", credential, h.client)
	refused(t, err, kindProviderNotFound, "unknown")
}

func TestIDTokenChecks(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	sign := func(kid string, claims map[string]any) string { return SignRS256(t, h.rec.key, kid, claims) }
	base := func(extra map[string]any) map[string]any {
		c := map[string]any{"iss": recordedGoogleSite, "aud": []any{"other", "google-client"}, "sub": GoogleSub, "email": "ada@example.com", "email_verified": "true"}
		for k, v := range extra {
			c[k] = v
		}
		return c
	}
	for msg, raw := range map[string]string{
		"expired":         sign(RecordedKID, base(map[string]any{"exp": now.Add(-2 * time.Minute).Unix()})),
		"not yet (nbf)":   sign(RecordedKID, base(map[string]any{"nbf": now.Add(2 * time.Minute).Unix()})),
		"not yet (iat)":   sign(RecordedKID, base(map[string]any{"iat": now.Add(2 * time.Minute).Unix()})),
		"non-numeric exp": sign(RecordedKID, base(map[string]any{"exp": "soon"})),
		"unknown kid":     sign("rotated", base(nil)),
		"no kid":          sign("", base(nil)),
		"not a JWT":       "not.a.jwt",
	} {
		_, err := h.p.idTokenSignIn(h.ctx, "google", raw, h.client)
		refused(t, err, kindProviderError, msg)
	}
	// Within the leeway, a list audience: valid.
	if _, err := h.p.idTokenSignIn(h.ctx, "google", sign(RecordedKID, base(map[string]any{"exp": now.Add(-30 * time.Second).Unix()})), h.client); err != nil {
		t.Fatal(err)
	}
	// A key whose alg is not the token's is refused; an empty key set is a provider error.
	es := map[string]any{"keys": []any{map[string]any{"kty": "RSA", "alg": "RS512", "kid": RecordedKID, "n": "0AoOBWTwYqYCbluFwdQU-AagNCLezYqiKNlzwgMw0LFn9jC57emfSX3pIKqONrflXn-xCTJZSqqz5H_4JICO3hf4AZQc3TDLQiUglRT0CE02Y0e3WhP7HQxr9RdffJ0_toUOWzLtcx4AH7IlN1OPdAnGFcIkeiulC4BaRdVXylt3Sl1oYc2PKGY0Pv5HCj2TXIeh2mA6MzCN-zHqMaKeD99oG2NqrvVkBqJum6dudRVNhetD3oUkosu_1k9eL8pEESSHktcCIxiePHcXpBU9d2JpCGy2G-epJ8pTThrzjdYvmPRStEVtdgHT3pTtTqWjAQUP5ujD4US3YPHZIXhbzw", "e": "AQAB"}}}
	h2 := newHarness(t)
	h2.rec.On("https://www.googleapis.com/oauth2/v3/certs", es)
	_, err := h2.p.idTokenSignIn(h2.ctx, "google", sign(RecordedKID, base(nil)), h2.client)
	refused(t, err, kindProviderError, "incorrect key for the algorithm")
	h3 := newHarness(t)
	h3.rec.On("https://www.googleapis.com/oauth2/v3/certs", map[string]any{"keys": []any{}})
	_, err = h3.p.idTokenSignIn(h3.ctx, "google", sign(RecordedKID, base(nil)), h3.client)
	refused(t, err, kindProviderError, "no keys")
	h4 := newHarness(t)
	h4.rec.On("https://accounts.google.com/.well-known/openid-configuration", map[string]any{"issuer": recordedGoogleSite})
	_, err = h4.p.idTokenSignIn(h4.ctx, "google", sign(RecordedKID, base(nil)), h4.client)
	refused(t, err, kindProviderError, "no jwks_uri")
}

func TestProviderTokensRefreshWhenExpiringAndAnyOAuth2ServerWorksFromItsDefinitionOrDiscovery(t *testing.T) {
	h := newHarness(t)
	h.rec.On("https://oauth2.googleapis.com/token", map[string]any{"access_token": "ya29.first", "expires_in": "30", "refresh_token": "1//0g-recorded-google-refresh-token",
		"scope": "openid", "id_token": h.rec.Mint(recordedGoogleSite, "google-client", GoogleSub, "ada@example.com", true, "Ada")})
	s := h.restart("google")
	h.rec.On("https://oauth2.googleapis.com/token", map[string]any{"access_token": "ya29.first", "expires_in": "30", "refresh_token": "1//0g-recorded-google-refresh-token",
		"scope": "openid", "id_token": h.rec.Mint(recordedGoogleSite, "google-client", GoogleSub, "ada@example.com", true, "Ada")})
	redirect, err := h.callback("google", map[string]any{"code": "good", "state": s.State})
	if err != nil {
		t.Fatal(err)
	}
	data, _ := h.p.exchange(h.ctx, queryParam(redirect, "code"))
	ada := userOf(data)["id"].(string)
	before := len(h.rec.requested())
	h.rec.On("https://oauth2.googleapis.com/token", map[string]any{"access_token": "ya29.refreshed", "expires_in": 3599, "scope": "openid email", "token_type": "Bearer"})
	refreshed, err := h.p.providerToken(h.ctx, ada, "google")
	if err != nil || refreshed["access_token"] != "ya29.refreshed" || refreshed["expires_at"] == nil {
		t.Fatalf("expiring within a minute: refreshed %v %v", refreshed, err)
	}
	req := h.rec.requested()[before]
	if req.Form.Get("grant_type") != "refresh_token" || req.Form.Get("refresh_token") != "1//0g-recorded-google-refresh-token" || h.count(EventTokenRefreshed) != 1 {
		t.Fatalf("refresh request %v", req.Form)
	}
	if again, _ := h.p.providerToken(h.ctx, ada, "google"); again["access_token"] != "ya29.refreshed" || len(h.rec.requested()) != before+1 {
		t.Fatal("still valid: no call")
	}
	_, err = h.p.providerToken(h.ctx, ada, "github")
	refused(t, err, kindNotLinked, "not linked")

	h.rec.On("https://acme.example/oauth/me", map[string]any{"id": "acme-43", "email": "zoe@example.com", "verified": false, "name": "Zoe"})
	s = h.restart("acme")
	_, err = h.callback("acme", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindEmailUnverified, "signed up unverified: core requires a verified email to sign in")
	if _, err := h.srv.Graph().Repos().Users.ByEmail(h.ctx, "zoe@example.com"); err != nil {
		t.Fatal("the account exists, to verify")
	}
	h.rec.On("https://acme.example/oauth/me", map[string]any{"id": "acme-42", "email": "eve@example.com", "verified": true, "name": "Eve"})
	eve := userOf(h.signIn("acme", ""))["id"].(string)
	// An acme token that expires and comes back with an HTTP error is a provider error.
	h.rec.Answer("https://acme.example/oauth/token", 400, map[string]any{"error": "invalid_grant", "error_description": "expired"})
	g := h.srv.Graph()
	if _, err := g.DB().Update(h.ctx, TableAccounts, store.Criteria{"user_id": eve}, store.Data{"expires_at": time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	_, err = h.p.providerToken(h.ctx, eve, "acme")
	if r, ok := asRefusal(err); !ok || r.kind != kindProviderError || !strings.Contains(r.detail, "HTTP 400: expired") {
		t.Fatalf("refresh refused: %v", err)
	}
	g.Events().Dispatch(h.ctx, event.UserDeleted{UserID: eve})
	if len(h.accounts(eve)) != 0 {
		t.Fatal("an erased user leaves no provider account")
	}
	s = h.restart("okta")
	if !strings.HasPrefix(s.URL, "https://acme.okta.example/oauth2/v1/authorize?") {
		t.Fatalf("discovered: %s", s.URL)
	}
	redirect, err = h.callback("okta", map[string]any{"code": "good", "state": s.State})
	if err != nil {
		t.Fatal(err)
	}
	if frank, _ := h.p.exchange(h.ctx, queryParam(redirect, "code")); userOf(frank)["email"] != "frank@example.com" {
		t.Fatal(frank)
	}
}

func TestSignUpPolicyAndTheMFAGate(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.DisableSignUp = true })
	s := h.restart("acme")
	_, err := h.callback("acme", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindAccountExists, "sign-up is off")

	h = newHarness(t)
	h.rec.On("https://acme.example/oauth/me", map[string]any{"id": "acme-44"})
	s = h.restart("acme")
	_, err = h.callback("acme", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindEmailRequired, "no email")
	h.rec.On("https://acme.example/oauth/me", map[string]any{"email": "nosub@example.com"})
	s = h.restart("acme")
	_, err = h.callback("acme", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindProviderError, "no subject")
	h.rec.Answer("https://acme.example/oauth/token", 200, map[string]any{"token_type": "Bearer"})
	s = h.restart("acme")
	_, err = h.callback("acme", map[string]any{"code": "good", "state": s.State})
	refused(t, err, kindProviderError, "no access token")
	h.rec.Answer("https://acme.example/oauth/token", 200, "access_token=form-access&scope=profile,email")
	h.rec.On("https://acme.example/oauth/me", map[string]any{"id": "acme-45", "email": "form@example.com", "verified": true})
	if out := h.signIn("acme", ""); userOf(out)["email"] != "form@example.com" {
		t.Fatalf("a form-encoded token answer: %v", out)
	}

	u := h.user("mfa@example.com", true)
	now := time.Now().UTC().Truncate(time.Second)
	f := model.MFAFactor{ID: repository.NewID(), UserID: u.ID, Type: model.FactorTOTP, ConfirmedAt: &now, IsDefault: true, CreatedAt: now, UpdatedAt: now}
	if err := h.srv.Graph().Repos().MFAFactors.Insert(h.ctx, f); err != nil {
		t.Fatal(err)
	}
	h.rec.On("https://acme.example/oauth/me", map[string]any{"id": "acme-46", "email": "mfa@example.com", "verified": true})
	if out := h.signIn("acme", u.ID); out["status"] != "linked" {
		t.Fatal(out)
	}
	if out := h.signIn("acme", ""); out["mfa_required"] != true || out["mfa_token"] == "" {
		t.Fatalf("core's gate: %v", out)
	}
	h = newHarnessOn(t, h.rec, func(c *Config) { c.SkipMFA = true })
	u = h.user("mfa@example.com", true)
	if err := h.srv.Graph().Repos().MFAFactors.Insert(h.ctx, model.MFAFactor{ID: repository.NewID(), UserID: u.ID, Type: model.FactorTOTP, ConfirmedAt: &now, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	h.signIn("acme", u.ID)
	if out := h.signIn("acme", ""); out["access_token"] == nil {
		t.Fatalf("SkipMFA: %v", out)
	}
}

func TestTheProxyForwardsASignedStateAndRefusesAnUnsignedOne(t *testing.T) {
	rec := NewRecorded(t)
	preview := newHarnessOn(t, rec, func(c *Config) { c.BaseURL, c.Proxy = "https://pr-42.preview.example/auth", "https://auth.example/" })
	stable := newHarnessOn(t, rec, func(c *Config) { c.BaseURL, c.Proxy = "https://auth.example/auth", "https://auth.example" })

	started, err := preview.p.start(preview.ctx, "google", "", nil, "")
	if err != nil || !strings.Contains(started.URL, "redirect_uri=https%3A%2F%2Fauth.example%2Fsocial%2Fgoogle%2Fcallback") || strings.Count(started.State, ".") != 2 {
		t.Fatalf("the provider sends the browser to the stable origin: %v %v", started, err)
	}
	forward, err := stable.callback("google", map[string]any{"code": "good", "state": started.State})
	if err != nil || forward != "https://pr-42.preview.example/auth/social/google/callback?code=good&state="+rawURLEncode(started.State) {
		t.Fatalf("forwarded with everything the provider sent: %q %v", forward, err)
	}
	parts := strings.Split(started.State, ".")
	forged := base64.RawURLEncoding.EncodeToString([]byte(`{"return_to":"https://evil.example/social/google/callback"}`))
	for msg, state := range map[string]string{
		"a tampered return_to": parts[0] + "." + forged + "." + parts[2],
		"unsigned":             parts[0] + "." + parts[1] + ".unsigned",
		"a plain state":        parts[0],
	} {
		_, err := stable.callback("google", map[string]any{"code": "good", "state": state})
		refused(t, err, kindStateInvalid, msg)
	}
	_, err = stable.callback("github", map[string]any{"code": "good", "state": started.State})
	refused(t, err, kindStateInvalid, "signed for another provider")
	sign := func(payload string) string {
		random := "abc"
		encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
		return random + "." + encoded + "." + stable.p.proxySignature(random+"."+encoded)
	}
	_, err = stable.callback("google", map[string]any{"state": sign(`{"return_to":"https://pr-42.preview.example/auth/social/google/callback","provider":"google","exp":1}`)})
	refused(t, err, kindStateInvalid, "expired with the state")
	_, err = stable.callback("google", map[string]any{"state": sign(`{"return_to":"https://pr-42.preview.example/elsewhere","provider":"google","exp":99999999999}`)})
	refused(t, err, kindStateInvalid, "names no callback")
	if f, _ := stable.callback("google", map[string]any{"user": map[string]any{"a": 1}, "state": sign(`{"return_to":"https://pr-42.preview.example/auth/social/google/callback?x=1","provider":"google","exp":99999999999}`)}); f != "" {
		t.Fatal(f)
	}

	rec.SetNonce(queryParam(started.URL, "nonce"))
	redirect, err := preview.callback("google", map[string]any{"code": "good", "state": started.State})
	if err != nil || !strings.HasPrefix(redirect, RecordedRedirect+"?code=") {
		t.Fatalf("the preview completes its own flow: %v", err)
	}
	var exchanged string
	for _, r := range rec.requested() {
		if r.Form.Get("grant_type") == "authorization_code" {
			exchanged = r.Form.Get("redirect_uri")
		}
	}
	if exchanged != "https://auth.example/social/google/callback" {
		t.Fatalf("the exchange names the redirect_uri the provider saw: %q", exchanged)
	}
	if out, _ := preview.p.exchange(preview.ctx, queryParam(redirect, "code")); userOf(out)["email"] != "ada@example.com" {
		t.Fatal(out)
	}
	if own, _ := stable.p.start(stable.ctx, "google", "", nil, ""); strings.Contains(own.State, ".") {
		t.Fatal("the stable origin signs nothing for itself")
	}
}

func TestCatalogProfiles(t *testing.T) {
	cases := map[string]map[string]any{
		"github":   {"id": jsonNumber("7"), "login": "octo", "email": "o@example.com", "email_verified": true},
		"discord":  {"id": "d1", "username": "disc", "email": "d@example.com", "verified": true},
		"facebook": {"id": "f1", "name": "Fa", "email": "f@example.com", "picture": map[string]any{"data": map[string]any{"url": "p"}}},
		"x":        {"data": map[string]any{"id": "x1", "confirmed_email": "x@example.com", "name": "X"}},
		"spotify":  {"id": "s1", "email": "s@example.com", "images": []any{map[string]any{"url": "p"}}},
		"zoom":     {"id": "z1", "email": "z@example.com", "verified": jsonNumber("1")},
		"notion":   {"owner": map[string]any{"user": map[string]any{"id": "n1", "name": "N", "person": map[string]any{"email": "n@example.com"}}}},
		"dropbox":  {"account_id": "db1", "email": "db@example.com", "email_verified": true, "name": map[string]any{"display_name": "DB"}},
		"reddit":   {"id": "r1", "name": "red"},
		"kick":     {"data": []any{map[string]any{"user_id": jsonNumber("5"), "email": "k@example.com", "name": "K"}}},
		"tiktok":   {"data": map[string]any{"user": map[string]any{"open_id": "t1", "display_name": "T"}}},
		"gitlab":   {"sub": "g1", "email": "g@example.com", "email_verified": jsonNumber("1"), "preferred_username": "gl"},
	}
	for id, data := range cases {
		def, _ := catalog(id, "")
		if p := def.Profile(data); p.Subject == "" || p.Name == "" && p.Email == "" {
			t.Fatalf("%s: %+v", id, p)
		}
	}
	if p := (Profile{Name: "  " + strings.Repeat("é", 130)}).normalized(); len([]rune(p.Name)) != 118 {
		t.Fatalf("a name fits core's display name: %d", len([]rune(p.Name)))
	}
	if str(true) != "1" || str(1.5) != "1.5" || truthy("0") || !truthy([]any{1}) || !truthy(map[string]any{"a": 1}) || truthy(nil) || !truthy(1.0) {
		t.Fatal("str and truthy read profile scalars")
	}
}

func jsonNumber(s string) json.Number { return json.Number(s) }
