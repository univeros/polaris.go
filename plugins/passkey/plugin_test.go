package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/mfa"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
)

// Port of upstream's PluginTest: the ceremonies through the graph with the software authenticator.

const (
	unitOrigin = "https://app.example"
	unitPass   = "correct horse battery staple"
)

type harness struct {
	t      *testing.T
	p      *Plugin
	srv    *polaristest.Server
	ctx    context.Context
	client token.ClientContext
}

func newHarness(t *testing.T, cfg ...Config) *harness {
	t.Helper()
	c := Config{Origins: []string{unitOrigin}, RPName: "Polaris tests"}
	if len(cfg) > 0 {
		c = cfg[0]
	}
	p := New(c)
	return &harness{t: t, p: p, srv: polaristest.New(t, polaristest.WithPlugins(p)), ctx: context.Background(), client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}}
}

func (h *harness) user(email string) model.User {
	h.t.Helper()
	g := h.srv.Graph()
	hash, _ := g.Hasher.Hash(unitPass)
	now := time.Now().UTC().Truncate(time.Second)
	name := "Ada"
	u := model.User{ID: repository.NewID(), Email: email, DisplayName: &name, PasswordHash: &hash, EmailVerifiedAt: &now, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := g.Repos.Users.Insert(h.ctx, u); err != nil {
		h.t.Fatal(err)
	}
	return u
}

func (h *harness) options(u model.User) map[string]any {
	h.t.Helper()
	o, err := h.p.registerOptions(h.ctx, u)
	if err != nil {
		h.t.Fatal(err)
	}
	return roundTrip(o)
}

func (h *harness) request() map[string]any {
	h.t.Helper()
	o, err := h.p.authenticateOptions(h.ctx)
	if err != nil {
		h.t.Fatal(err)
	}
	return roundTrip(o)
}

func (h *harness) register(u model.User, a *Authenticator, name string) registered {
	h.t.Helper()
	r, err := h.p.register(h.ctx, u, js(a.Create(h.options(u), unitOrigin, true)), name)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *harness) list(userID string) []record {
	h.t.Helper()
	all, err := h.p.forUser(h.ctx, userID)
	if err != nil {
		h.t.Fatal(err)
	}
	return all
}

// roundTrip is the options as the browser reads them (JSON).
func roundTrip(v map[string]any) map[string]any {
	raw, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func js(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func refused(t *testing.T, err error, want kind, msg string) {
	t.Helper()
	r, ok := asRefusal(err)
	if !ok || r.kind != want {
		t.Fatalf("%s: got %v, want %s", msg, err, want)
	}
}

func TestEverythingIsWiredThroughTheGraph(t *testing.T) {
	h := newHarness(t)
	g := h.srv.Graph()
	if !slices.ContainsFunc(g.Schema, func(m schema.Model) bool { return m.Table == TablePasskeys }) {
		t.Fatal("the table joins the schema")
	}
	var routes []string
	for _, r := range g.Manifest.Routes() {
		if r.Plugin == ID {
			step := ""
			if r.StepUp {
				step = " step_up"
			}
			routes = append(routes, r.Method+" "+r.Path+" "+string(r.Auth)+step)
		}
	}
	want := []string{"POST /passkey/register/options bearer step_up", "POST /passkey/register/verify bearer step_up", "POST /passkey/authenticate/options public",
		"POST /passkey/authenticate/verify public", "GET /passkey/list bearer", "PATCH /passkey/{id} bearer", "DELETE /passkey/{id} bearer step_up"}
	slices.Sort(routes)
	slices.Sort(want)
	if !slices.Equal(routes, want) {
		t.Fatalf("routes %v", routes)
	}
	if h.p.settings.rpID != "app.example" || !slices.Equal(h.p.settings.origins, []string{unitOrigin}) {
		t.Fatal(h.p.settings)
	}
	if len(h.p.MFAFactorTypes()) != 1 || h.p.MFAFactorTypes()[0].Type() != FactorType || New(Config{NoMFAFactor: true}).MFAFactorTypes() != nil {
		t.Fatal("factor types")
	}
	s, err := Config{Origins: []string{"https://app.example", "http://localhost:8080/"}, Attachment: "platform", UserVerification: UVRequired}.settings()
	if err != nil || s.origins[1] != "http://localhost:8080" || s.creationOptions([]byte("c"), "u", "n", "d", nil)["authenticatorSelection"].(map[string]any)["authenticatorAttachment"] != "platform" {
		t.Fatalf("%v %v", s, err)
	}
	for _, invalid := range []Config{{}, {Origins: []string{"app.example"}}, {Origins: []string{"https://app.example/auth"}}, {Origins: []string{unitOrigin}, UserVerification: "always"},
		{Origins: []string{unitOrigin}, Attachment: "usb"}, {Origins: []string{"http://app.example"}}, {Origins: []string{unitOrigin}, Timeout: -1}} {
		if _, err := invalid.settings(); err == nil {
			t.Fatalf("the settings are validated: %+v", invalid)
		}
	}
	if err := New(Config{}).Init(g); err == nil || !strings.Contains(err.Error(), "Origins is empty") {
		t.Fatal(err)
	}
}

func TestRegistrationMakesAPasskeyAndAConfirmedCoreFactor(t *testing.T) {
	h := newHarness(t)
	g := h.srv.Graph()
	ada, grace := h.user("ada@example.com"), h.user("grace@example.com")
	a := NewAuthenticator(t)

	options := h.options(ada)
	rp := options["rp"].(map[string]any)
	sel := options["authenticatorSelection"].(map[string]any)
	if rp["id"] != "app.example" || rp["name"] != "Polaris tests" || options["user"].(map[string]any)["name"] != "ada@example.com" ||
		options["user"].(map[string]any)["displayName"] != "Ada" || sel["residentKey"] != "required" || len(options["excludeCredentials"].([]any)) != 0 {
		t.Fatalf("options %v", options)
	}
	_, err := h.p.register(h.ctx, ada, js(a.Create(options, "https://evil.example", true)), "MacBook")
	refused(t, err, kindOriginMismatch, "origin")
	_, err = h.p.register(h.ctx, grace, js(a.Create(options, unitOrigin, true)), "MacBook")
	refused(t, err, kindChallengeInvalid, "another user's challenge, and it is spent")
	_, err = h.p.register(h.ctx, ada, js(a.Create(options, unitOrigin, true)), "MacBook")
	refused(t, err, kindChallengeInvalid, "once")
	_, err = h.p.register(h.ctx, ada, `{"nope":true}`, "")
	refused(t, err, kindInvalidInput, "not a credential")
	_, err = h.p.register(h.ctx, ada, js(a.Create(h.options(ada), unitOrigin, true)), strings.Repeat("x", 81))
	refused(t, err, kindInvalidInput, "name too long")

	reg := h.register(ada, a, " MacBook ")
	pk := reg.passkey
	if pk.Name != "MacBook" || pk.CredentialID != b64(a.CredentialID) || !slices.Equal(pk.Transports, []string{"internal", "hybrid"}) || !pk.BackedUp ||
		pk.AAGUID != "00000000-0000-0000-0000-000000000000" || len(reg.recoveryCodes) == 0 || pk.FactorID == "" {
		t.Fatalf("registered %+v", reg)
	}
	f, err := g.Repos.MFAFactors.Get(h.ctx, pk.FactorID)
	if err != nil || f.Type != FactorType || *f.Label != "MacBook" || f.UserID != ada.ID || f.ConfirmedAt == nil {
		t.Fatalf("factor %+v %v", f, err)
	}
	if n := slices.Index(h.srv.Events.Names(), "mfa.enrolled"); n < 0 {
		t.Fatal(h.srv.Events.Names())
	}

	options = h.options(ada)
	if options["excludeCredentials"].([]any)[0].(map[string]any)["id"] != b64(a.CredentialID) {
		t.Fatal("the existing passkey is excluded")
	}
	_, err = h.p.register(h.ctx, ada, js(a.Create(options, unitOrigin, true)), "")
	refused(t, err, kindCredentialInvalid, "the same credential again")
	second := h.register(ada, NewAuthenticator(t), "")
	if second.passkey.Name != DefaultName || len(second.recoveryCodes) != 0 || len(h.list(ada.ID)) != 2 {
		t.Fatalf("a second factor answers no codes: %+v", second)
	}

	plain := newHarness(t, Config{Origins: []string{unitOrigin}, NoMFAFactor: true})
	bob := plain.user("bob@example.com")
	if r := plain.register(bob, NewAuthenticator(t), ""); r.passkey.FactorID != "" || len(r.recoveryCodes) != 0 {
		t.Fatalf("not a factor: %+v", r)
	}
	if fs, _ := plain.srv.Graph().MFA.Factors(plain.ctx, bob.ID); len(fs) != 0 {
		t.Fatal(fs)
	}
}

func TestDiscoverableSignInOpensASessionAndTheGateAppliesWithoutUserVerification(t *testing.T) {
	h := newHarness(t)
	g := h.srv.Graph()
	ada := h.user("ada@example.com")
	a := NewAuthenticator(t)
	h.register(ada, a, "MacBook")

	options := h.request()
	if len(options["allowCredentials"].([]any)) != 0 || options["rpId"] != "app.example" {
		t.Fatal("discoverable: no credential named")
	}
	_, err := h.p.authenticate(h.ctx, js(a.Get(options, "https://evil.example", ada.ID, true, 0)), h.client)
	refused(t, err, kindOriginMismatch, "origin")
	_, err = h.p.authenticate(h.ctx, js(NewAuthenticator(t).Get(options, unitOrigin, ada.ID, true, 0)), h.client)
	refused(t, err, kindCredentialInvalid, "an unknown credential, and the challenge is spent")
	_, err = h.p.authenticate(h.ctx, js(a.Get(options, unitOrigin, ada.ID, true, 0)), h.client)
	refused(t, err, kindChallengeInvalid, "once")

	assertion := js(a.Get(h.request(), unitOrigin, ada.ID, true, 1))
	data, err := h.p.authenticate(h.ctx, assertion, h.client)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := g.Tokens.Parse(data["access_token"].(string))
	if amr, _ := tok.Claim("amr").([]any); !slices.Equal(amr, []any{"passkey"}) || tok.Claim("mfa") != true || tok.Subject() != ada.ID {
		t.Fatal("user verification: the gate is passed")
	}
	if l := h.list(ada.ID)[0]; l.Counter != 1 || l.LastUsedAt == nil {
		t.Fatalf("%+v", l)
	}
	_, err = h.p.authenticate(h.ctx, assertion, h.client)
	refused(t, err, kindChallengeInvalid, "replayed")
	_, err = h.p.authenticate(h.ctx, js(a.Get(h.request(), unitOrigin, ada.ID, true, 1)), h.client)
	refused(t, err, kindCredentialInvalid, "a counter that did not move: a cloned authenticator")
	_, err = h.p.authenticate(h.ctx, js(a.Get(h.request(), unitOrigin, "someone-else", true, 2)), h.client)
	refused(t, err, kindCredentialInvalid, "another user's handle")
	_, err = h.p.authenticate(h.ctx, js(a.Get(h.request(), unitOrigin, ada.ID, false, 2)), h.client)
	refused(t, err, kindUserVerificationReqd, "no user verification and the passkey is the only factor")

	now := time.Now().UTC().Truncate(time.Second)
	if err := g.Repos.MFAFactors.Insert(h.ctx, model.MFAFactor{ID: repository.NewID(), UserID: ada.ID, Type: model.FactorTOTP, ConfirmedAt: &now, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	gated, err := h.p.authenticate(h.ctx, js(a.Get(h.request(), unitOrigin, ada.ID, false, 3)), h.client)
	if err != nil || gated["mfa_required"] != true || gated["access_token"] != nil {
		t.Fatalf("no user verification: one factor, the gate applies: %v %v", gated, err)
	}
	if views := gated["factors"].([]mfa.FactorView); len(views) != 1 || views[0].Type != model.FactorTOTP {
		t.Fatalf("the signing passkey is not offered as its own second factor: %v", views)
	}

	disabled := ada
	disabled.Status = model.UserStatusDisabled
	_ = g.Repos.Users.Update(h.ctx, ada, disabled)
	_, err = h.p.authenticate(h.ctx, js(a.Get(h.request(), unitOrigin, ada.ID, true, 4)), h.client)
	refused(t, err, kindAccountDisabled, "disabled")
	unverified := disabled
	unverified.Status, unverified.EmailVerifiedAt = model.UserStatusActive, nil
	_ = g.Repos.Users.Update(h.ctx, disabled, unverified)
	_, err = h.p.authenticate(h.ctx, js(a.Get(h.request(), unitOrigin, ada.ID, true, 5)), h.client)
	refused(t, err, kindEmailUnverified, "core requires a verified email to sign in")

	plain := newHarness(t, Config{Origins: []string{unitOrigin}, NoMFAFactor: true})
	bob := plain.user("bob@example.com")
	key := NewAuthenticator(t)
	plain.register(bob, key, "")
	out, err := plain.p.authenticate(plain.ctx, js(key.Get(plain.request(), unitOrigin, bob.ID, false, 0)), plain.client)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ = plain.srv.Graph().Tokens.Parse(out["access_token"].(string))
	if tok.Claim("mfa") != false {
		t.Fatal("no factor to gate on: a one-factor session")
	}
}

func TestAPasskeyIsASecondFactorThroughCoresGateAndStepUp(t *testing.T) {
	h := newHarness(t)
	g := h.srv.Graph()
	ada := h.user("ada@example.com")
	a, other := NewAuthenticator(t), NewAuthenticator(t)
	pk := h.register(ada, a, "MacBook").passkey
	h.register(ada, other, "Phone")

	login, err := g.Identity.Login(h.ctx, "ada@example.com", unitPass, h.client)
	if err != nil || login.MFA == nil || login.MFA.Factors[0].ID != pk.FactorID {
		t.Fatalf("the password login hits the gate: %+v %v", login, err)
	}
	assertion := a.GetJSON(h.request(), unitOrigin, ada.ID, true, 0)
	if _, err := g.MFA.VerifyLogin(h.ctx, ada.ID, pk.FactorID, other.GetJSON(h.request(), unitOrigin, ada.ID, true, 0), h.client); !errors.Is(err, mfa.ErrInvalidOTP) {
		t.Fatalf("another passkey than the factor's: %v", err)
	}
	tokens, err := g.MFA.VerifyLogin(h.ctx, ada.ID, pk.FactorID, assertion, h.client)
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := g.Tokens.Parse(tokens.AccessToken)
	if amr, _ := tok.Claim("amr").([]any); !slices.Equal(amr, []any{"pwd", "otp"}) || tok.Claim("mfa") != true {
		t.Fatal("core's post-MFA session")
	}
	if _, err := g.MFA.VerifyLogin(h.ctx, ada.ID, pk.FactorID, assertion, h.client); !errors.Is(err, mfa.ErrInvalidOTP) {
		t.Fatalf("replayed: %v", err)
	}
	if _, err := g.MFA.VerifyStepUp(h.ctx, ada.ID, "", tokens.SessionID, pk.FactorID, a.GetJSON(h.request(), unitOrigin, ada.ID, true, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := g.MFA.Challenge(h.ctx, ada.ID, pk.FactorID, mfa.PurposeLoginMFA, h.client); !errors.Is(err, mfa.ErrInvalidOTP) {
		t.Fatalf("a passkey has no sent challenge: %v", err)
	}

	if err := g.MFA.RemoveFactor(h.ctx, ada.ID, pk.FactorID); err != nil {
		t.Fatal(err)
	}
	if l := h.list(ada.ID); l[0].FactorID != "" {
		t.Fatal("removed under core's route: the passkey stays, detached")
	}
	if out, err := h.p.authenticate(h.ctx, a.GetJSON(h.request(), unitOrigin, ada.ID, true, 2), h.client); err != nil || out["access_token"] == nil {
		t.Fatalf("still a sign-in credential: %v", err)
	}
	// A factor no passkey backs any more is a wrong code.
	if err := (factor{h.p}).Verify(h.ctx, model.MFAFactor{ID: pk.FactorID, UserID: ada.ID}, "{}", mfa.PurposeStepUp); !errors.Is(err, mfa.ErrInvalidOTP) {
		t.Fatal(err)
	}
	g.Events.Dispatch(h.ctx, event.UserDeleted{UserID: ada.ID})
	if len(h.list(ada.ID)) != 0 {
		t.Fatal("an erased user leaves no passkey")
	}
}

func TestRenameAndDeleteKeepCoreInStep(t *testing.T) {
	h := newHarness(t)
	g := h.srv.Graph()
	ada, grace := h.user("ada@example.com"), h.user("grace@example.com")
	pk := h.register(ada, NewAuthenticator(t), "MacBook").passkey

	_, err := h.p.rename(h.ctx, grace.ID, pk.ID, "Mine")
	refused(t, err, kindNotFound, "not grace's")
	_, err = h.p.rename(h.ctx, ada.ID, pk.ID, strings.Repeat("x", 81))
	refused(t, err, kindInvalidInput, "too long")
	if r, err := h.p.rename(h.ctx, ada.ID, pk.ID, "Work laptop"); err != nil || r.Name != "Work laptop" {
		t.Fatal(err)
	}
	if f, _ := g.Repos.MFAFactors.Get(h.ctx, pk.FactorID); *f.Label != "Work laptop" {
		t.Fatal("the factor follows")
	}

	enforced := ada
	enforced.MFAEnforced = true
	_ = g.Repos.Users.Update(h.ctx, ada, enforced)
	refused(t, h.p.remove(h.ctx, ada.ID, pk.ID), kindLastFactor, "protected")
	_ = g.Repos.Users.Update(h.ctx, enforced, ada)
	refused(t, h.p.remove(h.ctx, grace.ID, pk.ID), kindNotFound, "not grace's")
	if err := h.p.remove(h.ctx, ada.ID, pk.ID); err != nil {
		t.Fatal(err)
	}
	if fs, _ := g.MFA.Factors(h.ctx, ada.ID); len(h.list(ada.ID)) != 0 || len(fs) != 0 {
		t.Fatal("the passkey and its factor are gone")
	}
	// A passkey whose factor went under core's route renames and deletes alone.
	pk = h.register(ada, NewAuthenticator(t), "Phone").passkey
	if _, err := g.DB.Delete(h.ctx, "auth_mfa_factors", store.Criteria{"id": pk.FactorID}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.p.rename(h.ctx, ada.ID, pk.ID, ""); err != nil {
		t.Fatal(err)
	}
	if err := h.p.remove(h.ctx, ada.ID, pk.ID); err != nil {
		t.Fatal(err)
	}
}
