package social

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/token"
)

const victimPassword = "correct horse battery staple"

// post is one JSON POST to the server: the status and the decoded data.
func (h *harness) post(path string, body map[string]any) (int, map[string]any) {
	h.t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.srv.Handler().ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if d, ok := out["data"].(map[string]any); ok {
		out = d
	}
	return w.Code, out
}

// unvouched makes the acme provider answer the attacker's account, carrying the victim's address
// without vouching for it.
func (h *harness) unvouched(email string) {
	h.rec.On("https://acme.example/oauth/me", map[string]any{"id": "acme-attacker", "email": email, "verified": false, "name": "Mallory"})
}

// attempt runs a whole acme sign-in: the outcome, or the refusal.
func (h *harness) attempt() (map[string]any, error) {
	h.t.Helper()
	s := h.restart("acme")
	redirect, err := h.callback("acme", map[string]any{"code": "good", "state": s.State})
	if err != nil {
		return nil, err
	}
	return h.p.exchange(h.ctx, queryParam(redirect, "code"))
}

// A provider that does not vouch for an email creates nothing in the address's name: the person
// who owns the mailbox registers later and the provider account is not a way into their account.
func TestAnUnvouchedEmailLeavesNoAccountAndNoLink(t *testing.T) {
	h := newHarness(t)
	h.unvouched("victim@example.com")
	_, err := h.attempt()
	refused(t, err, kindEmailUnverified, "the provider does not vouch for the address")
	if u, _ := h.userByEmail(h.ctx, "victim@example.com"); u != nil {
		t.Errorf("an account was created for an address nobody proved: %s", u.ID)
	}
	if acct, _ := h.p.findAccount(h.ctx, accountKey("acme", "acme-attacker")); acct != nil {
		t.Errorf("the provider account stayed linked to %s", acct.UserID)
	}

	// The owner of the mailbox arrives: registers, verifies, signs in.
	if code, body := h.post("/auth/register", map[string]any{"email": "victim@example.com", "password": victimPassword}); code >= 300 {
		t.Fatalf("register: %d %v", code, body)
	}
	var reg event.UserRegistered
	for _, e := range h.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok {
			reg = r
		}
	}
	if reg.VerificationToken == "" {
		t.Fatal("the owner's registration created no account: the address was taken")
	}
	if code, body := h.post("/auth/email/verify", map[string]any{"token": reg.VerificationToken}); code != 200 {
		t.Fatalf("verify: %d %v", code, body)
	}
	if code, body := h.post("/auth/login", map[string]any{"email": "victim@example.com", "password": victimPassword}); code != 200 {
		t.Fatalf("the owner signs in: %d %v", code, body)
	}

	out, err := h.attempt()
	if err == nil {
		t.Fatalf("the provider account signed in to the owner's account: %v", userOf(out))
	}
	refused(t, err, kindAccountExists, "an untrusted provider does not link by email")
}

func (h *harness) userByEmail(ctx context.Context, email string) (*struct{ ID string }, error) {
	u, err := h.p.userByEmail(ctx, email)
	if err != nil || u == nil {
		return nil, err
	}
	return &struct{ ID string }{u.ID}, nil
}

// Where unverified accounts may sign in (RequireVerifiedEmail off), the unvouched sign-up opens a
// session and keeps its link, until someone proves the mailbox: the first proof is the owner's,
// and everything that could sign in before it goes.
func TestTheFirstProofOfTheMailboxRemovesWhatCameBefore(t *testing.T) {
	rec := NewRecorded(t)
	cfg := RecordedConfig(t, unitBase, rec)
	p := New(cfg)
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), p),
		polaristest.WithAuth(func(a *config.Auth) { a.Flows.RequireVerifiedEmail = false }))
	h := &harness{t: t, p: p, srv: srv, rec: rec, client: token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}, ctx: context.Background()}
	g := srv.Graph()

	h.unvouched("victim@example.com")
	out, err := h.attempt()
	if err != nil {
		t.Fatalf("unverified accounts sign in here: %v", err)
	}
	attackerRefresh, _ := out["refresh_token"].(string)
	victim, err := g.Repos().Users.ByEmail(h.ctx, "victim@example.com")
	if err != nil || victim.EmailVerifiedAt != nil || len(h.accounts(victim.ID)) != 1 {
		t.Fatalf("the unverified account and its link: %+v %v", victim, err)
	}

	// The owner recovers the account through the mailbox.
	if code, body := h.post("/auth/password/forgot", map[string]any{"email": "victim@example.com"}); code >= 300 {
		t.Fatalf("forgot: %d %v", code, body)
	}
	var reset event.PasswordResetRequested
	for _, e := range srv.Events.All() {
		if r, ok := e.(event.PasswordResetRequested); ok {
			reset = r
		}
	}
	if code, body := h.post("/auth/password/reset", map[string]any{"token": reset.ResetToken, "password": victimPassword, "new_password": victimPassword}); code != 200 {
		t.Fatalf("reset: %d %v", code, body)
	}

	if left := h.accounts(victim.ID); len(left) != 0 {
		t.Errorf("the provider account linked before the proof is still linked: %v", left[0].Provider)
	}
	if code, _ := h.post("/auth/token/refresh", map[string]any{"refresh_token": attackerRefresh}); code == 200 {
		t.Error("the session opened before the proof still refreshes")
	}
	if out, err := h.attempt(); err == nil {
		t.Errorf("the provider account signs in to the owner's account: %v", userOf(out))
	}
	after, _ := g.Repos().Users.Get(h.ctx, victim.ID)
	if after.EmailVerifiedAt == nil {
		t.Error("the reset proved the mailbox: the account is verified")
	}
	if code, body := h.post("/auth/login", map[string]any{"email": "victim@example.com", "password": victimPassword}); code != 200 {
		t.Fatalf("the owner signs in with the new password: %d %v", code, body["error"])
	}
}
