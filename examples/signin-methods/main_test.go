package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"

	"github.com/univeros/polaris.go/plugins/messaging"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// TestSignInMethods boots the example with a memory mail channel and walks the README: a magic
// link, an email code, a guest converted on sign-up, a username sign-in and the email MFA gate.
func TestSignInMethods(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewUnstartedServer(nil)
	base := "http://" + srv.Listener.Addr().String()
	for _, name := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_ISSUER", "OIDC_ISSUER"} {
		t.Setenv(name, "")
	}
	if err := devEnv(base); err != nil {
		t.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.DB().Close() })
	mail := messaging.NewMemory("mail", "email")
	h, err := newServer(ctx, db, base, mail)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.Start()
	t.Cleanup(srv.Close)
	c := client{t: t, base: base}
	lastVar := func(name string) string {
		msgs := mail.Messages()
		if len(msgs) == 0 {
			t.Fatal("no mail sent")
		}
		return fmt.Sprint(msgs[len(msgs)-1].Vars[name])
	}

	// Magic link: send, open (302 to the landing page with a code), exchange.
	c.do("POST", "/magic-link/send", "", map[string]any{"email": "ada@example.com"}, http.StatusAccepted)
	res, err := c.noRedirect().Get(lastVar("link"))
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	landing, err := url.Parse(res.Header.Get("Location"))
	if err != nil || landing.Path != "/signed-in" {
		t.Fatalf("magic link: %d %q", res.StatusCode, res.Header.Get("Location"))
	}
	ada := c.do("POST", "/magic-link/exchange", "", map[string]any{"code": landing.Query().Get("code")}, http.StatusOK)
	if ada["user"].(map[string]any)["email"] != "ada@example.com" {
		t.Fatalf("magic link signed in %v", ada["user"])
	}

	// Email code.
	c.do("POST", "/email-otp/send", "", map[string]any{"email": "bob@example.com"}, http.StatusAccepted)
	c.do("POST", "/email-otp/verify", "", map[string]any{"email": "bob@example.com", "code": lastVar("code")}, http.StatusOK)

	// A guest signs up with a password and is converted.
	guest := c.do("POST", "/anonymous/sign-in", "", nil, http.StatusCreated)["access_token"].(string)
	const pw = "correct horse battery staple"
	c.do("POST", "/auth/register", "", map[string]any{"email": "carol@example.com", "password": pw}, http.StatusAccepted)
	c.do("POST", "/auth/email/verify", "", map[string]any{"token": lastVar("token")}, http.StatusOK)
	carol := c.do("POST", "/auth/login", "", map[string]any{"email": "carol@example.com", "password": pw}, http.StatusOK)["access_token"].(string)
	converted := c.do("POST", "/anonymous/convert", guest, map[string]any{"access_token": carol}, http.StatusOK)
	if converted["status"] != "converted" {
		t.Fatalf("convert: %v", converted)
	}

	// Username sign-in, case-insensitive.
	c.do("PATCH", "/username", carol, map[string]any{"username": "Carol_C"}, http.StatusOK)
	c.do("POST", "/username/sign-in", "", map[string]any{"username": "carol_c", "password": pw}, http.StatusOK)

	// Email MFA: enrol, confirm; the next password sign-in stops at the gate.
	factor := c.do("POST", "/auth/mfa/email/enroll", carol, map[string]any{}, http.StatusOK)["factor_id"].(string)
	c.do("POST", "/auth/mfa/email/confirm", carol, map[string]any{"factor_id": factor, "code": lastVar("code")}, http.StatusOK)
	gate := c.do("POST", "/auth/login", "", map[string]any{"email": "carol@example.com", "password": pw}, http.StatusOK)
	if gate["mfa_required"] != true {
		t.Fatalf("login after MFA enrolment: %v", gate)
	}
	ticket := gate["mfa_token"].(string)
	c.do("POST", "/auth/mfa/challenge", ticket, map[string]any{"factor_id": factor}, http.StatusOK)
	c.do("POST", "/auth/mfa/verify", ticket, map[string]any{"factor_id": factor, "code": lastVar("code")}, http.StatusOK)
}

type client struct {
	t    *testing.T
	base string
}

func (c client) noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// do sends a JSON request, fails the test on another status, and answers the envelope's data.
func (c client) do(method, path, bearer string, body any, want int) map[string]any {
	c.t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(raw))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Data map[string]any `json:"data"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	if res.StatusCode != want {
		c.t.Fatalf("%s %s: %d, want %d (%v)", method, path, res.StatusCode, want, out.Data)
	}
	return out.Data
}
