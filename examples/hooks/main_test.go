package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// TestHooks drives what the README walks through: the host signup in one transaction and its
// rollback, the profile row the hooks keep, the claim, the request id and Prune.
func TestHooks(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_ISSUER"} {
		t.Setenv(name, "")
	}
	t.Setenv(polaris.EnvDev, "1") // DevEnv generates the throwaway secrets
	if err := polaris.DevEnv("http://localhost"); err != nil {
		t.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h, p, err := newServer(ctx, db, cheapHashing)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	plan := func(userID string) string {
		var plan string
		_ = db.DB().QueryRowContext(ctx, "SELECT plan FROM profiles WHERE user_id = ?", userID).Scan(&plan)
		return plan
	}
	signup := func(email, plan string) (int, map[string]any) {
		company := strings.Split(email, "@")[0] + " Inc"
		body := `{"email":"` + email + `","password":"correct horse battery staple","company":"` + company + `","plan":"` + plan + `"}`
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/api/signup", strings.NewReader(body))
		req.Header.Set("X-Request-Id", "test-1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.Header.Get("X-Request-Id") != "test-1" {
			t.Errorf("request id not echoed: %q", resp.Header.Get("X-Request-Id"))
		}
		out := map[string]any{}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	// The host signup commits the account, its profile with the plan and the organization.
	status, out := signup("ada@example.com", "pro")
	if status != http.StatusCreated || out["can_delete_org"] != true {
		t.Fatalf("signup: %d %v", status, out)
	}
	if got := plan(out["user_id"].(string)); got != "pro" {
		t.Errorf("ada's plan = %q", got)
	}

	// A plan the profiles table refuses rolls back the account and OnUserCreated's row.
	if status, out := signup("carol@example.com", "enterprise"); status != http.StatusUnprocessableEntity {
		t.Fatalf("rollback signup: %d %v", status, out)
	}
	if _, err := p.Users().ByEmail(ctx, "carol@example.com"); !errors.Is(err, polaris.ErrNotFound) {
		t.Errorf("carol after the rollback: %v", err)
	}
	var n int
	if err := db.DB().QueryRowContext(ctx, "SELECT COUNT(*) FROM profiles").Scan(&n); err != nil || n != 1 {
		t.Errorf("profiles after the rollback: %d %v", n, err)
	}

	// Every account gets a profile (OnUserCreated), its plan is in the token (Claims), and
	// erasing the account removes it (OnUserDeleted).
	bob, err := p.Users().Create(ctx, polaris.NewUser{Email: "bob@example.com", EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := p.Sessions().Issue(ctx, polaris.SignIn{UserID: bob.ID})
	if err != nil {
		t.Fatal(err)
	}
	if status, out := getProfile(t, srv.URL, tokens.AccessToken); status != http.StatusOK || out["plan"] != "free" || out["token_app_plan"] != "free" {
		t.Errorf("bob's profile: %d %v", status, out)
	}
	if err := p.Users().Delete(ctx, bob.ID); err != nil {
		t.Fatal(err)
	}
	if status, _ := getProfile(t, srv.URL, tokens.AccessToken); status != http.StatusNotFound || plan(bob.ID) != "" {
		t.Errorf("bob's profile after the erase: %d", status)
	}

	if _, err := p.Prune(ctx); err != nil {
		t.Errorf("prune: %v", err)
	}
}

func getProfile(t *testing.T, baseURL, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/api/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// cheapHashing swaps the production Argon2id for polaristest.Hasher: the same hash format, and a
// -race run that hashes in milliseconds instead of seconds.
func cheapHashing(c *polaris.Config) { c.Hasher = polaristest.Hasher() }
