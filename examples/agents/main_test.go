package main

import (
	"context"
	"encoding/json"
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

// TestDemo boots the example on a real listener (capability Locations and request JWT audiences are
// absolute URLs) and plays the whole story the README walks through,
// in both discovery modes: the Go agent SDK works in each.
func TestDemo(t *testing.T) {
	for name, protocol := range map[string]bool{"Polaris": false, "Agent Auth Protocol": true} {
		t.Run(name, func(t *testing.T) { playDemo(t, protocol) })
	}
}

func playDemo(t *testing.T, protocol bool) {
	ctx := context.Background()
	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()
	for _, name := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_ISSUER"} {
		t.Setenv(name, "")
	}
	t.Setenv(polaris.EnvDev, "1") // DevEnv generates the throwaway secrets
	if err := polaris.DevEnv(baseURL); err != nil {
		t.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	h, p, err := newServer(ctx, db, baseURL, protocol, cheapHashing)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.Start()
	t.Cleanup(srv.Close)

	var out strings.Builder
	resp, err := http.Get(baseURL + "/.well-known/agent-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var document struct {
		Endpoints map[string]string `json:"endpoints"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		t.Fatal(err)
	}
	if _, ok := document.Endpoints["introspect"]; ok != protocol {
		t.Fatalf("whose document it is: %v", document.Endpoints)
	}
	if err := runDemo(ctx, p, baseURL, false, &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{
		"grant invoices.list: active",
		"grant invoices.refund: pending",
		"grant invoices.refund: active",
		"refund 60 -> 200",
		"refund 500 -> 403 constraint_violated",
		"refund 60 -> 403 budget_exhausted",
		"receipt #2 invoices.refund success: valid=true",
		"The agent is revoked",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
}

// cheapHashing swaps the production Argon2id for polaristest.Hasher: the same hash format, and a
// -race run that hashes in milliseconds instead of seconds.
func cheapHashing(c *polaris.Config) { c.Hasher = polaristest.Hasher() }
