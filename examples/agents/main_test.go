package main

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// TestDemo boots the example on a real listener (capability Locations and request JWT audiences are
// absolute URLs) and plays the whole story the README walks through.
func TestDemo(t *testing.T) {
	ctx := context.Background()
	srv := httptest.NewUnstartedServer(nil)
	baseURL := "http://" + srv.Listener.Addr().String()
	for _, name := range []string{"APP_KEY", "AUTH_JWT_PRIVATE_KEY", "AUTH_JWT_PUBLIC_KEY", "AUTH_ISSUER"} {
		t.Setenv(name, "")
	}
	if err := devEnv(baseURL); err != nil {
		t.Fatal(err)
	}
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "polaris.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.DB().Close() })
	h, p, err := newServer(ctx, db, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = h
	srv.Start()
	t.Cleanup(srv.Close)

	var out strings.Builder
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
