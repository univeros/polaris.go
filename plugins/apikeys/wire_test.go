package apikeys_test

import (
	"context"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/apikeys"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
)

// Each field is read as the JSON type it is: a name is a string, permissions a list, metadata
// and rate_limit objects. A number or boolean is not a name, an object is not a list, [] is not {}.
func TestInputIsReadAsItsJSONType(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), apikeys.New(apikeys.Config{})))
	f := &flow{t: t, srv: srv, c: contracttest.NewClient(t, srv.Handler(), nil)}
	_, session := f.login("ada@example.com")
	as := contracttest.Bearer(session)
	for name, body := range map[string]map[string]any{
		"name true":        {"name": true},
		"name number":      {"name": 12},
		"permissions {}":   {"name": "k", "permissions": map[string]any{}},
		"permissions {..}": {"name": "k", "permissions": map[string]any{"0": "org.read"}},
		"metadata []":      {"name": "k", "metadata": []any{}},
		"rate_limit []":    {"name": "k", "rate_limit": []any{}},
	} {
		if resp := f.c.Post("/api-keys", body, as); resp.StatusCode != 422 {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
	}
	created := data(t, f.c.Post("/api-keys", map[string]any{"name": "k", "metadata": map[string]any{}}, as))
	if at, _ := created["created_at"].(string); !strings.HasSuffix(at, "Z") {
		t.Errorf("created_at %q", at)
	}
	id, _ := created["id"].(string)
	for name, body := range map[string]map[string]any{
		"name number":    {"name": 1},
		"permissions {}": {"permissions": map[string]any{}},
		"metadata []":    {"metadata": []any{}},
	} {
		if resp := f.c.Patch("/api-keys/"+id, body, as); resp.StatusCode != 422 {
			t.Errorf("update %s: %d", name, resp.StatusCode)
		}
	}
	// A row written by an earlier release with [] for empty metadata reads as {}.
	if _, err := srv.DB.Update(context.Background(), apikeys.TableKeys, store.Criteria{"id": id}, store.Data{"metadata": "[]"}); err != nil {
		t.Fatal(err)
	}
	if m, ok := data(t, f.c.Get("/api-keys/"+id, as))["metadata"].(map[string]any); !ok || len(m) != 0 {
		t.Errorf("stored [] metadata: %v", m)
	}
}
