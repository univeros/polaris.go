package oauth_test

import (
	"context"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

// A client an operator API key creates records the key's id in created_by (as upstream); its
// event names no actor.
func TestAnOperatorKeysClientRecordsTheKeyAsCreator(t *testing.T) {
	ctx := context.Background()
	srv := boot(t, &fakeHTTP{documents: map[string]any{}}, false)
	key, secret, err := admin.Of(srv.Graph()).Keys().Create(ctx, admin.Key{Name: "ci", Role: admin.RoleOwner})
	if err != nil {
		t.Fatal(err)
	}
	c := contracttest.NewClient(t, srv.Handler(), nil)
	resp := c.Post("/admin/oauth/clients", map[string]any{"name": "Bot", "grant_types": []string{oauth.GrantClientCredentials},
		"token_endpoint_auth_method": "client_secret_post"}, contracttest.Bearer(secret))
	created, _ := contracttest.JSON(t, resp)["data"].(map[string]any)
	if resp.StatusCode != 201 {
		t.Fatalf("create: %d %v", resp.StatusCode, created)
	}
	row, err := srv.DB.FindOne(ctx, oauth.TableClients, store.Criteria{"client_id": created["client_id"]})
	if err != nil || row == nil || row.String("created_by") != key.ID {
		t.Fatalf("created_by = %v (%v); want the key id %s", row["created_by"], err, key.ID)
	}
	for _, e := range srv.Events.All() {
		if ev, ok := e.(oauth.Event); ok && ev.Name == oauth.EventClientCreated && ev.UserID != "" {
			t.Errorf("the event names actor %q; want none for an API key", ev.UserID)
		}
	}
}
