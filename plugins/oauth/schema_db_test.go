package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/storetest"
)

// A consent for one client_id URL is never found for another that differs only in case (a
// metadata document at /App must not inherit the consent given to /app).
func TestConsentsCompareClientIDsByteForByte(t *testing.T) {
	storetest.Each(t, func(t *testing.T, db store.Adapter) {
		ctx := context.Background()
		now := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)
		if err := db.Insert(ctx, TableConsents, store.Row{"id": "c1", "user_id": "u1", "client_id": "https://host.example/app",
			"organization_id": nil, "scopes": "[]", "granted_at": now, "updated_at": now}); err != nil {
			t.Fatal(err)
		}
		row, err := db.FindOne(ctx, TableConsents, store.Criteria{"user_id": "u1", "client_id": "https://host.example/App"})
		if err != nil || row != nil {
			t.Fatalf("consent found for a case variant: %v %v", row, err)
		}
	}, append(schema.Core(), models()...)...)
}
