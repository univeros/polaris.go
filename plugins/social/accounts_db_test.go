package social

import (
	"context"
	"testing"
	"time"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/storetest"
)

// Two IdP subjects that differ only in case (or accent) are two accounts on every database; on
// MySQL the column is utf8mb4_bin, so neither the unique index nor the lookup folds them.
func TestSubjectsDifferingOnlyInCaseStayDistinct(t *testing.T) {
	storetest.Each(t, func(t *testing.T, db store.Adapter) {
		ctx := context.Background()
		now := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)
		insert := func(id, userID, subject string) error {
			return db.Insert(ctx, TableAccounts, store.Row{
				"id": id, "user_id": userID, "provider": "oidc", "provider_account_id": subject, "email": nil,
				"email_verified": false, "scopes": "[]", "profile": "{}", "access_token_enc": nil,
				"refresh_token_enc": nil, "expires_at": nil, "created_at": now, "updated_at": now,
			})
		}
		for i, subject := range []string{"AbC", "abc", "ábc"} {
			if err := insert(string(rune('a'+i)), string(rune('u'+i)), subject); err != nil {
				t.Fatalf("subject %q is its own account: %v", subject, err)
			}
		}
		for subject, want := range map[string]string{"AbC": "a", "abc": "b", "ábc": "c", "ABC": ""} {
			row, err := db.FindOne(ctx, TableAccounts, accountKey("oidc", subject))
			if err != nil || row.String("id") != want {
				t.Errorf("lookup of %q found %v (%v); want %q", subject, row, err, want)
			}
		}
	}, append(schema.Core(), Models()...)...)
}
