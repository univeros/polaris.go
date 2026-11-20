package passkey

import (
	"context"
	"testing"
	"time"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/storetest"
)

// The passkey table installs on every database (on MySQL a utf8mb4 VARCHAR(1024) unique index
// exceeds the 3072-byte key limit), and credential ids that differ only in case are two credentials
// (base64url is case-sensitive; MySQL's default collation is not).
func TestCredentialIDsAreUniqueByteForByte(t *testing.T) {
	storetest.Each(t, func(t *testing.T, db store.Adapter) {
		ctx := context.Background()
		now := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)
		insert := func(id, credentialID string) error {
			return db.Insert(ctx, TablePasskeys, store.Row{
				"id": id, "user_id": "u1", "credential_id": credentialID, "public_key": "pk", "counter": 0,
				"aaguid": "00000000-0000-0000-0000-000000000000", "transports": "[]", "backup_eligible": false,
				"backed_up": false, "name": "key", "factor_id": nil, "last_used_at": nil, "created_at": now,
			})
		}
		if err := insert("p1", "AbC-_x"); err != nil {
			t.Fatal(err)
		}
		if err := insert("p2", "abc-_X"); err != nil {
			t.Fatalf("a case variant is another credential: %v", err)
		}
		if err := insert("p3", "AbC-_x"); err == nil {
			t.Fatal("the same credential id twice")
		}
		row, err := db.FindOne(ctx, TablePasskeys, store.Criteria{"credential_id": "abc-_X"})
		if err != nil || row.String("id") != "p2" {
			t.Fatalf("lookup is byte-exact: %v %v", row, err)
		}
	}, append(schema.Core(), Models()...)...)
}
