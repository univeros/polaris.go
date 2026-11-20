package maintenance

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/sqlstore"
)

var ctx = context.Background()

func at(s string) time.Time {
	t, err := time.Parse(time.DateTime, s)
	if err != nil {
		panic(err)
	}
	return t
}

var now = at("2026-06-10 12:00:00")

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func backends(t *testing.T, fn func(t *testing.T, db store.Adapter)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) { fn(t, memstore.New(schema.Core()...)) })
	t.Run("sqlite", func(t *testing.T) {
		s, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "p.db"))
		must(t, err)
		t.Cleanup(func() { _ = s.DB().Close() })
		must(t, s.CreateSchema(ctx, schema.Core()))
		fn(t, s)
	})
}

func timeOrNil(s string) any {
	if s == "" {
		return nil
	}
	return at(s)
}

func insert(t *testing.T, db store.Adapter, table string, row store.Row) string {
	t.Helper()
	id := repository.NewID()
	row["id"] = id
	must(t, db.Insert(ctx, table, row))
	return id
}

func seedOTP(t *testing.T, db store.Adapter, consumedAt, expiresAt string) string {
	return insert(t, db, "auth_otp_challenges", store.Row{
		"user_id": repository.NewID(), "purpose": "login", "channel": "email", "attempts": 0,
		"consumed_at": timeOrNil(consumedAt), "expires_at": at(expiresAt), "created_at": at("2026-06-10 10:00:00"),
	})
}

func seedChallenge(t *testing.T, db store.Adapter, table, expiresAt, consumedAt string) string {
	return insert(t, db, table, store.Row{
		"user_id": repository.NewID(), "email": "someone@example.com", "token_hash": repository.NewID(),
		"consumed_at": timeOrNil(consumedAt), "expires_at": at(expiresAt), "created_at": at("2026-06-10 10:00:00"),
	})
}

func seedRefresh(t *testing.T, db store.Adapter, expiresAt, revokedAt string) string {
	var reason any
	if revokedAt != "" {
		reason = "logout"
	}
	return insert(t, db, "auth_refresh_tokens", store.Row{
		"user_id": repository.NewID(), "family_id": repository.NewID(), "token_hash": repository.NewID(),
		"revoked_at": timeOrNil(revokedAt), "revoked_reason": reason, "expires_at": at(expiresAt),
		"created_at": at("2026-06-01 00:00:00"),
	})
}

func ids(t *testing.T, db store.Adapter, table string) []string {
	t.Helper()
	rows, err := db.FindMany(ctx, table, nil, store.Query{})
	must(t, err)
	out := []string{}
	for _, r := range rows {
		out = append(out, r["id"].(string))
	}
	slices.Sort(out)
	return out
}

func sorted(s ...string) []string { slices.Sort(s); return s }

// Port of PruneExpiredServiceTest::testPrunesDeadRowsAndKeepsLiveOnes.
func TestPrunesDeadRowsAndKeepsLiveOnes(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		seedOTP(t, db, "2026-06-10 12:00:00", "2026-06-10 13:00:00")
		seedOTP(t, db, "", "2026-06-10 11:00:00")
		live := seedOTP(t, db, "", "2026-06-10 13:00:00")

		seedChallenge(t, db, "auth_email_verifications", "2026-06-09 00:00:00", "")
		seedChallenge(t, db, "auth_email_verifications", "2026-06-11 00:00:00", "2026-06-10 12:00:00")
		liveVerification := seedChallenge(t, db, "auth_email_verifications", "2026-06-11 00:00:00", "")
		seedChallenge(t, db, "auth_password_resets", "2026-06-11 00:00:00", "2026-06-10 12:00:00")

		// Long expired (pruned), revoked long ago but unexpired (pruned), expired within grace,
		// freshly revoked and live (kept).
		seedRefresh(t, db, "2026-06-01 00:00:00", "")
		seedRefresh(t, db, "2027-01-01 00:00:00", "2026-05-20 00:00:00")
		inGrace := seedRefresh(t, db, "2026-06-08 00:00:00", "")
		freshRevoked := seedRefresh(t, db, "2027-01-01 00:00:00", "2026-06-09 00:00:00")
		liveToken := seedRefresh(t, db, "2026-06-20 00:00:00", "")

		insert(t, db, "auth_audit_log", store.Row{"event": "user.logged_in", "metadata": "{}", "created_at": at("2020-01-01 00:00:00")})

		deleted, err := PruneExpired(ctx, db, now, 0)
		must(t, err)
		want := map[string]int64{"auth_otp_challenges": 2, "auth_email_verifications": 2, "auth_password_resets": 1, "auth_refresh_tokens": 2}
		if len(deleted) != len(want) {
			t.Errorf("deleted = %v", deleted)
		}
		for table, n := range want {
			if deleted[table] != n {
				t.Errorf("deleted[%s] = %d; want %d", table, deleted[table], n)
			}
		}
		for table, kept := range map[string][]string{
			"auth_otp_challenges":      {live},
			"auth_email_verifications": {liveVerification},
			"auth_password_resets":     {},
			"auth_refresh_tokens":      sorted(inGrace, freshRevoked, liveToken),
		} {
			if got := ids(t, db, table); !slices.Equal(got, kept) {
				t.Errorf("%s = %v; want %v", table, got, kept)
			}
		}
		if len(ids(t, db, "auth_audit_log")) != 1 {
			t.Error("audit rows are never pruned")
		}
	})
}

// Port of testASecondRunIsANoOp.
func TestASecondRunIsANoOp(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		seedOTP(t, db, "2026-06-10 12:00:00", "2026-06-10 13:00:00")
		_, err := PruneExpired(ctx, db, now, 0)
		must(t, err)
		second, err := PruneExpired(ctx, db, now, 0)
		must(t, err)
		for table, n := range second {
			if n != 0 {
				t.Errorf("second run deleted %d from %s", n, table)
			}
		}
	})
}

func TestTheRefreshGraceIsConfigurable(t *testing.T) {
	backends(t, func(t *testing.T, db store.Adapter) {
		seedRefresh(t, db, "2026-06-10 11:00:00", "")
		deleted, err := PruneExpired(ctx, db, now, 30*time.Minute)
		must(t, err)
		if deleted["auth_refresh_tokens"] != 1 {
			t.Errorf("deleted = %v", deleted)
		}
	})
}

func TestAStoreFailureNamesTheTable(t *testing.T) {
	_, err := PruneExpired(ctx, failingDeletes{memstore.New(schema.Core()...)}, now, 0)
	if err == nil || !strings.Contains(err.Error(), "auth_otp_challenges") {
		t.Fatalf("err = %v", err)
	}
}

type failingDeletes struct{ store.Adapter }

func (failingDeletes) Delete(context.Context, string, store.Criteria) (int64, error) {
	return 0, errors.New("disk full")
}
