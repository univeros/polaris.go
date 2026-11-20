// Package storetest is the store.Adapter conformance suite (port of PHP AdapterConformanceTests):
// every criteria form, ordering, paging, Increment, transactions with savepoints, duplicate keys
// and concurrent use, over core's tables. An adapter passes it to be a drop-in store.
package storetest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
)

// Installer is implemented by adapters whose tables must be created before use, such as
// *sqlstore.Store. Run drops and recreates core's tables on such an adapter before each test.
type Installer interface {
	DropSchema(ctx context.Context, models []schema.Model) error
	CreateSchema(ctx context.Context, models []schema.Model) error
}

// Run runs the conformance suite. newAdapter is called once per subtest and must return an adapter
// whose state no other subtest sees, or an Installer (its tables are dropped and recreated).
func Run(t *testing.T, newAdapter func(t *testing.T) store.Adapter) {
	t.Helper()
	tests := []struct {
		name string
		fn   func(t *testing.T, a store.Adapter)
	}{
		{"InsertReadsBackTypedValues", testInsertReadsBackTypedValues},
		{"UpdateWritesColumnsAndDeleteRemoves", testUpdateWritesColumnsAndDeleteRemoves},
		{"CriteriaForms", testCriteriaForms},
		{"OrderLimitOffset", testOrderLimitOffset},
		{"ConditionalUpdateWithIncrementIsCompareAndSwap", testConditionalUpdateWithIncrement},
		{"TransactionCommits", testTransactionCommits},
		{"TransactionRollsBackAndReturnsTheError", testTransactionRollsBack},
		{"NestedTransactionRollsBackOnlyTheSavepoint", testNestedTransaction},
		{"CompositeKeyRoundTrip", testCompositeKeyRoundTrip},
		{"DuplicateKeyWrapsErrDuplicate", testDuplicateKey},
		{"ConcurrentWrites", testConcurrentWrites},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := newAdapter(t)
			if in, ok := a.(Installer); ok {
				install(t, in)
			}
			tc.fn(t, a)
		})
	}
}

func install(t *testing.T, in Installer) {
	t.Helper()
	ctx := context.Background()
	core := schema.Core()
	if err := in.DropSchema(ctx, core); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if err := in.CreateSchema(ctx, core); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		if err := in.DropSchema(context.Background(), core); err != nil {
			t.Errorf("drop schema: %v", err)
		}
	})
}

var base = time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)

func newID() string { return uuid.Must(uuid.NewV7()).String() }

func user(email string) store.Row {
	return store.Row{
		"id": newID(), "email": email, "email_verified_at": nil, "password_hash": nil, "display_name": nil,
		"status": "active", "mfa_enforced": false, "failed_login_count": 0, "failed_login_at": nil,
		"locked_until": nil, "last_login_at": nil, "created_at": base, "updated_at": base,
	}
}

func refreshToken(userID string, createdAt time.Time, suffix string) store.Row {
	return store.Row{
		"id": newID(), "user_id": userID, "organization_id": nil, "family_id": newID(), "parent_id": nil,
		"token_hash": strings.Repeat(suffix, 64), "user_agent": nil, "ip": nil, "mfa": false, "amr": nil,
		"auth_time": nil, "expires_at": createdAt.AddDate(0, 0, 30), "last_used_at": nil, "revoked_at": nil,
		"revoked_reason": nil, "created_at": createdAt,
	}
}

func with(r store.Row, kv ...any) store.Row {
	out := store.Row{}
	for k, v := range r {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		out[kv[i].(string)] = kv[i+1]
	}
	return out
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func insert(t *testing.T, a store.Adapter, table string, rows ...store.Row) {
	t.Helper()
	for _, r := range rows {
		must(t, a.Insert(context.Background(), table, r))
	}
}

func count(t *testing.T, a store.Adapter, table string, c store.Criteria) int64 {
	t.Helper()
	n, err := a.Count(context.Background(), table, c)
	must(t, err)
	return n
}

func findMany(t *testing.T, a store.Adapter, table string, c store.Criteria, q store.Query) []store.Row {
	t.Helper()
	rows, err := a.FindMany(context.Background(), table, c, q)
	must(t, err)
	return rows
}

func strs(rows []store.Row, col string) string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.String(col)
	}
	return strings.Join(out, ",")
}

func testInsertReadsBackTypedValues(t *testing.T, a store.Adapter) {
	ctx := context.Background()
	u := with(user("ada@example.com"), "failed_login_count", 2, "mfa_enforced", true, "failed_login_at", base)
	insert(t, a, "auth_users", u)

	found, err := a.FindOne(ctx, "auth_users", store.Criteria{"email": "ada@example.com"})
	must(t, err)
	if found == nil {
		t.Fatal("inserted user not found")
	}
	at, _ := found.Time("failed_login_at")
	got := fmt.Sprintf("%s %s %t %d %v %s", found.String("id"), found.String("status"), found.Bool("mfa_enforced"),
		found.Int("failed_login_count"), found.StringPtr("password_hash"), at.Format(store.TimeLayout))
	if want := fmt.Sprintf("%s active true 2 <nil> 2026-06-07 10:00:00", u["id"]); got != want {
		t.Errorf("read back %q, want %q (row %v)", got, want, found)
	}
	byID, err := a.FindOne(ctx, "auth_users", store.Criteria{"id": u["id"]})
	must(t, err)
	if byID == nil || byID.String("email") != "ada@example.com" {
		t.Errorf("find by id = %v", byID)
	}
	if all := findMany(t, a, "auth_users", nil, store.Query{}); len(all) != 1 {
		t.Errorf("all users = %d, want 1", len(all))
	}
	missing, err := a.FindOne(ctx, "auth_users", store.Criteria{"email": "missing@example.com"})
	if err != nil || missing != nil {
		t.Errorf("missing user = %v, %v; want nil, nil", missing, err)
	}
}

func testUpdateWritesColumnsAndDeleteRemoves(t *testing.T, a store.Adapter) {
	ctx := context.Background()
	u := user("two@example.com")
	other := user("other@example.com")
	insert(t, a, "auth_users", u, other)

	n, err := a.Update(ctx, "auth_users", store.Criteria{"id": u["id"]}, store.Data{"display_name": "Two", "status": "locked"})
	must(t, err)
	if n != 1 {
		t.Errorf("updated %d rows, want 1", n)
	}
	reloaded, err := a.FindOne(ctx, "auth_users", store.Criteria{"id": u["id"]})
	must(t, err)
	if reloaded.String("display_name") != "Two" || reloaded.String("status") != "locked" || reloaded.String("email") != "two@example.com" {
		t.Errorf("reloaded = %v", reloaded)
	}
	if o, _ := a.FindOne(ctx, "auth_users", store.Criteria{"id": other["id"]}); o.String("status") != "active" {
		t.Error("update touched a row outside its criteria")
	}

	n, err = a.Delete(ctx, "auth_users", store.Criteria{"id": u["id"]})
	must(t, err)
	if n != 1 || count(t, a, "auth_users", nil) != 1 {
		t.Errorf("deleted %d, left %d; want 1, 1", n, count(t, a, "auth_users", nil))
	}
	n, err = a.Delete(ctx, "auth_users", nil)
	must(t, err)
	if n != 1 || count(t, a, "auth_users", nil) != 0 {
		t.Errorf("delete all removed %d", n)
	}
}

func testCriteriaForms(t *testing.T, a store.Adapter) {
	userID := newID()
	live := refreshToken(userID, base, "a")
	revoked := with(refreshToken(userID, base, "b"), "revoked_at", base, "auth_time", 5)
	other := with(refreshToken(newID(), base.Add(time.Hour), "c"), "auth_time", 9)
	insert(t, a, "auth_refresh_tokens", live, revoked, other)

	half := base.Add(30 * time.Minute)
	cases := []struct {
		name string
		c    store.Criteria
		want int
	}{
		{"equality", store.Criteria{"user_id": userID}, 2},
		{"equality and IS NULL", store.Criteria{"user_id": userID, "revoked_at": nil}, 1},
		{"IN []any", store.Criteria{"token_hash": []any{live["token_hash"], other["token_hash"]}}, 2},
		{"IN []string", store.Criteria{"token_hash": []string{live.String("token_hash")}}, 1},
		{"IN []int64", store.Criteria{"auth_time": []int64{5, 9, 11}}, 2},
		{"empty IN matches nothing", store.Criteria{"token_hash": []string{}}, 0},
		{"not null", store.Criteria{"revoked_at": store.NotNull()}, 1},
		{"lt time", store.Criteria{"created_at": store.Lt(half)}, 2},
		{"gte time", store.Criteria{"created_at": store.Gte(half)}, 1},
		{"lte time", store.Criteria{"created_at": store.Lte(base)}, 2},
		{"gt int", store.Criteria{"auth_time": store.Gt(5)}, 1},
		{"ne", store.Criteria{"user_id": store.Ne(userID)}, 1},
		{"bool", store.Criteria{"mfa": false}, 3},
	}
	for _, tc := range cases {
		if got := findMany(t, a, "auth_refresh_tokens", tc.c, store.Query{}); len(got) != tc.want {
			t.Errorf("%s: %d rows, want %d", tc.name, len(got), tc.want)
		}
		if got := count(t, a, "auth_refresh_tokens", tc.c); got != int64(tc.want) {
			t.Errorf("%s: count %d, want %d", tc.name, got, tc.want)
		}
	}
	ordered := findMany(t, a, "auth_refresh_tokens", store.Criteria{"user_id": userID},
		store.Query{OrderBy: []store.Order{{Column: "token_hash", Desc: true}}, Limit: 1})
	if len(ordered) != 1 || ordered[0].String("token_hash") != revoked["token_hash"] {
		t.Errorf("ordered desc limit 1 = %s", strs(ordered, "token_hash"))
	}
}

func testOrderLimitOffset(t *testing.T, a store.Adapter) {
	for i, email := range []string{"c@x.io", "a@x.io", "d@x.io", "b@x.io"} {
		insert(t, a, "auth_users", with(user(email), "failed_login_count", i%2))
	}
	order := []store.Order{{Column: "failed_login_count", Desc: true}, {Column: "email"}}
	cases := []struct {
		q    store.Query
		want string
	}{
		{store.Query{OrderBy: order}, "a@x.io,b@x.io,c@x.io,d@x.io"},
		{store.Query{OrderBy: []store.Order{{Column: "email"}}, Limit: 2}, "a@x.io,b@x.io"},
		{store.Query{OrderBy: []store.Order{{Column: "email"}}, Offset: 1}, "b@x.io,c@x.io,d@x.io"},
		{store.Query{OrderBy: []store.Order{{Column: "email", Desc: true}}, Limit: 2, Offset: 1}, "c@x.io,b@x.io"},
	}
	for _, tc := range cases {
		if got := strs(findMany(t, a, "auth_users", nil, tc.q), "email"); got != tc.want {
			t.Errorf("%+v = %s, want %s", tc.q, got, tc.want)
		}
	}
}

func testConditionalUpdateWithIncrement(t *testing.T, a store.Adapter) {
	ctx := context.Background()
	id := newID()
	insert(t, a, "auth_otp_challenges", store.Row{
		"id": id, "user_id": newID(), "factor_id": nil, "purpose": "login", "channel": "email",
		"code_hash": strings.Repeat("c", 64), "destination": nil, "attempts": 0, "max_attempts": 2,
		"expires_at": base.Add(10 * time.Minute), "consumed_at": nil, "ip": nil, "created_at": base,
	})
	spend := func() int64 {
		n, err := a.Update(ctx, "auth_otp_challenges", store.Criteria{"id": id, "attempts": store.Lt(2)}, store.Data{"attempts": store.Increment{By: 1}})
		must(t, err)
		return n
	}
	if a, b, c := spend(), spend(), spend(); a != 1 || b != 1 || c != 0 {
		t.Errorf("spends = %d %d %d, want 1 1 0: the budget is enforced by the database", a, b, c)
	}
	row, err := a.FindOne(ctx, "auth_otp_challenges", store.Criteria{"id": id})
	must(t, err)
	if row.Int("attempts") != 2 {
		t.Errorf("attempts = %v, want 2", row["attempts"])
	}
	claim := func() int64 {
		n, err := a.Update(ctx, "auth_otp_challenges", store.Criteria{"id": id, "consumed_at": nil}, store.Data{"consumed_at": base.Add(5 * time.Minute)})
		must(t, err)
		return n
	}
	if first, second := claim(), claim(); first != 1 || second != 0 {
		t.Errorf("claims = %d %d, want 1 0: a second consumer loses the race", first, second)
	}
}

func testTransactionCommits(t *testing.T, a store.Adapter) {
	err := a.Tx(context.Background(), func(ctx context.Context) error {
		if err := a.Insert(ctx, "auth_users", user("commit@example.com")); err != nil {
			return err
		}
		if n, err := a.Count(ctx, "auth_users", nil); err != nil || n != 1 {
			return fmt.Errorf("inside the transaction: count %d, %v", n, err)
		}
		return nil
	})
	must(t, err)
	if n := count(t, a, "auth_users", nil); n != 1 {
		t.Errorf("after commit: %d users, want 1", n)
	}
}

func testTransactionRollsBack(t *testing.T, a store.Adapter) {
	abort := errors.New("abort")
	err := a.Tx(context.Background(), func(ctx context.Context) error {
		if err := a.Insert(ctx, "auth_users", user("rollback@example.com")); err != nil {
			return err
		}
		return abort
	})
	if err != abort {
		t.Errorf("Tx returned %v, want the callback's error unchanged", err)
	}
	if n := count(t, a, "auth_users", nil); n != 0 {
		t.Errorf("after rollback: %d users, want 0", n)
	}
}

func testNestedTransaction(t *testing.T, a store.Adapter) {
	inner := errors.New("inner")
	err := a.Tx(context.Background(), func(ctx context.Context) error {
		if err := a.Insert(ctx, "auth_users", user("outer@example.com")); err != nil {
			return err
		}
		if err := a.Tx(ctx, func(ctx context.Context) error {
			if err := a.Insert(ctx, "auth_users", user("inner@example.com")); err != nil {
				return err
			}
			return inner
		}); err != inner {
			return fmt.Errorf("inner Tx returned %v", err)
		}
		return a.Tx(ctx, func(ctx context.Context) error {
			return a.Insert(ctx, "auth_users", user("second@example.com"))
		})
	})
	must(t, err)
	if got := strs(findMany(t, a, "auth_users", nil, store.Query{OrderBy: []store.Order{{Column: "email"}}}), "email"); got != "outer@example.com,second@example.com" {
		t.Errorf("users = %s; only the inner savepoint rolls back", got)
	}
}

func testCompositeKeyRoundTrip(t *testing.T, a store.Adapter) {
	ctx := context.Background()
	roleID, permID := newID(), newID()
	insert(t, a, "auth_roles", store.Row{
		"id": roleID, "organization_id": nil, "name": "Owner", "slug": "owner", "description": nil,
		"is_system": false, "created_at": base, "updated_at": base,
	})
	insert(t, a, "auth_permissions", store.Row{"id": permID, "key": "org.manage", "description": "Manage the organization"})
	insert(t, a, "auth_role_permissions", store.Row{"role_id": roleID, "permission_id": permID})

	found := findMany(t, a, "auth_role_permissions", store.Criteria{"role_id": roleID}, store.Query{})
	if len(found) != 1 || found[0].String("permission_id") != permID {
		t.Fatalf("links = %v", found)
	}
	n, err := a.Delete(ctx, "auth_role_permissions", store.Criteria{"role_id": roleID, "permission_id": permID})
	must(t, err)
	if n != 1 || len(findMany(t, a, "auth_role_permissions", store.Criteria{"role_id": roleID}, store.Query{})) != 0 {
		t.Errorf("link not removed")
	}
}

func testDuplicateKey(t *testing.T, a store.Adapter) {
	ctx := context.Background()
	first := user("dup@example.com")
	second := user("second@example.com")
	insert(t, a, "auth_users", first, second)

	writes := map[string]func() error{
		"insert a duplicate email": func() error { return a.Insert(ctx, "auth_users", user("dup@example.com")) },
		"insert a duplicate primary key": func() error {
			return a.Insert(ctx, "auth_users", with(user("third@example.com"), "id", first["id"]))
		},
		"update to a duplicate email": func() error {
			_, err := a.Update(ctx, "auth_users", store.Criteria{"id": second["id"]}, store.Data{"email": "dup@example.com"})
			return err
		},
	}
	for name, write := range writes {
		if err := write(); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("%s: %v, want ErrDuplicate", name, err)
		}
	}
	if n := count(t, a, "auth_users", store.Criteria{"email": "dup@example.com"}); n != 1 {
		t.Errorf("%d rows hold the duplicate email, want 1", n)
	}
	// NULLs never collide in a unique index.
	insert(t, a, "auth_roles",
		store.Row{"id": newID(), "organization_id": nil, "name": "A", "slug": "same", "description": nil, "is_system": true, "created_at": base, "updated_at": base},
		store.Row{"id": newID(), "organization_id": nil, "name": "B", "slug": "same", "description": nil, "is_system": true, "created_at": base, "updated_at": base},
	)
}

func testConcurrentWrites(t *testing.T, a store.Adapter) {
	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- a.Tx(context.Background(), func(ctx context.Context) error {
				return a.Insert(ctx, "auth_users", user(fmt.Sprintf("u%d@example.com", i)))
			})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		must(t, err)
	}
	if n := count(t, a, "auth_users", nil); n != writers {
		t.Errorf("%d users after concurrent inserts, want %d", n, writers)
	}
}
