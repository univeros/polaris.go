package sqlstore_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// The host's own onboarding in one transaction: the account (with the profile row OnUserCreated
// writes through Conn), the organization and the host's own update. The events, and the mail
// their listeners send, wait for the commit; a rollback leaves no account, no row and no event.
func ExampleStore_Tx() {
	ctx := context.Background()
	dir, _ := os.MkdirTemp("", "polaris")
	defer os.RemoveAll(dir)
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(dir, "app.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		panic(err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Conn(ctx).ExecContext(ctx, "CREATE TABLE profiles (user_id TEXT PRIMARY KEY, plan TEXT NOT NULL DEFAULT 'free')"); err != nil {
		panic(err)
	}
	p := newPolaris(db, polaris.Hooks{
		OnUserCreated: func(ctx context.Context, u polaris.User) error { // ctx carries the transaction
			_, err := db.Conn(ctx).ExecContext(ctx, "INSERT INTO profiles (user_id) VALUES (?)", u.ID) // $1 on PostgreSQL
			return err
		},
	}, func(_ context.Context, e event.Event) { fmt.Println("event", e.EventName()) })

	signup := func(email, plan string) error {
		return db.Tx(ctx, func(ctx context.Context) error {
			u, err := p.Users().Create(ctx, polaris.NewUser{Email: email, EmailVerified: true})
			if err != nil {
				return err
			}
			if _, err := p.Orgs().Create(ctx, u.ID, email+" team", ""); err != nil {
				return err
			}
			if plan != "free" && plan != "pro" {
				return errors.New("no such plan") // rolls back everything above
			}
			_, err = db.Conn(ctx).ExecContext(ctx, "UPDATE profiles SET plan = ? WHERE user_id = ?", plan, u.ID)
			fmt.Println("inside the transaction: no event yet")
			return err
		})
	}
	fmt.Println(signup("ada@example.com", "pro"))
	fmt.Println(signup("bob@example.com", "gold"))
	var n int
	_ = db.Conn(ctx).QueryRowContext(ctx, "SELECT COUNT(*) FROM profiles").Scan(&n)
	fmt.Println(n, "profile")
	// Output:
	// inside the transaction: no event yet
	// event user.registered
	// event org.created
	// <nil>
	// no such plan
	// 1 profile
}

// AfterCommit for the host's own side effects: they run once the transaction commits, never
// after a rollback.
func ExampleStore_AfterCommit() {
	ctx := context.Background()
	dir, _ := os.MkdirTemp("", "polaris")
	defer os.RemoveAll(dir)
	db, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(dir, "app.db"))
	if err != nil {
		panic(err)
	}
	defer func() { _ = db.Close() }()

	_ = db.Tx(ctx, func(ctx context.Context) error {
		db.AfterCommit(ctx, func() { fmt.Println("committed: send the welcome email") })
		return nil
	})
	_ = db.Tx(ctx, func(ctx context.Context) error {
		db.AfterCommit(ctx, func() { fmt.Println("never printed") })
		return errors.New("rolled back")
	})
	fmt.Println(db.AfterCommit(ctx, func() {})) // no transaction: nothing queued
	// Output:
	// committed: send the welcome email
	// false
}

// newPolaris boots Polaris over db with test keys and the cheap test hasher; a host reads its
// keys with polaris.FromEnv.
func newPolaris(db *sqlstore.Store, hooks polaris.Hooks, listener event.Listener) *polaris.Polaris {
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://auth.example.com"
	p, err := polaris.New(polaris.Config{
		Secrets:   config.Secrets{AppKey: "an-application-key-of-32-bytes!!", JWTPrivateKey: private, JWTPublicKey: public},
		Auth:      auth,
		DB:        db,
		Hasher:    polaristest.Hasher(),
		Hooks:     hooks,
		Listeners: []event.Listener{listener},
	})
	if err != nil {
		panic(err)
	}
	if _, err := p.Migrate(context.Background()); err != nil {
		panic(err)
	}
	return p
}
