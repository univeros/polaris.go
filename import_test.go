package polaris_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris.go"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store/sqlstore"
)

// Published vectors (testdata/vectors/imported-hashes.json and argon2id.json).
var migrated = []struct{ email, password, hash string }{
	{"bcrypt@example.com", "bcrypt", "$2y$04$9xkaXv9u52gB5CSHs990Rujqpwb54f2v3nd7nRc.mRPDPsGvyU1R6"},
	{"pbkdf2@example.com", "password", "$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa17k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww"},
	{"scrypt@example.com", "pleaseletmein", "$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofI"},
}

// A migration imports a batch in the host's transaction (OnUserCreated runs for each); each user
// then signs in over HTTP with their old password, which replaces the imported hash with
// Argon2id, and signs in again against it.
func TestImportedUsersSignInAndAreRehashed(t *testing.T) {
	ctx := context.Background()
	log := &hookLog{}
	var db *sqlstore.Store
	srv := polaristest.New(t, polaristest.WithConfig(func(c *polaris.Config) {
		db = c.DB.(*sqlstore.Store)
		c.Hooks = log.hooks()
	}))

	tx, err := db.DB().BeginTx(ctx, nil)
	ok(t, err)
	for _, m := range migrated {
		_, err := srv.Users().Import(sqlstore.WithTx(ctx, tx), polaris.ImportedUser{Email: m.email, PasswordHash: m.hash, EmailVerified: true})
		ok(t, err)
	}
	ok(t, tx.Rollback())
	if _, err := srv.Users().ByEmail(ctx, migrated[0].email); !errors.Is(err, polaris.ErrNotFound) {
		t.Fatalf("after the host's rollback: %v", err)
	}

	tx, err = db.DB().BeginTx(ctx, nil)
	ok(t, err)
	created := time.Date(2019, 3, 1, 9, 30, 0, 0, time.UTC)
	for _, m := range migrated {
		_, err := srv.Users().Import(sqlstore.WithTx(ctx, tx), polaris.ImportedUser{
			Email: m.email, PasswordHash: m.hash, EmailVerified: true, CreatedAt: created,
		})
		ok(t, err)
	}
	ok(t, tx.Commit())
	if len(log.created) != 2*len(migrated) {
		t.Fatalf("OnUserCreated ran %d times", len(log.created))
	}

	c := contracttest.NewClient(t, srv.Handler(), nil)
	for _, m := range migrated {
		u, err := srv.Users().ByEmail(ctx, m.email)
		ok(t, err)
		if !u.CreatedAt.Equal(created) {
			t.Errorf("%s: created_at %v", m.email, u.CreatedAt)
		}
		if r := c.Post("/auth/login", map[string]any{"email": m.email, "password": m.password + "x"}); r.StatusCode != 401 {
			t.Fatalf("%s: wrong password: %d", m.email, r.StatusCode)
		}
		if r := c.Post("/auth/login", map[string]any{"email": m.email, "password": m.password}); r.StatusCode != 200 {
			t.Fatalf("%s: login: %d", m.email, r.StatusCode)
		}
		row, err := srv.Graph().Repos().Users.Get(ctx, u.ID)
		ok(t, err)
		if !strings.HasPrefix(*row.PasswordHash, "$argon2id$") {
			t.Fatalf("%s: not rehashed: %s", m.email, *row.PasswordHash)
		}
		if r := c.Post("/auth/login", map[string]any{"email": m.email, "password": m.password}); r.StatusCode != 200 {
			t.Fatalf("%s: login after the rehash: %d", m.email, r.StatusCode)
		}
	}
}

func TestImportRefusals(t *testing.T) {
	ctx := context.Background()
	srv := polaristest.New(t)
	_, err := srv.Users().Import(ctx, polaris.ImportedUser{Email: "ada@example.com", PasswordHash: "md5$seasalt$3f86d0d3d465b7b458c231bf3555c0e3"})
	is(t, err, polaris.ErrInvalidInput, "an unsupported hash")
	is(t, err, security.ErrUnsupportedHash, "an unsupported hash")
	if !strings.Contains(err.Error(), security.SupportedHashFormats) {
		t.Fatalf("the error does not list the formats: %v", err)
	}
	_, err = srv.Users().Import(ctx, polaris.ImportedUser{Email: "ada@example.com", PasswordHash: migrated[0].hash})
	ok(t, err)
	_, err = srv.Users().Import(ctx, polaris.ImportedUser{Email: "ada@example.com"})
	is(t, err, polaris.ErrConflict, "a taken email")
	_, err = srv.Users().Import(ctx, polaris.ImportedUser{Email: "bob@example.com", CreatedAt: time.Now().Add(time.Hour)})
	is(t, err, polaris.ErrInvalidInput, "a creation time in the future")
}
