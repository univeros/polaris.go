package identity

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/security"
)

// Published vectors (testdata/vectors): one per family a migration brings.
var importedVectors = []struct{ name, password, hash string }{
	{"bcrypt", "bcrypt", "$2y$04$9xkaXv9u52gB5CSHs990Rujqpwb54f2v3nd7nRc.mRPDPsGvyU1R6"},
	{"pbkdf2", "password", "$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ"},
	{"scrypt", "pleaseletmein", "$scrypt$ln=14,r=8,p=1$U29kaXVtQ2hsb3JpZGU$cCO9yzr9c0hGHAbNgf046/2o+7qQT44+qbVD9lRdofI"},
}

// An imported hash signs the user in with the password they already had; that sign-in replaces
// it with the configured Argon2id, and the next one verifies against the new hash.
func TestImportedUserSignsInAndIsRehashed(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		for _, v := range importedVectors {
			address := v.name + "@example.com"
			created := start.Add(-365 * 24 * time.Hour)
			u, err := h.svc.ImportUser(ctx, ImportedUser{Email: address, PasswordHash: v.hash, EmailVerified: true, CreatedAt: created})
			must(t, err)
			row := h.user(t, address)
			if row.ID != u.ID || row.PasswordHash == nil || *row.PasswordHash != v.hash || !row.CreatedAt.Equal(created) ||
				row.EmailVerifiedAt == nil || row.Status != model.UserStatusActive {
				t.Fatalf("%s: row %+v", v.name, row)
			}

			if _, err := h.svc.Login(ctx, address, v.password+"x", client); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("%s: wrong password: %v", v.name, err)
			}
			if _, err := h.svc.Login(ctx, address, v.password, client); err != nil {
				t.Fatalf("%s: login: %v", v.name, err)
			}
			upgraded := *h.user(t, address).PasswordHash
			if !strings.HasPrefix(upgraded, "$argon2id$") || h.hasher.NeedsRehash(upgraded) {
				t.Fatalf("%s: not rehashed: %s", v.name, upgraded)
			}
			if _, err := h.svc.Login(ctx, address, v.password, client); err != nil {
				t.Fatalf("%s: second login: %v", v.name, err)
			}
			if *h.user(t, address).PasswordHash != upgraded {
				t.Fatalf("%s: rehashed twice", v.name)
			}
		}
	})
}

func TestImportUserState(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		// Unverified: no challenge, no email; the user asks for one (resend) when they need it.
		u, err := h.svc.ImportUser(ctx, ImportedUser{Email: " Ada@Example.com ", DisplayName: "Ada", PasswordHash: importedVectors[0].hash})
		must(t, err)
		if u.Email != email || u.EmailVerifiedAt != nil || !u.CreatedAt.Equal(start) || u.DisplayName == nil || *u.DisplayName != "Ada" {
			t.Fatalf("user %+v", u)
		}
		if rows, err := h.repos.EmailVerifications.ListByUser(ctx, u.ID); err != nil || len(rows) != 0 {
			t.Fatalf("verification rows %v, %v", rows, err)
		}
		regs := ofType[event.UserRegistered](h.events)
		if len(regs) != 1 || regs[0].UserID != u.ID || regs[0].VerificationToken != "" {
			t.Fatalf("events %+v", regs)
		}

		// Disabled: the right password still meets the disabled account.
		_, err = h.svc.ImportUser(ctx, ImportedUser{Email: "grace@example.com", PasswordHash: importedVectors[0].hash, Disabled: true, EmailVerified: true})
		must(t, err)
		if h.user(t, "grace@example.com").Status != model.UserStatusDisabled {
			t.Fatal("not disabled")
		}
		_, err = h.svc.Login(ctx, "grace@example.com", importedVectors[0].password, client)
		isErr(t, err, ErrAccountDisabled)

		// No hash: an account that signs in another way.
		_, err = h.svc.ImportUser(ctx, ImportedUser{Email: "linus@example.com", EmailVerified: true})
		must(t, err)
		if h.user(t, "linus@example.com").PasswordHash != nil {
			t.Fatal("a password hash was stored")
		}
	})
}

func TestImportUserRefusals(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		good := importedVectors[0].hash
		_, err := h.svc.ImportUser(ctx, ImportedUser{Email: email, PasswordHash: good})
		must(t, err)
		before := len(ofType[event.UserRegistered](h.events))

		cases := []struct {
			name string
			in   ImportedUser
			want error
		}{
			{"taken email", ImportedUser{Email: email, PasswordHash: good}, ErrEmailTaken},
			{"bad email", ImportedUser{Email: "not-an-email", PasswordHash: good}, ErrInvalidProfile},
			{"long name", ImportedUser{Email: "x@example.com", DisplayName: strings.Repeat("a", 121)}, ErrInvalidProfile},
			{"future creation", ImportedUser{Email: "x@example.com", CreatedAt: start.Add(time.Second)}, ErrInvalidProfile},
			{"plaintext password", ImportedUser{Email: "x@example.com", PasswordHash: "hunter2"}, security.ErrUnsupportedHash},
			{"md5", ImportedUser{Email: "x@example.com", PasswordHash: "md5$seasalt$3f86d0d3d465b7b458c231bf3555c0e3"}, security.ErrUnsupportedHash},
			{"bcrypt cost 17", ImportedUser{Email: "x@example.com", PasswordHash: "$2y$17$9xkaXv9u52gB5CSHs990Rujqpwb54f2v3nd7nRc.mRPDPsGvyU1R6"}, security.ErrUnsupportedHash},
		}
		for _, c := range cases {
			_, err := h.svc.ImportUser(ctx, c.in)
			if !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
		}
		if _, err := h.repos.Users.ByEmail(ctx, "x@example.com"); err == nil {
			t.Fatal("a refused import left an account")
		}
		if got := len(ofType[event.UserRegistered](h.events)); got != before {
			t.Fatalf("refusals dispatched %d events", got-before)
		}
	})
}

// opaqueHasher is a PasswordHasher that cannot say which hashes it verifies.
type opaqueHasher struct{ security.PasswordHasher }

func TestImportUserNeedsAHashChecker(t *testing.T) {
	backends(t, func(t *testing.T, h *harness) {
		s, err := New(Config{
			DB: h.db, Hasher: opaqueHasher{h.hasher}, Pepper: h.pepper, Sessions: h.sessions, MFA: gate{h.repos},
			Tickets: tickets{}, Authority: h.admins, Auth: h.auth, Clock: h.clock, Events: h.events,
		})
		must(t, err)
		_, err = s.ImportUser(ctx, ImportedUser{Email: email, PasswordHash: importedVectors[0].hash})
		if err == nil || !strings.Contains(err.Error(), "security.HashChecker") {
			t.Fatalf("error %v", err)
		}
		// Without a hash there is nothing to check.
		_, err = s.ImportUser(ctx, ImportedUser{Email: email})
		must(t, err)
	})
}
