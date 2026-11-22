package passwordless

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/univeros/polaris.go/wiring"
	"math/big"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
)

// Tables the plugin owns.
const (
	TableSecrets = "polaris_passwordless_secret"
	TablePhones  = "polaris_passwordless_phone"
)

// Models returns the plugin's tables (the columns existing databases hold): the secrets of the
// four methods (keyed hashes only, single use) and the verified phones (one per user, each
// number once).
func Models() []schema.Model {
	return []schema.Model{
		schema.Table(TableSecrets,
			schema.StringField("id", 36).AsPrimary(),
			schema.StringField("kind", 32),
			schema.StringField("identifierHash", 128),
			schema.StringField("userId", 36).AsNullable(),
			schema.StringField("secretHash", 128),
			schema.IntField("attempts").WithDefault(0),
			schema.JSONField("data"),
			schema.DateTimeField("expiresAt"),
			schema.DateTimeField("usedAt").AsNullable(),
			schema.DateTimeField("createdAt"),
		).
			Index([]string{"kind", "identifier_hash"}, "polaris_passwordless_secret_identifier_index").
			Index([]string{"secret_hash"}, "polaris_passwordless_secret_hash_index"),
		schema.Table(TablePhones,
			schema.StringField("userId", 36).AsPrimary(),
			schema.StringField("e164", 16),
			schema.DateTimeField("verifiedAt"),
			schema.DateTimeField("createdAt"),
		).Unique([]string{"e164"}, "polaris_passwordless_phone_unique"),
	}
}

// Secret kinds (the kind column).
const (
	kindMagicLink    = "magic_link"
	kindEmailSignIn  = "email_otp:sign-in"
	kindEmailVerify  = "email_otp:verify-email"
	kindEmailReset   = "email_otp:reset-password"
	kindPhoneSignIn  = "phone:sign-in"
	kindPhoneAdd     = "phone:add"
	kindOneTimeToken = "one_time_token"

	identifierContext = "passwordless:identifier"
)

// secret is a spent row of polaris_passwordless_secret.
type secret struct {
	userID string // "" when none
	data   []byte // the JSON data column
}

// secrets stores the secrets of the four methods. Only keyed hashes are stored (one pepper context
// per kind); a code is hashed with its identifier, so it only works for the address it was sent to.
// A secret is spent by an update requiring it unused; every guess at a code reserves one attempt
// with an update conditioned on attempts < max before it is compared, so parallel guesses cannot
// exceed the budget; a code sent again inherits the attempts of the live one it replaces.
type secrets struct {
	db          store.Adapter
	pepper      wiring.Pepper
	clock       clock.Clock
	maxAttempts int
}

// newToken is 256 random bits, base64url without padding.
func newToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails
	return base64.RawURLEncoding.EncodeToString(b)
}

// newCode is a uniform random code of length digits, zero-padded.
func newCode(length int) string {
	n, _ := rand.Int(rand.Reader, new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(length)), nil)) // never fails
	return fmt.Sprintf("%0*s", length, n.String())
}

func (s *secrets) now() time.Time { return s.clock.Now().UTC().Truncate(time.Second) }

func (s *secrets) identifier(v string) string { return s.pepper.Hash(identifierContext, v) }

// issueToken stores a token (a magic link, a one-time token), found again by its hash alone.
func (s *secrets) issueToken(ctx context.Context, kind, identifier, userID, tok string, ttl time.Duration, data any) error {
	return s.insert(ctx, kind, identifier, userID, s.pepper.Hash("passwordless:"+kind, tok), ttl, data, 0)
}

// issueCode stores a code for an identifier; the identifier's earlier unused codes of the kind die
// with it, and their attempts carry over. One transaction, so concurrent sends leave one code.
func (s *secrets) issueCode(ctx context.Context, kind, identifier, userID, code string, ttl time.Duration) error {
	unused := store.Criteria{"kind": kind, "identifier_hash": s.identifier(identifier), "used_at": nil}
	return s.db.Tx(ctx, func(ctx context.Context) error {
		live, err := s.db.FindMany(ctx, TableSecrets, store.Criteria{
			"kind": kind, "identifier_hash": unused["identifier_hash"], "used_at": nil, "expires_at": store.Gt(s.now()),
		}, store.Query{OrderBy: []store.Order{{Column: "attempts", Desc: true}}, Limit: 1})
		if err != nil {
			return err
		}
		attempts := 0
		if len(live) > 0 {
			attempts = int(live[0].Int("attempts"))
		}
		if _, err := s.db.Delete(ctx, TableSecrets, unused); err != nil {
			return err
		}
		return s.insert(ctx, kind, identifier, userID, s.pepper.Hash("passwordless:"+kind, identifier+"\x00"+code), ttl, nil, attempts)
	})
}

// spendToken spends the token's secret; ok is false when it is unknown, used or expired.
func (s *secrets) spendToken(ctx context.Context, kind, tok string) (secret, bool, error) {
	row, err := s.db.FindOne(ctx, TableSecrets, store.Criteria{"kind": kind, "secret_hash": s.pepper.Hash("passwordless:"+kind, tok), "used_at": nil})
	if err != nil || row == nil {
		return secret{}, false, err
	}
	return s.spend(ctx, row)
}

// liveToken reports whether the token's secret is unused and unexpired, spending nothing.
func (s *secrets) liveToken(ctx context.Context, kind, tok string) (bool, error) {
	row, err := s.db.FindOne(ctx, TableSecrets, store.Criteria{"kind": kind, "secret_hash": s.pepper.Hash("passwordless:"+kind, tok), "used_at": nil})
	if err != nil || row == nil {
		return false, err
	}
	expires, _ := row.Time("expires_at")
	return expires.After(s.now()), nil
}

// spendCode spends the identifier's latest code; ok is false when there is none, it expired, its
// attempts are used up, or the code is wrong. Every guess, right or wrong, uses an attempt.
func (s *secrets) spendCode(ctx context.Context, kind, identifier, code string) (secret, bool, error) {
	rows, err := s.db.FindMany(ctx, TableSecrets, store.Criteria{"kind": kind, "identifier_hash": s.identifier(identifier), "used_at": nil},
		store.Query{OrderBy: []store.Order{{Column: "id", Desc: true}}, Limit: 1})
	if err != nil || len(rows) == 0 {
		return secret{}, false, err
	}
	row := rows[0]
	reserved, err := s.db.Update(ctx, TableSecrets, store.Criteria{"id": row.String("id"), "used_at": nil, "attempts": store.Lt(s.maxAttempts)},
		store.Data{"attempts": store.Increment{By: 1}})
	if err != nil || reserved != 1 || !s.pepper.Matches("passwordless:"+kind, identifier+"\x00"+code, row.String("secret_hash")) {
		return secret{}, false, err
	}
	return s.spend(ctx, row)
}

func (s *secrets) spend(ctx context.Context, row store.Row) (secret, bool, error) {
	now := s.now()
	if expires, _ := row.Time("expires_at"); !expires.After(now) {
		return secret{}, false, nil
	}
	spent, err := s.db.Update(ctx, TableSecrets, store.Criteria{"id": row.String("id"), "used_at": nil}, store.Data{"used_at": now})
	if err != nil || spent != 1 {
		return secret{}, false, err
	}
	userID, _ := row.NullString("user_id")
	return secret{userID: userID, data: []byte(row.String("data"))}, true, nil
}

func (s *secrets) insert(ctx context.Context, kind, identifier, userID, hash string, ttl time.Duration, data any, attempts int) error {
	encoded, err := escapedJSON(data)
	if err != nil {
		return err
	}
	now := s.now()
	var user any
	if userID != "" {
		user = userID
	}
	return s.db.Insert(ctx, TableSecrets, store.Row{
		"id": repository.NewID(), "kind": kind, "identifier_hash": s.identifier(identifier), "user_id": user,
		"secret_hash": hash, "attempts": attempts, "data": encoded, "expires_at": now.Add(ttl),
		"used_at": nil, "created_at": now,
	})
}

// escapedJSON encodes v with slashes escaped ("\/") and every non-ASCII character as a \uXXXX
// escape (surrogate pairs above the BMP); nil is "[]". It is the form the data column has always
// held, so rows written by earlier releases and new ones read the same.
func escapedJSON(v any) (string, error) {
	if v == nil {
		return "[]", nil
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	var out strings.Builder
	for _, r := range strings.TrimSuffix(b.String(), "\n") {
		switch {
		case r == '/':
			out.WriteString(`\/`)
		case r < 0x80:
			out.WriteRune(r)
		default:
			for _, u := range utf16.Encode([]rune{r}) {
				out.WriteString(`\u` + leftPad(strconv.FormatUint(uint64(u), 16)))
			}
		}
	}
	return out.String(), nil
}

func leftPad(hex string) string { return strings.Repeat("0", 4-len(hex)) + hex }
