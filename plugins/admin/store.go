package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/univeros/polaris.go/wiring"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// KeyPrefix starts every operator API key: "pak_" and 256 random bits, base64url.
const KeyPrefix = "pak_"

// keyPepperContext is the keyed-hash context of the key secrets (core's Pepper).
const keyPepperContext = "admin_key"

const keyNameMax = 120

// dateAtom is RFC 3339 to the second with UTC written "+00:00" (not "Z"), the timestamp format
// the API emits and stored rows keep.
const dateAtom = "2006-01-02T15:04:05-07:00"

// ErrInvalid wraps the refusal of a grant or key with an invalid role, scope, name or allowlist.
var ErrInvalid = errors.New("admin: invalid input")

func atom(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.Format(dateAtom)
}

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func orInstance(scope string) string {
	if scope == "" {
		return ScopeInstance
	}
	return scope
}

// Grant is a Polaris user's operator role (polaris_admin_grant), on the instance or one
// organization, optionally expiring. A user has at most one.
type Grant struct {
	ID        string
	UserID    string
	Role      Role
	Scope     string // ScopeInstance ("" on input) or an organization id
	GrantedBy string // "" for none
	ExpiresAt *time.Time
	CreatedAt time.Time
}

// Map is the grant's wire shape.
func (g Grant) Map() map[string]any {
	return map[string]any{
		"id": g.ID, "user_id": g.UserID, "role": string(g.Role), "scope": g.Scope,
		"granted_by": null(g.GrantedBy), "expires_at": atom(g.ExpiresAt), "created_at": g.CreatedAt.Format(dateAtom),
	}
}

// Grants stores the operator roles of Polaris users.
type Grants struct {
	db    store.Adapter
	clock clock.Clock
}

func (s *Grants) now() time.Time { return s.clock.Now().UTC().Truncate(time.Second) }

// Grant gives g.UserID the role g.Role on g.Scope (default the instance) until g.ExpiresAt (nil:
// no expiry), replacing the user's previous grant: one grant per user, its id kept. An unknown
// role wraps ErrInvalid.
func (s *Grants) Grant(ctx context.Context, g Grant) (Grant, error) {
	if _, ok := ParseRole(string(g.Role)); !ok || g.UserID == "" {
		return Grant{}, fmt.Errorf("%w: a grant needs a user id and a role (viewer, support, admin or owner)", ErrInvalid)
	}
	g.Scope = orInstance(g.Scope)
	// user_id is unique: of two concurrent first grants one inserts, the other's insert is a
	// duplicate and it runs again as the update of the row now there, as if it had come second.
	var err error
	for range grantAttempts {
		if err = s.upsert(ctx, &g); !errors.Is(err, store.ErrDuplicate) {
			break
		}
	}
	if err != nil {
		return Grant{}, fmt.Errorf("admin: grant: %w", err)
	}
	return g, nil
}

// grantAttempts bounds Grant's retries after a concurrent first grant of the same user.
const grantAttempts = 3

// upsert updates the user's grant row or inserts it, in one transaction.
func (s *Grants) upsert(ctx context.Context, g *Grant) error {
	return s.db.Tx(ctx, func(ctx context.Context) error {
		r, err := s.db.FindOne(ctx, TableGrants, store.Criteria{"user_id": g.UserID})
		if err != nil {
			return err
		}
		data := store.Data{"role": string(g.Role), "scope": g.Scope, "granted_by": null(g.GrantedBy), "expires_at": timeOrNil(g.ExpiresAt)}
		if r != nil {
			g.ID, g.CreatedAt = r.String("id"), rowTime(r, "created_at")
			_, err = s.db.Update(ctx, TableGrants, store.Criteria{"id": g.ID}, data)
			return err
		}
		g.ID, g.CreatedAt = repository.NewID(), s.now()
		row := store.Row{"id": g.ID, "user_id": g.UserID, "created_at": g.CreatedAt}
		for k, v := range data {
			row[k] = v
		}
		return s.db.Insert(ctx, TableGrants, row)
	})
}

// For returns the user's grant when it has not lapsed.
func (s *Grants) For(ctx context.Context, userID string) (Grant, bool, error) {
	g, ok, err := s.find(ctx, store.Criteria{"user_id": userID})
	if !ok || err != nil || (g.ExpiresAt != nil && !g.ExpiresAt.After(s.clock.Now())) {
		return Grant{}, false, err
	}
	return g, true, nil
}

// Find returns the grant with id, lapsed or not.
func (s *Grants) Find(ctx context.Context, id string) (Grant, bool, error) {
	return s.find(ctx, store.Criteria{"id": id})
}

func (s *Grants) find(ctx context.Context, c store.Criteria) (Grant, bool, error) {
	r, err := s.db.FindOne(ctx, TableGrants, c)
	if err != nil || r == nil {
		return Grant{}, false, err
	}
	return hydrateGrant(r), true, nil
}

// All returns every grant, oldest first.
func (s *Grants) All(ctx context.Context) ([]Grant, error) {
	rows, err := s.db.FindMany(ctx, TableGrants, store.Criteria{}, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	out := make([]Grant, 0, len(rows))
	for _, r := range rows {
		out = append(out, hydrateGrant(r))
	}
	return out, err
}

// Revoke deletes the grant; false when it did not exist.
func (s *Grants) Revoke(ctx context.Context, id string) (bool, error) {
	n, err := s.db.Delete(ctx, TableGrants, store.Criteria{"id": id})
	return n > 0, err
}

func hydrateGrant(r store.Row) Grant {
	return Grant{
		ID: r.String("id"), UserID: r.String("user_id"), Role: Role(r.String("role")), Scope: r.String("scope"),
		GrantedBy: r.String("granted_by"), ExpiresAt: r.TimePtr("expires_at"), CreatedAt: rowTime(r, "created_at"),
	}
}

// Key is an operator API key (polaris_admin_key) for a dashboard or an integration: hashed at
// rest, with a role, a scope, an optional IP allowlist and an optional expiry.
type Key struct {
	ID          string
	Name        string
	Role        Role
	Scope       string   // ScopeInstance ("" on input) or an organization id
	IPAllowlist []string // addresses or CIDR blocks; empty means anywhere
	ExpiresAt   *time.Time
	LastUsedAt  *time.Time
	CreatedBy   string // "" for none
	CreatedAt   time.Time
}

// Map is the key's wire shape (never the secret nor its hash).
func (k Key) Map() map[string]any {
	allow := k.IPAllowlist
	if allow == nil {
		allow = []string{}
	}
	return map[string]any{
		"id": k.ID, "name": k.Name, "role": string(k.Role), "scope": k.Scope, "ip_allowlist": allow,
		"expires_at": atom(k.ExpiresAt), "last_used_at": atom(k.LastUsedAt), "created_by": null(k.CreatedBy),
		"created_at": k.CreatedAt.Format(dateAtom),
	}
}

// Keys stores the operator API keys.
type Keys struct {
	db     store.Adapter
	pepper wiring.Pepper
	clock  clock.Clock
}

func (s *Keys) now() time.Time { return s.clock.Now().UTC().Truncate(time.Second) }

// Create stores k (its ID, CreatedAt and LastUsedAt are set here) and returns it with its secret,
// which is shown once: only its keyed hash is stored. A name outside 1 to 120 characters, an
// unknown role or an invalid allowlist entry wraps ErrInvalid.
func (s *Keys) Create(ctx context.Context, k Key) (Key, string, error) {
	if n := utf8.RuneCountInString(k.Name); n == 0 || n > keyNameMax {
		return Key{}, "", fmt.Errorf("%w: name must be 1 to 120 characters", ErrInvalid)
	}
	if _, ok := ParseRole(string(k.Role)); !ok {
		return Key{}, "", fmt.Errorf("%w: role must be viewer, support, admin or owner", ErrInvalid)
	}
	for _, entry := range k.IPAllowlist {
		if !ValidAllowlistEntry(entry) {
			return Key{}, "", fmt.Errorf("%w: %q is not an address or a CIDR block", ErrInvalid, entry)
		}
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Key{}, "", fmt.Errorf("admin: key: %w", err)
	}
	secret := KeyPrefix + base64.RawURLEncoding.EncodeToString(b)
	k.ID, k.Scope, k.CreatedAt, k.LastUsedAt = repository.NewID(), orInstance(k.Scope), s.now(), nil
	if k.IPAllowlist == nil {
		k.IPAllowlist = []string{}
	}
	allow, err := store.JSONValue(k.IPAllowlist)
	if err != nil {
		return Key{}, "", err
	}
	err = s.db.Insert(ctx, TableKeys, store.Row{
		"id": k.ID, "name": k.Name, "key_hash": s.pepper.Hash(keyPepperContext, secret), "role": string(k.Role),
		// The stored text escapes slashes ("10.0.0.0\/8"), the bytes rows written by earlier releases
		// hold.
		"scope": k.Scope, "ip_allowlist": strings.ReplaceAll(allow, "/", `\/`), "expires_at": timeOrNil(k.ExpiresAt),
		"last_used_at": nil, "created_by": null(k.CreatedBy), "created_at": k.CreatedAt,
	})
	if err != nil {
		return Key{}, "", fmt.Errorf("admin: key: %w", err)
	}
	return k, secret, nil
}

// Authenticate returns the key behind secret when it exists, has not expired and allows ip; its
// last use is stamped.
func (s *Keys) Authenticate(ctx context.Context, secret, ip string) (Key, bool, error) {
	if !strings.HasPrefix(secret, KeyPrefix) {
		return Key{}, false, nil
	}
	k, ok, err := s.find(ctx, store.Criteria{"key_hash": s.pepper.Hash(keyPepperContext, secret)})
	now := s.now()
	if !ok || err != nil || (k.ExpiresAt != nil && !k.ExpiresAt.After(s.clock.Now())) || !AllowlistAllows(k.IPAllowlist, ip) {
		return Key{}, false, err
	}
	k.LastUsedAt = &now
	if _, err := s.db.Update(ctx, TableKeys, store.Criteria{"id": k.ID}, store.Data{"last_used_at": now}); err != nil {
		return Key{}, false, err
	}
	return k, true, nil
}

// Find returns the key with id.
func (s *Keys) Find(ctx context.Context, id string) (Key, bool, error) {
	return s.find(ctx, store.Criteria{"id": id})
}

func (s *Keys) find(ctx context.Context, c store.Criteria) (Key, bool, error) {
	r, err := s.db.FindOne(ctx, TableKeys, c)
	if err != nil || r == nil {
		return Key{}, false, err
	}
	return hydrateKey(r), true, nil
}

// All returns every key, oldest first.
func (s *Keys) All(ctx context.Context) ([]Key, error) {
	rows, err := s.db.FindMany(ctx, TableKeys, store.Criteria{}, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	out := make([]Key, 0, len(rows))
	for _, r := range rows {
		out = append(out, hydrateKey(r))
	}
	return out, err
}

// Delete deletes the key, which stops working at once; false when it did not exist.
func (s *Keys) Delete(ctx context.Context, id string) (bool, error) {
	n, err := s.db.Delete(ctx, TableKeys, store.Criteria{"id": id})
	return n > 0, err
}

func hydrateKey(r store.Row) Key {
	k := Key{
		ID: r.String("id"), Name: r.String("name"), Role: Role(r.String("role")), Scope: r.String("scope"),
		ExpiresAt: r.TimePtr("expires_at"), LastUsedAt: r.TimePtr("last_used_at"), CreatedBy: r.String("created_by"),
		CreatedAt: rowTime(r, "created_at"), IPAllowlist: []string{},
	}
	var allow []any
	if r.JSON("ip_allowlist", &allow) == nil {
		for _, v := range allow {
			if s, ok := v.(string); ok { // non-string entries are ignored
				k.IPAllowlist = append(k.IPAllowlist, s)
			}
		}
	}
	return k
}

func rowTime(r store.Row, col string) time.Time {
	t, _ := r.Time(col)
	return t
}

func timeOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}
