package apikeys

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
)

// PepperContext is the keyed-hash context of key secrets (core's Pepper).
const PepperContext = "api_key"

// Owner types and statuses.
const (
	OwnerUser         = "user"
	OwnerOrganization = "organization"

	StatusActive  = "active"
	StatusRotated = "rotated"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

const (
	secretBytes        = 32
	maxSecretLength    = 80
	lastUsedResolution = time.Minute
	nameMax            = 80
	metadataMaxBytes   = 4096
	maxRateLimitWindow = 86400 // seconds
)

var permissionPattern = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)

// RateLimit is a key's own budget: Max requests per Window seconds.
type RateLimit struct {
	Window int `json:"window"`
	Max    int `json:"max"`
}

// Key is a row of polaris_api_key: who owns it (a user, or an organization through the member who
// created it), the organization it acts in, the permissions its owner delegated, its limits and
// lifecycle. The secret is never stored; Hint is its last four characters.
type Key struct {
	ID             string
	OwnerType      string
	OwnerID        string
	OrganizationID string // "" when none
	CreatedBy      string
	Name           string
	Environment    string
	Hint           string
	KeyHash        string
	Permissions    []string
	RateLimit      *RateLimit
	Metadata       map[string]any
	RotatedFromID  string
	GraceUntil     *time.Time
	ExpiresAt      *time.Time
	LastUsedAt     *time.Time
	RevokedAt      *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// Subject is the user the key acts as: its owner, or the member who created an organization's key.
func (k Key) Subject() string {
	if k.OwnerType == OwnerUser {
		return k.OwnerID
	}
	return k.CreatedBy
}

// Status is the key's state at now.
func (k Key) Status(now time.Time) string {
	switch {
	case k.RevokedAt != nil:
		return StatusRevoked
	case k.ExpiresAt != nil && !k.ExpiresAt.After(now):
		return StatusExpired
	case k.GraceUntil != nil:
		return StatusRotated
	}
	return StatusActive
}

// Map is the key's wire shape (never the secret nor its hash).
func (k Key) Map(now time.Time) map[string]any {
	return map[string]any{
		"id":              k.ID,
		"name":            k.Name,
		"owner_type":      k.OwnerType,
		"owner_id":        k.OwnerID,
		"organization_id": null(k.OrganizationID),
		"created_by":      k.CreatedBy,
		"environment":     k.Environment,
		"hint":            k.Hint,
		"permissions":     list(k.Permissions),
		"rate_limit":      rateLimitValue(k.RateLimit),
		"metadata":        metadata(k.Metadata),
		"status":          k.Status(now),
		"rotated_from":    null(k.RotatedFromID),
		"grace_until":     atom(k.GraceUntil),
		"expires_at":      atom(k.ExpiresAt),
		"last_used_at":    atom(k.LastUsedAt),
		"created_at":      k.CreatedAt.UTC().Format(dateAtom),
		"updated_at":      k.UpdatedAt.UTC().Format(dateAtom),
	}
}

// Issued is a freshly created or rotated key and its secret, shown exactly once.
type Issued struct {
	Key    Key
	Secret string
}

// String keeps the secret out of fmt output.
func (i Issued) String() string { return "apikeys.Issued{" + i.Key.ID + "}" }

// GoString keeps the secret out of %#v output.
func (i Issued) GoString() string { return i.String() }

// CreateParams describe a new key.
type CreateParams struct {
	OwnerType      string // OwnerUser or OwnerOrganization
	OwnerID        string
	OrganizationID string // the organization the key acts in, "" for none
	CreatedBy      string
	Name           string
	Permissions    []string // each must be in the catalog and in Held
	Held           []string // what the caller holds in the key's organization
	Environment    string   // "live" or "test"; "" means the plugin's default
	RateLimit      *RateLimit
	ExpiresAt      *time.Time // in the future
	Metadata       map[string]any
}

// UpdateParams change a key; nil fields keep their value. ClearRateLimit and ClearExpiry clear
// the limit and the expiry.
type UpdateParams struct {
	Held           []string // bounds Permissions
	Name           *string
	Permissions    []string // nil keeps them
	RateLimit      *RateLimit
	ClearRateLimit bool
	ExpiresAt      *time.Time
	ClearExpiry    bool
	Metadata       map[string]any // nil keeps it
}

// Keys mints, authenticates, changes, rotates and revokes API keys: pk_<environment>_ plus 256
// random bits, stored as a keyed hash under the api_key pepper context.
type Keys struct {
	db          store.Adapter
	pepper      *security.Pepper
	permissions map[string]bool // the permission catalog
	settings    settings
	clock       clock.Clock
}

func (k *Keys) now() time.Time { return k.clock.Now().UTC().Truncate(time.Second) }

// Create mints a key; the secret is in the result only.
func (k *Keys) Create(ctx context.Context, p CreateParams) (Issued, error) {
	now := k.now()
	env := p.Environment
	if env == "" {
		env = k.settings.environment
	}
	if env != EnvLive && env != EnvTest {
		return Issued{}, invalid("environment must be live or test.")
	}
	live, err := k.db.Count(ctx, TableKeys, store.Criteria{"owner_type": p.OwnerType, "owner_id": p.OwnerID, "revoked_at": nil})
	if err != nil {
		return Issued{}, err
	}
	if live >= int64(k.settings.maxPerOwner) {
		return Issued{}, &Error{Kind: KindTooMany, Detail: fmt.Sprintf("An owner may hold at most %d keys; revoke one first.", k.settings.maxPerOwner)}
	}
	key := Key{ID: repository.NewID(), OwnerType: p.OwnerType, OwnerID: p.OwnerID, OrganizationID: p.OrganizationID,
		CreatedBy: p.CreatedBy, Environment: env, CreatedAt: now, UpdatedAt: now}
	if key.Name, err = checkName(p.Name); err != nil {
		return Issued{}, err
	}
	if key.Permissions, err = k.checkPermissions(p.Permissions, p.Held); err != nil {
		return Issued{}, err
	}
	if key.RateLimit, err = checkRateLimit(p.RateLimit); err != nil {
		return Issued{}, err
	}
	if key.ExpiresAt, err = checkExpiry(p.ExpiresAt, now); err != nil {
		return Issued{}, err
	}
	if key.Metadata, err = checkMetadata(p.Metadata); err != nil {
		return Issued{}, err
	}
	issued, err := k.mint(key)
	if err != nil {
		return Issued{}, err
	}
	r, err := row(issued.Key)
	if err != nil {
		return Issued{}, err
	}
	return issued, k.db.Insert(ctx, TableKeys, r)
}

func (k *Keys) mint(key Key) (Issued, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return Issued{}, err
	}
	secret := "pk_" + key.Environment + "_" + base64.RawURLEncoding.EncodeToString(b)
	key.Hint = secret[len(secret)-4:]
	key.KeyHash = k.pepper.Hash(PepperContext, secret)
	return Issued{Key: key, Secret: secret}, nil
}

// Authenticate returns the key behind a presented secret when it is live: not revoked, not
// expired, and (after a rotation) within its grace window. ok is false otherwise. Its
// last_used_at is stamped at most once a minute.
func (k *Keys) Authenticate(ctx context.Context, secret string) (Key, bool, error) {
	if !strings.HasPrefix(secret, "pk_") || len(secret) > maxSecretLength {
		return Key{}, false, nil
	}
	r, err := k.db.FindOne(ctx, TableKeys, store.Criteria{"key_hash": k.pepper.Hash(PepperContext, secret)})
	if err != nil || r == nil {
		return Key{}, false, err
	}
	key := hydrate(r)
	now := k.now()
	if key.RevokedAt != nil || (key.ExpiresAt != nil && !key.ExpiresAt.After(now)) || (key.GraceUntil != nil && !key.GraceUntil.After(now)) {
		return Key{}, false, nil
	}
	if key.LastUsedAt == nil || now.Sub(*key.LastUsedAt) >= lastUsedResolution {
		key.LastUsedAt = &now
		if _, err := k.db.Update(ctx, TableKeys, store.Criteria{"id": key.ID}, store.Data{"last_used_at": now}); err != nil {
			return Key{}, false, err
		}
	}
	return key, true, nil
}

// Find returns the key id names (revoked included); ok false when absent.
func (k *Keys) Find(ctx context.Context, id string) (Key, bool, error) {
	r, err := k.db.FindOne(ctx, TableKeys, store.Criteria{"id": id})
	if err != nil || r == nil {
		return Key{}, false, err
	}
	return hydrate(r), true, nil
}

// ForOwner lists the owner's keys that are not revoked, newest first.
func (k *Keys) ForOwner(ctx context.Context, ownerType, ownerID string) ([]Key, error) {
	rows, err := k.db.FindMany(ctx, TableKeys, store.Criteria{"owner_type": ownerType, "owner_id": ownerID, "revoked_at": nil},
		store.Query{OrderBy: []store.Order{{Column: "id", Desc: true}}})
	if err != nil {
		return nil, err
	}
	out := make([]Key, len(rows))
	for i, r := range rows {
		out[i] = hydrate(r)
	}
	return out, nil
}

// Update changes key and returns it with what changed (in upstream's order).
func (k *Keys) Update(ctx context.Context, key Key, p UpdateParams) (Key, []string, error) {
	now := k.now()
	data := store.Data{"updated_at": now}
	changes := []string{}
	var err error
	if p.Name != nil {
		if key.Name, err = checkName(*p.Name); err != nil {
			return key, nil, err
		}
		data["name"], changes = key.Name, append(changes, "name")
	}
	if p.Permissions != nil {
		if key.Permissions, err = k.checkPermissions(p.Permissions, p.Held); err != nil {
			return key, nil, err
		}
		if data["permissions"], err = store.JSONValue(key.Permissions); err != nil {
			return key, nil, err
		}
		changes = append(changes, "permissions")
	}
	if p.RateLimit != nil || p.ClearRateLimit {
		if key.RateLimit, err = checkRateLimit(p.RateLimit); err != nil {
			return key, nil, err
		}
		data["rate_limit_window"], data["rate_limit_max"] = nil, nil
		if key.RateLimit != nil {
			data["rate_limit_window"], data["rate_limit_max"] = key.RateLimit.Window, key.RateLimit.Max
		}
		changes = append(changes, "rate_limit")
	}
	if p.ExpiresAt != nil || p.ClearExpiry {
		if key.ExpiresAt, err = checkExpiry(p.ExpiresAt, now); err != nil {
			return key, nil, err
		}
		data["expires_at"], changes = nullTime(key.ExpiresAt), append(changes, "expires_at")
	}
	if p.Metadata != nil {
		if key.Metadata, err = checkMetadata(p.Metadata); err != nil {
			return key, nil, err
		}
		if data["metadata"], err = store.JSONValue(metadata(key.Metadata)); err != nil {
			return key, nil, err
		}
		changes = append(changes, "metadata")
	}
	key.UpdatedAt = now
	_, err = k.db.Update(ctx, TableKeys, store.Criteria{"id": key.ID}, data)
	return key, changes, err
}

// Rotate mints a successor with a new secret and the same owner, name, permissions, limit,
// expiry and metadata; key answers until the grace window ends. A key already rotated is refused
// (its successor is the one to rotate), also when two rotations race. It returns the predecessor
// as updated and the successor.
func (k *Keys) Rotate(ctx context.Context, key Key) (Key, Issued, error) {
	refused := &Error{Kind: KindForbidden, Detail: "This key was already rotated; rotate its successor."}
	if key.GraceUntil != nil {
		return key, Issued{}, refused
	}
	now := k.now()
	successor := key
	successor.ID, successor.RotatedFromID, successor.GraceUntil, successor.LastUsedAt = repository.NewID(), key.ID, nil, nil
	successor.CreatedAt, successor.UpdatedAt = now, now
	issued, err := k.mint(successor)
	if err != nil {
		return key, Issued{}, err
	}
	r, err := row(issued.Key)
	if err != nil {
		return key, Issued{}, err
	}
	grace := now.Add(k.settings.rotationGrace)
	err = k.db.Tx(ctx, func(ctx context.Context) error {
		n, err := k.db.Update(ctx, TableKeys, store.Criteria{"id": key.ID, "grace_until": nil, "revoked_at": nil}, store.Data{"grace_until": grace, "updated_at": now})
		if err != nil {
			return err
		}
		if n != 1 {
			return refused
		}
		return k.db.Insert(ctx, TableKeys, r)
	})
	if err != nil {
		return key, Issued{}, err
	}
	key.GraceUntil, key.UpdatedAt = &grace, now
	return key, issued, nil
}

// Revoke stops key at once.
func (k *Keys) Revoke(ctx context.Context, key Key) (Key, error) {
	now := k.now()
	key.RevokedAt, key.UpdatedAt = &now, now
	_, err := k.db.Update(ctx, TableKeys, store.Criteria{"id": key.ID}, store.Data{"revoked_at": now, "updated_at": now})
	return key, err
}

// DeleteForUser erases a user's keys: their own, and the organization keys they act for.
func (k *Keys) DeleteForUser(ctx context.Context, userID string) error {
	if _, err := k.db.Delete(ctx, TableKeys, store.Criteria{"owner_type": OwnerUser, "owner_id": userID}); err != nil {
		return err
	}
	_, err := k.db.Delete(ctx, TableKeys, store.Criteria{"created_by": userID})
	return err
}

// DeleteForMember erases the organization keys a departing member acts for.
func (k *Keys) DeleteForMember(ctx context.Context, organizationID, userID string) error {
	_, err := k.db.Delete(ctx, TableKeys, store.Criteria{"owner_type": OwnerOrganization, "owner_id": organizationID, "created_by": userID})
	return err
}

// DeleteForOrganization erases every key acting in an organization.
func (k *Keys) DeleteForOrganization(ctx context.Context, organizationID string) error {
	_, err := k.db.Delete(ctx, TableKeys, store.Criteria{"organization_id": organizationID})
	return err
}

func checkName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > nameMax {
		return "", invalid(fmt.Sprintf("name is required and at most %d characters.", nameMax))
	}
	return name, nil
}

// checkPermissions: each must be in the catalog and held by the owner; duplicates are dropped.
func (k *Keys) checkPermissions(permissions, held []string) ([]string, error) {
	out := []string{}
	for _, p := range permissions {
		if slices.Contains(out, p) {
			continue
		}
		if !permissionPattern.MatchString(p) || !k.permissions[p] {
			return nil, invalid(fmt.Sprintf("Unknown permission %q.", p))
		}
		if !slices.Contains(held, p) {
			return nil, &Error{Kind: KindPermissionNotHeld, Detail: fmt.Sprintf("You do not hold %q in this organization, so the key cannot either.", p)}
		}
		out = append(out, p)
	}
	return out, nil
}

func checkRateLimit(r *RateLimit) (*RateLimit, error) {
	if r == nil {
		return nil, nil
	}
	if r.Window < 1 || r.Window > maxRateLimitWindow || r.Max < 1 {
		return nil, invalid(fmt.Sprintf("rate_limit needs window (1 to %d seconds) and max (at least 1).", maxRateLimitWindow))
	}
	cp := *r
	return &cp, nil
}

func checkExpiry(t *time.Time, now time.Time) (*time.Time, error) {
	if t == nil {
		return nil, nil
	}
	if !t.After(now) {
		return nil, invalid("expires_at must be in the future.")
	}
	at := t.UTC().Truncate(time.Second)
	return &at, nil
}

func checkMetadata(m map[string]any) (map[string]any, error) {
	encoded, err := store.JSONValue(metadata(m))
	if err != nil {
		return nil, invalid("metadata must be an object.")
	}
	if len(encoded) > metadataMaxBytes {
		return nil, invalid(fmt.Sprintf("metadata is limited to %d bytes.", metadataMaxBytes))
	}
	return m, nil
}

func row(key Key) (store.Row, error) {
	perms, err := store.JSONValue(list(key.Permissions))
	if err != nil {
		return nil, err
	}
	meta, err := store.JSONValue(metadata(key.Metadata))
	if err != nil {
		return nil, err
	}
	var window, limit any
	if key.RateLimit != nil {
		window, limit = key.RateLimit.Window, key.RateLimit.Max
	}
	return store.Row{
		"id": key.ID, "owner_type": key.OwnerType, "owner_id": key.OwnerID, "organization_id": null(key.OrganizationID),
		"created_by": key.CreatedBy, "name": key.Name, "environment": key.Environment, "hint": key.Hint,
		"key_hash": key.KeyHash, "permissions": perms, "rate_limit_window": window, "rate_limit_max": limit,
		"metadata": meta, "rotated_from_id": null(key.RotatedFromID), "grace_until": nullTime(key.GraceUntil),
		"expires_at": nullTime(key.ExpiresAt), "last_used_at": nullTime(key.LastUsedAt), "revoked_at": nullTime(key.RevokedAt),
		"created_at": key.CreatedAt, "updated_at": key.UpdatedAt,
	}, nil
}

func hydrate(r store.Row) Key {
	key := Key{
		ID: r.String("id"), OwnerType: r.String("owner_type"), OwnerID: r.String("owner_id"),
		OrganizationID: r.String("organization_id"), CreatedBy: r.String("created_by"), Name: r.String("name"),
		Environment: r.String("environment"), Hint: r.String("hint"), KeyHash: r.String("key_hash"),
		RotatedFromID: r.String("rotated_from_id"), GraceUntil: r.TimePtr("grace_until"), ExpiresAt: r.TimePtr("expires_at"),
		LastUsedAt: r.TimePtr("last_used_at"), RevokedAt: r.TimePtr("revoked_at"),
		Permissions: []string{}, Metadata: map[string]any{},
	}
	key.CreatedAt, _ = r.Time("created_at")
	key.UpdatedAt, _ = r.Time("updated_at")
	_ = r.JSON("permissions", &key.Permissions)
	var meta any
	if r.JSON("metadata", &meta) == nil {
		if m, ok := meta.(map[string]any); ok {
			key.Metadata = m
		}
	}
	if r["rate_limit_window"] != nil {
		key.RateLimit = &RateLimit{Window: int(r.Int("rate_limit_window")), Max: int(r.Int("rate_limit_max"))}
	}
	return key
}

func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func atom(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(dateAtom)
}

func list(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func metadata(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func rateLimitValue(r *RateLimit) any {
	if r == nil {
		return nil
	}
	return map[string]any{"window": r.Window, "max": r.Max}
}
