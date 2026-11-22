package scim

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/univeros/polaris.go/wiring"
	"strings"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// TokenPrefix starts every connection token.
const TokenPrefix = "pst_"

// Connection states and deprovisioning modes.
const (
	StatusActive         = "active"
	StatusDecommissioned = "decommissioned"
	// DeprovisionDeactivate bans a deprovisioned user and ends their sessions (the default).
	DeprovisionDeactivate = "deactivate"
	// DeprovisionDelete anonymises a deprovisioned user.
	DeprovisionDelete = "delete"
)

// Connection listing bounds.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// pepperContext keys the token hash; tokens issued by earlier releases are stored hashed under
// it, so it never changes.
const pepperContext = "scim_token"

// Connection is a directory's link to one organization (polaris_scim_connection).
type Connection struct {
	ID               string
	OrganizationID   string
	SSOProviderID    string // "" when unpaired
	Name             string
	TokenHash        string
	Status           string
	Deprovision      string // DeprovisionDeactivate or DeprovisionDelete
	LastSyncAt       *time.Time
	DecommissionedAt *time.Time
	CreatedBy        string // "" when unknown
	CreatedAt        time.Time
}

// Active reports whether the connection's token still authenticates.
func (c Connection) Active() bool { return c.Status == StatusActive }

// Map is the connection as the API shows it: never the token hash.
func (c Connection) Map() map[string]any {
	return map[string]any{
		"id": c.ID, "organization_id": c.OrganizationID, "sso_provider_id": nullable(c.SSOProviderID),
		"name": c.Name, "status": c.Status, "deprovision": c.Deprovision,
		"last_sync_at": atomPtr(c.LastSyncAt), "decommissioned_at": atomPtr(c.DecommissionedAt),
		"created_by": nullable(c.CreatedBy), "created_at": atom(c.CreatedAt),
	}
}

// Connections stores the organizations' connections and authenticates their tokens: TokenPrefix
// and 256 random bits, stored as a keyed hash, shown once.
type Connections struct {
	db     store.Adapter
	pepper wiring.Pepper
	clock  clock.Clock
}

func (c *Connections) now() time.Time { return c.clock.Now().UTC().Truncate(time.Second) }

// Create stores a new connection; the token in clear is returned only here.
func (c *Connections) Create(ctx context.Context, organizationID, name, deprovision, ssoProviderID, createdBy string) (Connection, string, error) {
	token, err := newToken()
	if err != nil {
		return Connection{}, "", err
	}
	if deprovision != DeprovisionDelete {
		deprovision = DeprovisionDeactivate
	}
	settings, _ := json.Marshal(map[string]string{"deprovision": deprovision})
	conn := Connection{
		ID: repository.NewID(), OrganizationID: organizationID, SSOProviderID: ssoProviderID, Name: name,
		TokenHash: c.pepper.Hash(pepperContext, token), Status: StatusActive, Deprovision: deprovision,
		CreatedBy: createdBy, CreatedAt: c.now(),
	}
	err = c.db.Insert(ctx, TableConnections, store.Row{
		"id": conn.ID, "organization_id": organizationID, "sso_provider_id": nullable(ssoProviderID), "name": name,
		"token_hash": conn.TokenHash, "status": StatusActive, "settings": string(settings), "last_sync_at": nil,
		"decommissioned_at": nil, "created_by": nullable(createdBy), "created_at": conn.CreatedAt,
	})
	if err != nil {
		return Connection{}, "", err
	}
	return conn, token, nil
}

// Rotate gives conn a new token; the previous one stops at once.
func (c *Connections) Rotate(ctx context.Context, conn Connection) (Connection, string, error) {
	token, err := newToken()
	if err != nil {
		return conn, "", err
	}
	conn.TokenHash = c.pepper.Hash(pepperContext, token)
	if _, err := c.db.Update(ctx, TableConnections, store.Criteria{"id": conn.ID}, store.Data{"token_hash": conn.TokenHash}); err != nil {
		return conn, "", err
	}
	return conn, token, nil
}

// Decommission stops the connection's token; what it provisioned stays.
func (c *Connections) Decommission(ctx context.Context, conn Connection) (Connection, error) {
	now := c.now()
	conn.Status, conn.DecommissionedAt = StatusDecommissioned, &now
	_, err := c.db.Update(ctx, TableConnections, store.Criteria{"id": conn.ID}, store.Data{"status": conn.Status, "decommissioned_at": now})
	return conn, err
}

// touch records a directory request.
func (c *Connections) touch(ctx context.Context, conn Connection) error {
	_, err := c.db.Update(ctx, TableConnections, store.Criteria{"id": conn.ID}, store.Data{"last_sync_at": c.now()})
	return err
}

// Authenticate returns the active connection token belongs to; ok is false otherwise.
func (c *Connections) Authenticate(ctx context.Context, token string) (Connection, bool, error) {
	if !strings.HasPrefix(token, TokenPrefix) {
		return Connection{}, false, nil
	}
	r, err := c.db.FindOne(ctx, TableConnections, store.Criteria{"token_hash": c.pepper.Hash(pepperContext, token)})
	if err != nil || r == nil {
		return Connection{}, false, err
	}
	conn := hydrate(r)
	return conn, conn.Active(), nil
}

// Find returns the connection id names; ok is false when there is none.
func (c *Connections) Find(ctx context.Context, id string) (Connection, bool, error) {
	r, err := c.db.FindOne(ctx, TableConnections, store.Criteria{"id": id})
	if err != nil || r == nil {
		return Connection{}, false, err
	}
	return hydrate(r), true, nil
}

// ForOrganization lists an organization's connections, oldest first.
func (c *Connections) ForOrganization(ctx context.Context, organizationID string) ([]Connection, error) {
	return c.find(ctx, store.Criteria{"organization_id": organizationID}, 0)
}

// List pages every connection (or one organization's when organizationID is set), oldest
// first, after cursor; next is the cursor of the following page, "" on the last. limit is
// clamped to 1..MaxLimit.
func (c *Connections) List(ctx context.Context, organizationID, cursor string, limit int) (page []Connection, next string, err error) {
	limit = max(1, min(MaxLimit, limit))
	criteria := store.Criteria{}
	if organizationID != "" {
		criteria["organization_id"] = organizationID
	}
	if cursor != "" {
		criteria["id"] = store.Gt(cursor)
	}
	found, err := c.find(ctx, criteria, limit+1)
	if err != nil || len(found) <= limit {
		return found, "", err
	}
	return found[:limit], found[limit-1].ID, nil
}

func (c *Connections) find(ctx context.Context, criteria store.Criteria, limit int) ([]Connection, error) {
	rows, err := c.db.FindMany(ctx, TableConnections, criteria, store.Query{OrderBy: []store.Order{{Column: "id"}}, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]Connection, len(rows))
	for i, r := range rows {
		out[i] = hydrate(r)
	}
	return out, nil
}

// Delete removes the connection with its external ids and provenance (the users stay); false
// when there was none.
func (c *Connections) Delete(ctx context.Context, id string) (bool, error) {
	var n int64
	err := c.db.Tx(ctx, func(ctx context.Context) error {
		for _, table := range []string{TableResources, TableProvenance} {
			if _, err := c.db.Delete(ctx, table, store.Criteria{"connection_id": id}); err != nil {
				return err
			}
		}
		var err error
		n, err = c.db.Delete(ctx, TableConnections, store.Criteria{"id": id})
		return err
	})
	return n > 0, err
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return TokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func hydrate(r store.Row) Connection {
	var settings struct {
		Deprovision any `json:"deprovision"`
	}
	_ = r.JSON("settings", &settings)
	conn := Connection{
		ID: r.String("id"), OrganizationID: r.String("organization_id"), SSOProviderID: r.String("sso_provider_id"),
		Name: r.String("name"), TokenHash: r.String("token_hash"), Status: r.String("status"),
		Deprovision: DeprovisionDeactivate, LastSyncAt: r.TimePtr("last_sync_at"),
		DecommissionedAt: r.TimePtr("decommissioned_at"), CreatedBy: r.String("created_by"),
	}
	if settings.Deprovision == DeprovisionDelete {
		conn.Deprovision = DeprovisionDelete
	}
	conn.CreatedAt, _ = r.Time("created_at")
	return conn
}

// dateAtom is RFC 3339 to the second with UTC written "+00:00" (not "Z"): the timestamp format
// the API emits and stored rows keep.
const dateAtom = "2006-01-02T15:04:05-07:00"

func atom(t time.Time) string { return t.UTC().Format(dateAtom) }

func atomPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return atom(*t)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
