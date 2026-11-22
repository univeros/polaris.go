package sso

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
)

// Provider listing bounds for the operators.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// The configuration members a provider keeps, in the order they are stored.
var (
	samlKeys = []string{"sso_url", "slo_url", "slo_response_url", "certificate", "idp_initiated"}
	oidcKeys = []string{"issuer", "client_id", "client_secret", "scopes"}
)

// Providers stores the organizations' providers (polaris_sso_provider); the OIDC client secret is
// encrypted at rest with core's encrypter and decrypted only for the token exchange.
type Providers struct {
	db    store.Adapter
	enc   security.Encrypter
	clock clock.Clock
}

func (s *Providers) now() time.Time { return s.clock.Now().UTC().Truncate(time.Second) }

// Find returns the provider id names; ok is false when there is none.
func (s *Providers) Find(ctx context.Context, id string) (Provider, bool, error) {
	r, err := s.db.FindOne(ctx, TableProviders, store.Criteria{"id": id})
	if err != nil || r == nil {
		return Provider{}, false, err
	}
	return hydrateProvider(r), true, nil
}

// ForOrganization lists an organization's providers, oldest first.
func (s *Providers) ForOrganization(ctx context.Context, organizationID string) ([]Provider, error) {
	return s.find(ctx, store.Criteria{"organization_id": organizationID}, 0)
}

// List pages every provider (or one organization's when organizationID is set), oldest first,
// after cursor; next is the cursor of the following page, "" on the last. limit is clamped to
// 1..MaxLimit.
func (s *Providers) List(ctx context.Context, organizationID, cursor string, limit int) (page []Provider, next string, err error) {
	limit = max(1, min(MaxLimit, limit))
	criteria := store.Criteria{}
	if organizationID != "" {
		criteria["organization_id"] = organizationID
	}
	if cursor != "" {
		criteria["id"] = store.Gt(cursor)
	}
	found, err := s.find(ctx, criteria, limit+1)
	if err != nil || len(found) <= limit {
		return found, "", err
	}
	return found[:limit], found[limit-1].ID, nil
}

func (s *Providers) find(ctx context.Context, criteria store.Criteria, limit int) ([]Provider, error) {
	rows, err := s.db.FindMany(ctx, TableProviders, criteria, store.Query{OrderBy: []store.Order{{Column: "id"}}, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]Provider, len(rows))
	for i, r := range rows {
		out[i] = hydrateProvider(r)
	}
	return out, nil
}

// Create stores a new provider; p.Config carries the client secret in clear, stored encrypted.
// The id and the timestamps are set here.
func (s *Providers) Create(ctx context.Context, p Provider) (Provider, error) {
	now := s.now()
	p.ID, p.CreatedAt, p.UpdatedAt = repository.NewID(), now, now
	var err error
	if p.Config, err = s.seal(p.Config); err != nil {
		return Provider{}, err
	}
	row, err := providerRow(p)
	if err != nil {
		return Provider{}, err
	}
	row["id"], row["organization_id"], row["type"], row["created_by"], row["created_at"] =
		p.ID, p.OrganizationID, p.Type, nullable(p.CreatedBy), p.CreatedAt
	return p, s.db.Insert(ctx, TableProviders, row)
}

// Update replaces the provider's fields with next's (id, organization, type and creation stay);
// a next.Config without a client secret keeps the stored one.
func (s *Providers) Update(ctx context.Context, current, next Provider) (Provider, error) {
	next.ID, next.OrganizationID, next.Type, next.CreatedBy, next.CreatedAt =
		current.ID, current.OrganizationID, current.Type, current.CreatedBy, current.CreatedAt
	next.UpdatedAt = s.now()
	config := next.Config
	if stored := current.Setting(secretKey); stored != "" && config[secretKey] == nil {
		config = withMember(config, secretKey, stored) // already sealed
	} else {
		var err error
		if config, err = s.seal(config); err != nil {
			return current, err
		}
	}
	next.Config = config
	row, err := providerRow(next)
	if err != nil {
		return current, err
	}
	_, err = s.db.Update(ctx, TableProviders, store.Criteria{"id": current.ID}, store.Data(row))
	return next, err
}

// Delete removes the provider and its domains; false when there was none.
func (s *Providers) Delete(ctx context.Context, id string) (bool, error) {
	var n int64
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if _, err := s.db.Delete(ctx, TableDomains, store.Criteria{"provider_id": id}); err != nil {
			return err
		}
		var err error
		n, err = s.db.Delete(ctx, TableProviders, store.Criteria{"id": id})
		return err
	})
	return n > 0, err
}

// Secret is the provider's OIDC client secret in clear, "" when none is set.
func (s *Providers) Secret(p Provider) (string, error) {
	sealed := p.Setting(secretKey)
	if sealed == "" {
		return "", nil
	}
	return s.enc.Decrypt(sealed)
}

func (s *Providers) seal(config map[string]any) (map[string]any, error) {
	secret, _ := config[secretKey].(string)
	if secret == "" {
		return config, nil
	}
	sealed, err := s.enc.Encrypt(secret)
	if err != nil {
		return nil, err
	}
	return withMember(config, secretKey, sealed), nil
}

func withMember(m map[string]any, key string, value any) map[string]any {
	out := make(map[string]any, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	out[key] = value
	return out
}

// providerRow is the provider's mutable columns. The JSON columns are written by escapedJSON with
// the known configuration members first, in a fixed order, so stored rows keep one byte form.
func providerRow(p Provider) (store.Row, error) {
	keys := oidcKeys
	if p.Type == TypeSAML {
		keys = samlKeys
	}
	var config object
	for _, k := range keys {
		if v, ok := p.Config[k]; ok {
			config = append(config, member{k, v})
		}
	}
	for _, k := range sortedAnyKeys(p.Config) { // members set from code, after the known ones
		if !slices.Contains(keys, k) {
			config = append(config, member{k, p.Config[k]})
		}
	}
	var attributes object
	for _, k := range sortedKeys(p.Attributes) {
		attributes = append(attributes, member{k, p.Attributes[k]})
	}
	encoded := make([]string, 4)
	for i, v := range []any{config, attributes, object{{"enabled", p.JIT.Enabled}, {"roles", nonNil(p.JIT.Roles)}}, nonNil(p.RedirectURIs)} {
		var err error
		if encoded[i], err = escapedJSON(v); err != nil {
			return nil, err
		}
	}
	return store.Row{
		"name": p.Name, "issuer": p.Issuer, "config": encoded[0], "attributes": encoded[1], "jit": encoded[2],
		"redirect_uris": encoded[3], "enabled": p.Enabled, "updated_at": p.UpdatedAt,
	}, nil
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func hydrateProvider(r store.Row) Provider {
	p := Provider{
		ID: r.String("id"), OrganizationID: r.String("organization_id"), Type: r.String("type"), Name: r.String("name"),
		Issuer: r.String("issuer"), Enabled: r.Bool("enabled"), CreatedBy: r.String("created_by"),
		Config: map[string]any{}, Attributes: map[string]string{},
	}
	var config, attributes map[string]any
	_ = r.JSON("config", &config) // an empty object is stored as "[]", which leaves the maps empty
	for k, v := range config {
		p.Config[k] = v
	}
	_ = r.JSON("attributes", &attributes)
	for k, v := range attributes {
		if s, ok := v.(string); ok && s != "" {
			p.Attributes[k] = s
		}
	}
	var jit struct {
		Enabled any `json:"enabled"`
		Roles   any `json:"roles"`
	}
	_ = r.JSON("jit", &jit)
	p.JIT = JIT{Enabled: jit.Enabled == true, Roles: stringsOf(jit.Roles)}
	var uris any
	_ = r.JSON("redirect_uris", &uris)
	p.RedirectURIs = stringsOf(uris)
	p.CreatedAt, _ = r.Time("created_at")
	p.UpdatedAt, _ = r.Time("updated_at")
	return p
}

// stringsOf is the string items of a JSON list, other items skipped; never nil.
func stringsOf(v any) []string {
	list, _ := v.([]any)
	out := []string{}
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Domains stores the organizations' domains (polaris_sso_domain): claimed with a token, verified
// through DNS or HTTPS, then routing sign-ins. A domain belongs to one organization across the
// instance.
type Domains struct {
	db    store.Adapter
	clock clock.Clock
}

// Find returns the domain id names; ok is false when there is none.
func (s *Domains) Find(ctx context.Context, id string) (Domain, bool, error) {
	return s.one(ctx, store.Criteria{"id": id})
}

// FindByName returns the record of a domain name, whatever its case.
func (s *Domains) FindByName(ctx context.Context, name string) (Domain, bool, error) {
	return s.one(ctx, store.Criteria{"domain": strings.ToLower(name)})
}

// Verified returns the verified record of a domain name, for routing.
func (s *Domains) Verified(ctx context.Context, name string) (Domain, bool, error) {
	d, ok, err := s.FindByName(ctx, name)
	return d, ok && d.VerifiedAt != nil, err
}

// ForOrganization lists an organization's domains, oldest first.
func (s *Domains) ForOrganization(ctx context.Context, organizationID string) ([]Domain, error) {
	rows, err := s.db.FindMany(ctx, TableDomains, store.Criteria{"organization_id": organizationID}, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, err
	}
	out := make([]Domain, len(rows))
	for i, r := range rows {
		out[i] = hydrateDomain(r)
	}
	return out, nil
}

// Add claims a domain for a provider with a fresh verification token; a domain claimed already
// fails with store.ErrDuplicate.
func (s *Domains) Add(ctx context.Context, organizationID, providerID, name string) (Domain, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return Domain{}, err
	}
	d := Domain{
		ID: repository.NewID(), OrganizationID: organizationID, ProviderID: providerID, Domain: strings.ToLower(name),
		Token: "polaris-sso-" + hex.EncodeToString(token), CreatedAt: s.clock.Now().UTC().Truncate(time.Second),
	}
	return d, s.db.Insert(ctx, TableDomains, store.Row{
		"id": d.ID, "organization_id": d.OrganizationID, "provider_id": d.ProviderID, "domain": d.Domain,
		"token": d.Token, "verified_at": nil, "created_at": d.CreatedAt,
	})
}

// MarkVerified records the domain as verified now.
func (s *Domains) MarkVerified(ctx context.Context, d Domain) (Domain, error) {
	now := s.clock.Now().UTC().Truncate(time.Second)
	d.VerifiedAt = &now
	_, err := s.db.Update(ctx, TableDomains, store.Criteria{"id": d.ID}, store.Data{"verified_at": now})
	return d, err
}

// Delete removes a domain; false when there was none.
func (s *Domains) Delete(ctx context.Context, id string) (bool, error) {
	n, err := s.db.Delete(ctx, TableDomains, store.Criteria{"id": id})
	return n > 0, err
}

func (s *Domains) one(ctx context.Context, criteria store.Criteria) (Domain, bool, error) {
	r, err := s.db.FindOne(ctx, TableDomains, criteria)
	if err != nil || r == nil {
		return Domain{}, false, err
	}
	return hydrateDomain(r), true, nil
}

func hydrateDomain(r store.Row) Domain {
	d := Domain{
		ID: r.String("id"), OrganizationID: r.String("organization_id"), ProviderID: r.String("provider_id"),
		Domain: r.String("domain"), Token: r.String("token"), VerifiedAt: r.TimePtr("verified_at"),
	}
	d.CreatedAt, _ = r.Time("created_at")
	return d
}
