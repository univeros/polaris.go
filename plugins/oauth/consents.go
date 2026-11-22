package oauth

import (
	"context"
	"slices"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// Consent is a user's consent to a client in an organization: the scopes granted so far.
type Consent struct {
	ID, UserID, ClientID, OrganizationID string
	Scopes                               []string
	GrantedAt, UpdatedAt                 time.Time
}

func (c Consent) view() map[string]any {
	return map[string]any{
		"id": c.ID, "client_id": c.ClientID, "organization_id": null(c.OrganizationID),
		"scopes": list(c.Scopes), "granted_at": timestamp(c.GrantedAt), "updated_at": timestamp(c.UpdatedAt),
	}
}

func consentFromRow(r store.Row) Consent {
	c := Consent{
		ID: r.String("id"), UserID: r.String("user_id"), ClientID: r.String("client_id"),
		OrganizationID: r.String("organization_id"), Scopes: stringList(r, "scopes"),
	}
	c.GrantedAt, _ = r.Time("granted_at")
	c.UpdatedAt, _ = r.Time("updated_at")
	return c
}

// consents keeps one row per user, client and organization ("" outside any): what a user grants
// a client while acting in one organization says nothing about another, where the same scopes
// reach other data. A request within the scopes needs no screen, a wider one asks again. A row
// written before decision 75 (one per user and client) counts for the organization it names.
type consents struct {
	db    store.Adapter
	clock clock.Clock
}

func (s *consents) find(ctx context.Context, userID, clientID, organizationID string) (*Consent, error) {
	row, err := s.db.FindOne(ctx, TableConsents, store.Criteria{"user_id": userID, "client_id": clientID, "organization_id": null(organizationID)})
	if err != nil || row == nil {
		return nil, err
	}
	c := consentFromRow(row)
	return &c, nil
}

func (s *consents) covers(ctx context.Context, userID, clientID, organizationID string, scopes []string) (bool, error) {
	c, err := s.find(ctx, userID, clientID, organizationID)
	if err != nil || c == nil {
		return false, err
	}
	for _, sc := range scopes {
		if !slices.Contains(c.Scopes, sc) {
			return false, nil
		}
	}
	return true, nil
}

// grant records scopes, merged with what the user granted the client in the organization before.
func (s *consents) grant(ctx context.Context, userID, clientID, organizationID string, scopes []string) error {
	now := s.clock.Now()
	existing, err := s.find(ctx, userID, clientID, organizationID)
	if err != nil {
		return err
	}
	if existing == nil {
		value, err := store.JSONValue(unique(scopes))
		if err != nil {
			return err
		}
		return s.db.Insert(ctx, TableConsents, store.Row{
			"id": repository.NewID(), "user_id": userID, "client_id": clientID,
			"organization_id": null(organizationID), "scopes": value, "granted_at": now, "updated_at": now,
		})
	}
	value, err := store.JSONValue(unique(append(slices.Clone(existing.Scopes), scopes...)))
	if err != nil {
		return err
	}
	_, err = s.db.Update(ctx, TableConsents, store.Criteria{"id": existing.ID}, store.Data{"scopes": value, "updated_at": now})
	return err
}

func (s *consents) forUser(ctx context.Context, userID string) ([]Consent, error) {
	rows, err := s.db.FindMany(ctx, TableConsents, store.Criteria{"user_id": userID}, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, err
	}
	out := make([]Consent, 0, len(rows))
	for _, r := range rows {
		out = append(out, consentFromRow(r))
	}
	return out, nil
}

func (s *consents) revoke(ctx context.Context, userID, clientID string) (bool, error) {
	n, err := s.db.Delete(ctx, TableConsents, store.Criteria{"user_id": userID, "client_id": clientID})
	return n > 0, err
}

// unique keeps the first occurrence of each value, never nil.
func unique(values []string) []string {
	out := []string{}
	for _, v := range values {
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}
