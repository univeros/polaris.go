package agents

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"strings"

	"github.com/univeros/polaris.go/store"
)

const (
	// HostTokenPrefix starts every host enrolment token.
	HostTokenPrefix = "peh_"
	hostPepper      = "agent_host"
	maxDefaults     = 50
)

// createHost creates a host for the owner with its enrolment token, shown once and stored as a
// keyed hash.
func (s *service) createHost(ctx context.Context, owner Host, name any, defaults []any) (Host, string, error) {
	n, _ := name.(string)
	n, ok := displayName(n)
	if !ok {
		return Host{}, "", refuse(ErrInvalidInput, "name is required, at most 160 characters.")
	}
	if len(defaults) > maxDefaults {
		return Host{}, "", refuse(ErrInvalidInput, "At most 50 default capabilities.")
	}
	h := owner
	h.DefaultCapabilities = []string{}
	for _, d := range defaults {
		capability, ok := d.(string)
		if !ok || s.caps.find(capability) == nil {
			if !ok {
				capability = "?"
			}
			return Host{}, "", &Error{Type: ErrCapabilityNotFound, Detail: "default_capabilities names capabilities this server declares.",
				Extra: map[string]any{"invalid_capabilities": []string{capability}}}
		}
		h.DefaultCapabilities = append(h.DefaultCapabilities, capability)
	}
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	secret := HostTokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	h.ID, h.Name, h.CreatedAt, h.tokenHash = newID(), n, s.now(), s.pepper.Hash(hostPepper, secret)
	if err := s.db.Insert(ctx, TableHosts, h.row()); err != nil {
		return Host{}, "", err
	}
	return h, secret, nil
}

// hostByToken is the live host an enrolment token belongs to; ok is false for anything else. The
// row is found by the keyed hash and the token re-checked in constant time.
func (s *service) hostByToken(ctx context.Context, secret string) (Host, bool, error) {
	if !strings.HasPrefix(secret, HostTokenPrefix) {
		return Host{}, false, nil
	}
	row, err := s.db.FindOne(ctx, TableHosts, store.Criteria{"enrollment_token_hash": s.pepper.Hash(hostPepper, secret)})
	if err != nil || row == nil {
		return Host{}, false, err
	}
	h := hostFromRow(row)
	return h, s.pepper.Matches(hostPepper, secret, h.tokenHash) && h.RevokedAt == nil, nil
}

func (s *service) host(ctx context.Context, id string) (Host, bool, error) {
	row, err := s.db.FindOne(ctx, TableHosts, store.Criteria{"id": id})
	if err != nil || row == nil {
		return Host{}, false, err
	}
	return hostFromRow(row), true, nil
}

// liveHosts are the owner's hosts not revoked.
func (s *service) liveHosts(ctx context.Context, c store.Criteria) ([]Host, error) {
	c["revoked_at"] = nil
	rows, err := s.db.FindMany(ctx, TableHosts, c, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return nil, err
	}
	out := make([]Host, 0, len(rows))
	for _, r := range rows {
		out = append(out, hostFromRow(r))
	}
	return out, nil
}

// revokeHosts revokes the live hosts the criteria select (a conditional update: once).
func (s *service) revokeHosts(ctx context.Context, c store.Criteria) error {
	c["revoked_at"] = nil
	_, err := s.db.Update(ctx, TableHosts, c, store.Data{"revoked_at": s.now()})
	return err
}
