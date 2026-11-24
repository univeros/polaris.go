package agents

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"strings"

	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

const (
	// HostTokenPrefix starts every host enrolment token.
	HostTokenPrefix = "peh_"
	hostPepper      = "agent_host"
	maxDefaults     = 50
)

// createHost creates a host for the owner with its enrolment token, shown once and stored as a
// keyed hash. An owner with a key (withKey) makes a host that signs with it and has no token.
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
	if h.ID == "" {
		h.ID = newID()
	}
	h.Name, h.CreatedAt, h.tokenHash = n, s.now(), s.pepper.Hash(hostPepper, secret)
	if h.hasKey() {
		secret = "" // never shown: the stored hash matches nothing anyone holds
	}
	if err := s.db.Insert(ctx, TableHosts, h.row()); err != nil {
		if h.hasKey() && errors.Is(err, store.ErrDuplicate) {
			return Host{}, "", refuse(ErrConflict, "The key or the JWKS URL belongs to a host already, live or revoked.")
		}
		return Host{}, "", err
	}
	return h, secret, nil
}

// withKey is the host with the key its owner gave: an Ed25519 public key, or the URL the host
// publishes its keys at (§2.8, §4.1); neither makes a host with an enrolment token.
func (s *service) withKey(h Host, publicKey, url any) (Host, error) {
	switch {
	case publicKey != nil && url != nil:
		return h, refuse(ErrInvalidInput, "public_key or jwks_url, not both.")
	case publicKey != nil:
		jwk, err := protocolKey(publicKey)
		if err != nil {
			return h, refuse(ErrInvalidInput, "public_key is an Ed25519 public key as a JWK (kty OKP, crv Ed25519, x), without its private part.")
		}
		h.PublicJWK = jwk
		if h.KeyThumbprint, err = oauth.Thumbprint(jwk); err != nil {
			return h, err
		}
	case url != nil:
		if !s.settings.jwksURLs {
			return h, refuse(ErrInvalidInput, "jwks_url is not taken by this server; register the host with its public_key.")
		}
		u, err := jwksURL(url)
		if err != nil {
			return h, err
		}
		h.JWKSURL = u
	}
	return h, nil
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

// revokeHosts revokes the live hosts the criteria select (a conditional update: once), and with a
// host that has a key every agent under it (§2.11, §8.5). The agents a token enrolled stay, as their
// own credentials do.
func (s *service) revokeHosts(ctx context.Context, c store.Criteria) error {
	return s.db.Tx(ctx, func(ctx context.Context) error {
		live := maps.Clone(c)
		live["revoked_at"] = nil
		// The first statement: it waits for a registration in flight, which holds the host's row
		// (lockHost), so what is read next (MySQL's snapshot too) has its agent; a later one finds the
		// host revoked.
		if _, err := s.db.Update(ctx, TableHosts, live, store.Data{"revoked_at": s.now()}); err != nil {
			return err
		}
		rows, err := s.db.FindMany(ctx, TableHosts, c, store.Query{OrderBy: []store.Order{{Column: "id"}}})
		if err != nil {
			return err
		}
		for _, row := range rows { // one revoked before has no agent left to revoke
			h := hostFromRow(row)
			if !h.hasKey() {
				continue
			}
			agents, err := s.agentsWhere(ctx, store.Criteria{"host_id": h.ID, "status": []string{StatusActive, StatusSuspended, StatusPending}})
			if err != nil {
				return err
			}
			for _, a := range agents {
				if _, _, err := s.revoke(ctx, a, "", "host_revoked", client{}); err != nil {
					if e, ok := asError(err); !ok || e.Type != ErrConflict { // revoked meanwhile
						return err
					}
				}
			}
		}
		return nil
	})
}

// lockHost serializes a registration with the host's revocation: it takes the live host's row lock, as
// lockAgent does, and must be the transaction's first statement.
func (s *service) lockHost(ctx context.Context, id string) error {
	n, err := s.db.Update(ctx, TableHosts, store.Criteria{"id": id, "revoked_at": nil}, store.Data{"id": id})
	if err == nil && n != 1 {
		err = refuse(ErrHostRevoked, "The host is revoked.")
	}
	return err
}
