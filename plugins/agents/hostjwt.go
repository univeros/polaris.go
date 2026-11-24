package agents

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/plugins/oauth"
	"github.com/univeros/polaris.go/store"
)

// thumbprintFormat is an RFC 7638 SHA-256 thumbprint, what a host JWT's iss must be.
var thumbprintFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// HostJWTType is the typ header of a host's JWT (Agent Auth Protocol §4.2).
const HostJWTType = "host+jwt"

// hostOf is the host a request authenticates as with a host JWT (§4.5.1), and the JWT's claims. The
// host is one somebody owns: an unknown key is refused.
func (s *service) hostOf(r *http.Request) (Host, map[string]any, error) {
	return s.hostCalling(r, false)
}

// hostCalling is hostOf where a host the server does not know may call (§2.8): to register, and to read
// that registration's status. Such a host has no ID: its JWT verifies with the key it presents, which
// its iss names, and that is all that is known of it.
func (s *service) hostCalling(r *http.Request, unknown bool) (Host, map[string]any, error) {
	ctx := r.Context()
	m := bearerOnly.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil {
		return Host{}, nil, invalidJWT("A host JWT (typ host+jwt) is required as the bearer.")
	}
	raw := m[1]
	peeked, ok := peekJWT(raw, HostJWTType)
	if !ok {
		return Host{}, nil, invalidJWT("The credential is not a host JWT (typ host+jwt).")
	}
	if err := noKeyHeader(peeked.header, "host"); err != nil {
		return Host{}, nil, err
	}
	if peeked.header["alg"] != AlgEdDSA {
		return Host{}, nil, invalidJWT("alg must be EdDSA.")
	}
	// Nothing read here is trusted before the signature verifies with the stored host's key; the
	// claims only say which host that is.
	unverified := decodeJSONSegment(strings.Split(raw, ".")[1])
	iss, _ := unverified["iss"].(string)
	if !thumbprintFormat.MatchString(iss) || unverified["aud"] != s.issuerJWTs.audience {
		return Host{}, nil, invalidJWT("iss must be the thumbprint of the signing key, and aud exactly the server's issuer.")
	}
	inline, hasKey := unverified["host_public_key"]
	url, hasURL := unverified["host_jwks_url"]
	if hasKey == hasURL {
		return Host{}, nil, invalidJWT("host_public_key or host_jwks_url is required, and only one of them.")
	}
	h, ok, err := s.hostNamed(ctx, iss, url)
	if err != nil {
		return Host{}, nil, err
	}
	if !ok {
		if h, err = s.unknownHost(inline, iss, unknown); err != nil {
			return Host{}, nil, err
		}
	}
	key, err := s.hostKey(ctx, h, peeked.header["kid"], inline, url)
	if err != nil {
		return Host{}, nil, err
	}
	if thumbprint, err := oauth.Thumbprint(key); err != nil || thumbprint != iss {
		return Host{}, nil, invalidJWT("iss must be the thumbprint of the signing key.")
	}
	claims, err := s.issuerJWTs.decode(raw, key)
	if err != nil {
		return Host{}, nil, invalidJWT("The JWT does not verify: " + err.Error())
	}
	if err := s.issuerJWTs.lifetime(claims); err != nil {
		return Host{}, nil, err
	}
	if err := s.issuerJWTs.once(ctx, iss, claims); err != nil {
		return Host{}, nil, err
	}
	if h.RevokedAt != nil {
		return Host{}, nil, refuse(ErrHostRevoked, "The host is revoked.")
	}
	if h.KeyThumbprint != iss { // a JWKS host signing with a new key (§4.5.1 step 3, §8.7)
		if err := s.renameHost(ctx, h, iss); err != nil {
			return Host{}, nil, err
		}
		h.KeyThumbprint = iss
	}
	return h, claims, nil
}

// unknownHost is the host a key the server does not know makes, when one is taken here. Its keys are in
// the JWT: an URL anyone may name is not fetched.
func (s *service) unknownHost(inline any, iss string, taken bool) (Host, error) {
	if !s.settings.dynamicHosts {
		return Host{}, invalidJWT("The host is unknown: its owner registers its key with POST /agents/hosts.")
	}
	if !taken {
		return Host{}, invalidJWT("The host is unknown until a person approves its registration.")
	}
	jwk, err := protocolKey(inline)
	if err != nil {
		return Host{}, invalidJWT("The host is unknown: it registers with host_public_key, an Ed25519 public key in its canonical form.")
	}
	if thumbprint, err := oauth.Thumbprint(jwk); err != nil || thumbprint != iss {
		return Host{}, invalidJWT("iss must be the thumbprint of the signing key.")
	}
	return Host{PublicJWK: jwk, KeyThumbprint: iss}, nil
}

// hostNamed is the host a thumbprint names, else the one the JWKS URL names (§4.5.1 step 3).
func (s *service) hostNamed(ctx context.Context, thumbprint string, url any) (Host, bool, error) {
	row, err := s.db.FindOne(ctx, TableHosts, store.Criteria{"key_thumbprint": thumbprint})
	if u, invalid := jwksURL(url); err == nil && row == nil && invalid == nil {
		row, err = s.db.FindOne(ctx, TableHosts, store.Criteria{"jwks_url": u})
	}
	if err != nil || row == nil {
		return Host{}, false, err
	}
	return hostFromRow(row), true, nil
}

// hostKey is the key the host signs with, delivered as it was registered (§8.7): the stored one, or
// the one kid names in its key set.
func (s *service) hostKey(ctx context.Context, h Host, kid, inline, url any) (map[string]any, error) {
	if h.JWKSURL == "" {
		jwk, ok := inline.(map[string]any)
		if !ok {
			return nil, invalidJWT("The host was registered with its key: host_public_key is required.")
		}
		// The stored key verifies; the claim must be the same key.
		if t, err := oauth.Thumbprint(jwk); err != nil || t != h.KeyThumbprint {
			return nil, invalidJWT("host_public_key is not the host's key.")
		}
		return h.PublicJWK, nil
	}
	if url != h.JWKSURL {
		return nil, invalidJWT("The host was registered with another JWKS URL.")
	}
	id, _ := kid.(string)
	if id == "" {
		return nil, invalidJWT("kid is required with a JWKS URL.")
	}
	if !s.settings.jwksURLs {
		return nil, invalidJWT("JWKS URLs are turned off on this server.")
	}
	if h.RevokedAt != nil { // before its URL is fetched
		return nil, refuse(ErrHostRevoked, "The host is revoked.")
	}
	key, err := s.jwks.key(ctx, h.JWKSURL, id)
	if err != nil {
		return nil, invalidJWT("The host's key could not be read: " + err.Error() + ".")
	}
	if key, err = protocolKey(key); err != nil {
		return nil, invalidJWT("The host's key must be an Ed25519 key in its canonical form.")
	}
	return key, nil
}

// renameHost stores a JWKS host's new thumbprint.
func (s *service) renameHost(ctx context.Context, h Host, thumbprint string) error {
	_, err := s.db.Update(ctx, TableHosts, store.Criteria{"id": h.ID}, store.Data{"key_thumbprint": thumbprint})
	if errors.Is(err, store.ErrDuplicate) {
		return invalidJWT("The key belongs to another host.")
	}
	return err
}

// checkHost is §4.5 steps 4 and 5 for an agent's JWT on the protocol routes: its host is not revoked,
// and iss, when the JWT has one, is the host's thumbprint (for a JWKS host, of any key of its set).
func (s *service) checkHost(ctx context.Context, a Agent, iss any, hasISS bool) error {
	var h Host
	if a.HostID != "" {
		var ok bool
		var err error
		if h, ok, err = s.host(ctx, a.HostID); err != nil {
			return err
		}
		if ok && h.hasKey() && h.RevokedAt != nil {
			return refuse(ErrHostRevoked, "The agent's host is revoked.")
		}
		if !ok && a.ofHostJWT() {
			return invalidJWT("The agent's host is unknown.")
		}
	}
	if !hasISS {
		return nil
	}
	named, _ := iss.(string)
	if named != "" && named == h.KeyThumbprint {
		return nil
	}
	if named != "" && h.JWKSURL != "" && s.settings.jwksURLs {
		keys, err := s.jwks.keys(ctx, h.JWKSURL, false)
		if err == nil && slices.ContainsFunc(keys, func(k map[string]any) bool {
			if k, err := protocolKey(k); err == nil {
				t, err := oauth.Thumbprint(k)
				return err == nil && t == named
			}
			return false
		}) {
			return nil
		}
	}
	return invalidJWT("iss is not the thumbprint of the agent's host.")
}
