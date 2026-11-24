package agents

import (
	"context"
	"strings"

	"github.com/univeros/polaris.go/plugins/oauth"
)

// HostLinkJWTType is the typ header of the proof POST /agents/hosts takes with a key: a JWT signed by it
// whose sub is the account that is to own the host. A type of its own, because a host JWT says nothing of
// the account, and a server a client was lured to may hold one for this server (§8.9).
const HostLinkJWTType = "host-link+jwt"

// hostLinkMaxAge is the most seconds a host link JWT lives: the owner carries it by hand.
const hostLinkMaxAge = 300

// proven is h once proof shows that whoever holds its key wants its owner to own it; a host without a key
// has nothing to prove. Without it, anyone could register a public key they know and own what the agents
// of that host do. A host that publishes its keys is known by the one that signed.
func (s *service) proven(ctx context.Context, h Host, proof any) (Host, error) {
	if !h.hasKey() {
		return h, nil
	}
	raw, _ := proof.(string)
	thumbprint, err := s.hostLink(ctx, h, raw)
	if e, ok := asError(err); ok {
		return h, refuse(ErrInvalidInput, "proof is a JWT (typ "+HostLinkJWTType+") signed by the host's key, whose sub is the account that will own the host: "+e.Detail)
	}
	if err != nil {
		return h, err
	}
	h.KeyThumbprint = thumbprint
	return h, nil
}

// hostLink is the thumbprint of the key that signed a host link JWT for h.
func (s *service) hostLink(ctx context.Context, h Host, raw string) (string, error) {
	peeked, ok := peekJWT(raw, HostLinkJWTType)
	if !ok {
		return "", invalidJWT("It is missing or of another type.")
	}
	if err := noKeyHeader(peeked.header, "host"); err != nil {
		return "", err
	}
	if peeked.header["alg"] != AlgEdDSA {
		return "", invalidJWT("alg must be EdDSA.")
	}
	// Before a key set is fetched; the signature covers them.
	iss, _ := peeked.iss.(string)
	unverified := decodeJSONSegment(strings.Split(raw, ".")[1])
	if !thumbprintFormat.MatchString(iss) || unverified["aud"] != s.linkJWTs.audience || peeked.sub != h.OwnerID {
		return "", invalidJWT("iss must be the thumbprint of the signing key, aud exactly the server's issuer, and sub the owner's id.")
	}
	if err := s.linkJWTs.lifetime(unverified); err != nil {
		return "", err
	}
	key, err := s.hostKey(ctx, h, peeked.header["kid"], h.PublicJWK, h.JWKSURL)
	if _, refused := asError(err); refused { // not why: it would tell the caller what a URL serves
		return "", invalidJWT("The host's key could not be read.")
	}
	if err != nil {
		return "", err
	}
	if thumbprint, err := oauth.Thumbprint(key); err != nil || thumbprint != iss {
		return "", invalidJWT("iss must be the thumbprint of the signing key.")
	}
	claims, err := s.linkJWTs.decode(raw, key)
	if err != nil {
		return "", invalidJWT("It does not verify: " + err.Error() + ".")
	}
	return iss, s.linkJWTs.once(ctx, iss, claims)
}
