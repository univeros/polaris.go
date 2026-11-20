package token

import (
	"fmt"
	"time"
)

// Mint signs a non-session JWT (an OAuth at+jwt access token, an OpenID ID token) with the
// Codec's key and kid, as upstream's OAuth Jwt::mint. The header is {"typ":typ,"alg":…,"kid":…}
// (typ "" means "JWT"); the payload starts with iss, iat and nbf (now) and exp (expiresAt, at
// microsecond precision), then claims in order. Caller iss/iat/nbf/exp are dropped; sub and
// jti must be strings; aud is a string or a list of strings (a one-element list is written as
// a string). The configured Audience and TTL do not apply.
func (c *Codec) Mint(typ string, claims Claims, expiresAt time.Time) (string, error) {
	if c.sign == nil {
		return "", fmt.Errorf("%w: a private key is required to sign a token (set AUTH_JWT_PRIVATE_KEY)", ErrInvalidConfig)
	}
	if typ == "" {
		typ = "JWT"
	}
	now := c.now()
	payload := Claims{}.
		With("iss", c.issuer).
		With("iat", encodeInstant(now)).
		With("nbf", encodeInstant(now)).
		With("exp", encodeInstant(expiresAt))
	payload, err := appendClaims(payload, claims, map[string]bool{"iss": true, "iat": true, "nbf": true, "exp": true})
	if err != nil {
		return "", err
	}
	return c.signJWT(typ, payload)
}

// Sign signs a JWS with no managed time claims, as upstream's agents receipt signature: the
// header is {"typ":typ,"alg":…,"kid":…} (typ "" means "JWT"), the payload {"iss":…} followed by
// claims in order. A time.Time iat, nbf or exp is written as lcobucci/jwt writes dates (whole
// seconds as an integer, otherwise seconds.micros); any other value as given. Caller iss is
// dropped; sub, jti and aud follow Mint's rules. VerifyJWT accepts the result (an absent exp
// never expires).
func (c *Codec) Sign(typ string, claims Claims) (string, error) {
	if c.sign == nil {
		return "", fmt.Errorf("%w: a private key is required to sign a token (set AUTH_JWT_PRIVATE_KEY)", ErrInvalidConfig)
	}
	if typ == "" {
		typ = "JWT"
	}
	payload, err := appendClaims(Claims{}.With("iss", c.issuer), claims, map[string]bool{"iss": true})
	if err != nil {
		return "", err
	}
	return c.signJWT(typ, payload)
}

// appendClaims routes caller claims onto payload as lcobucci's builder does: managed names
// are dropped, sub and jti must be strings, aud goes through permittedFor, iat/nbf/exp given
// as time.Time are encoded as dates.
func appendClaims(payload, claims Claims, managed map[string]bool) (Claims, error) {
	for _, name := range claims.names {
		value := claims.values[name]
		if managed[name] {
			continue
		}
		switch name {
		case "":
			// Upstream would emit an empty key no parser accepts; refuse instead.
			return Claims{}, fmt.Errorf("%w: empty claim name", errUnencodable)
		case "sub", "jti":
			if _, ok := value.(string); !ok {
				return Claims{}, fmt.Errorf("%w: claim %q must be a string, got %T", errUnencodable, name, value)
			}
		case "aud":
			aud, err := mintAudience(value)
			if err != nil {
				return Claims{}, err
			}
			value = aud
		case "iat", "nbf", "exp":
			if t, ok := value.(time.Time); ok {
				value = encodeInstant(t)
			}
		}
		payload = payload.With(name, value)
	}
	return payload, nil
}

// mintAudience is lcobucci's permittedFor over an empty set followed by UnifyAudience:
// duplicates are kept and a single audience is written as a string.
func mintAudience(v any) (any, error) {
	var list []string
	switch v := v.(type) {
	case string:
		return v, nil
	case []string:
		list = v
	case []any:
		list = make([]string, 0, len(v))
		for _, e := range v {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("%w: aud entries must be strings, got %T", errUnencodable, e)
			}
			list = append(list, s)
		}
	default:
		return nil, fmt.Errorf("%w: aud must be a string or a list of strings, got %T", errUnencodable, v)
	}
	if len(list) == 1 {
		return list[0], nil
	}
	return nonNil(list), nil
}

// VerifyJWT verifies a JWT this server signed for a non-session purpose, as upstream's OAuth
// Jwt::verify: structure, algorithm, signature, issuer and the validity window widened by
// leeway (iat and nbf at most now+leeway, exp after now-leeway). There is no audience, typ or
// purpose rule: callers check Header("typ") and the claims they need.
//
// The key is chosen by kid: the previous kid (during a rotation) verifies with the previous
// public key; an absent or null kid, or the current kid, with the current key; any other kid
// is refused. Failures wrap ErrInvalidToken; a negative leeway is ErrInvalidConfig.
func (c *Codec) VerifyJWT(raw string, leeway time.Duration) (*Token, error) {
	if leeway < 0 {
		return nil, fmt.Errorf("%w: the leeway cannot be negative", ErrInvalidConfig)
	}
	seg, err := splitToken(raw)
	if err != nil {
		return nil, err
	}
	verify := c.verify
	switch kid := seg.header["kid"].(type) {
	case nil:
	case string:
		if c.prevVer != nil && kid == c.prevKID {
			verify = c.prevVer
		} else if kid != c.kid {
			return nil, invalid("the token names an unknown signing key")
		}
	default:
		return nil, invalid("the token names an unknown signing key")
	}
	if alg, _ := seg.header["alg"].(string); alg != string(c.alg) {
		return nil, invalid("token signer mismatch")
	}
	if !verify([]byte(seg.signingInput), seg.signature) {
		return nil, invalid("token signature mismatch")
	}
	if iss, ok := seg.claims["iss"].(string); !ok || iss != c.issuer {
		return nil, invalid("the token was not issued by the given issuers")
	}
	if err := checkWindow(seg.claims, c.now(), leeway); err != nil {
		return nil, err
	}
	return &Token{raw: raw, header: seg.header, claims: seg.claims}, nil
}
