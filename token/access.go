package token

import (
	"errors"
	"log/slog"
	"time"
)

// ErrInvalidClaims reports an access-token claim set without a subject or token id.
var ErrInvalidClaims = errors.New("token: invalid access-token claims")

// AccessClaims is the Polaris access-token claim set (docs/auth/flows.md §6). The protocol
// claims (iss, aud, iat, exp, nbf) belong to the Codec and are absent here.
type AccessClaims struct {
	Subject        string   // sub, the user id; required
	ID             string   // jti, unique per token; required
	SessionID      string   // sid, the refresh family; emitted when set
	OrganizationID string   // org, the active organization; always emitted, null when empty
	Roles          []string // role slugs in the active org
	Scope          []string // flattened permission keys; emitted when non-empty
	EmailVerified  bool
	MFA            bool
	AMR            []string // authentication methods, e.g. ["pwd","otp"]
	AuthTime       *int64   // auth_time, Unix seconds; emitted when set
	// Extra claims a package adds (impersonated_by, act, cnf, …). They come first; a
	// standard claim of the same name wins.
	Extra Claims
}

// Claims renders the set in upstream's order: extra claims, then sub, jti, org, roles,
// email_verified, mfa, amr, and sid, scope, auth_time when set. It fails with
// ErrInvalidClaims when Subject or ID is empty.
func (a AccessClaims) Claims() (Claims, error) {
	if a.Subject == "" {
		return Claims{}, errors.Join(ErrInvalidClaims, errors.New("access-token subject (sub) must not be empty"))
	}
	if a.ID == "" {
		return Claims{}, errors.Join(ErrInvalidClaims, errors.New("access-token id (jti) must not be empty"))
	}
	var org any
	if a.OrganizationID != "" {
		org = a.OrganizationID
	}
	c := a.Extra.
		With("sub", a.Subject).
		With("jti", a.ID).
		With("org", org).
		With("roles", nonNil(a.Roles)).
		With("email_verified", a.EmailVerified).
		With("mfa", a.MFA).
		With("amr", nonNil(a.AMR))
	if a.SessionID != "" {
		c = c.With("sid", a.SessionID)
	}
	if len(a.Scope) > 0 {
		c = c.With("scope", a.Scope)
	}
	if a.AuthTime != nil {
		c = c.With("auth_time", *a.AuthTime)
	}
	return c, nil
}

// nonNil keeps an absent list encoding as [] (PHP's empty array), never null.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// SessionPrincipal is an authenticated identity and its session context: everything an
// access token carries except the session-specific jti and sid. A nil AMR means ["pwd"].
type SessionPrincipal struct {
	UserID         string
	OrganizationID string
	Roles          []string
	Scope          []string
	EmailVerified  bool
	MFA            bool
	AMR            []string
	AuthTime       *int64
}

// IssuedTokens is the result of issuing or refreshing a session: a short-lived access JWT and
// the opaque refresh secret (returned to the client exactly once; only its hash is stored).
// SessionID is the refresh family id, tying the access token to a device.
type IssuedTokens struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresIn  int // seconds
	RefreshExpiresAt time.Time
	SessionID        string
}

// LogValue keeps both bearer secrets out of logs.
func (t IssuedTokens) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("session_id", t.SessionID),
		slog.Int("access_expires_in", t.AccessExpiresIn),
		slog.Time("refresh_expires_at", t.RefreshExpiresAt),
	)
}

// String keeps both bearer secrets out of fmt output.
func (t IssuedTokens) String() string { return "token.IssuedTokens" + t.LogValue().String() }

// GoString keeps both bearer secrets out of %#v output.
func (t IssuedTokens) GoString() string { return t.String() }

// ClientContext is the device and network context of a token request, recorded on the
// refresh-token row and on reuse-detection events. The zero value is "no context".
type ClientContext struct {
	IP        string
	UserAgent string
}
