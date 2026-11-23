// Package session runs the refresh-token session lifecycle: issuing a short-lived access JWT plus a
// rotating, opaque refresh token; refreshing with reuse detection; step-up and organization
// switches that re-mint without rotating; listing and revoking sessions. It also holds the
// access-token denylist and the login-MFA ticket.
//
// A session is a refresh family: auth_refresh_tokens rows sharing family_id, of which at most
// one is live (not revoked). Only the keyed hash (security.Pepper, context "refresh") of a
// refresh secret is stored; the plaintext is returned to the client once.
package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// ErrInvalidConfig reports a Config missing a dependency.
var ErrInvalidConfig = errors.New("session: invalid configuration")

const (
	pepperContext = "refresh"
	secretBytes   = 32 // 256-bit opaque refresh secret
)

// Issuer mints signed access tokens; *token.Codec is the implementation.
type Issuer interface {
	Issue(claims token.Claims) (string, error)
}

// PrincipalResolver resolves the authorization context (roles, scope, email_verified) of a user in
// an organization ("" for none) when a session's access token is minted again: on refresh, step-up
// and organization switch, so role changes apply within one access-token TTL. authz.Principals is
// the production implementation; UserPrincipals resolves identity only.
type PrincipalResolver interface {
	Resolve(ctx context.Context, userID, organizationID string) (token.SessionPrincipal, error)
}

// Config wires a Service. DB, Pepper, Access, Principals and Denylist are required.
type Config struct {
	DB         store.Adapter
	Pepper     *security.Pepper  // hashes refresh secrets (context "refresh")
	Access     Issuer            // mints access JWTs: the access-token *token.Codec
	Principals PrincipalResolver // authz.Principals in production
	// Denylist receives the per-user watermark of RevokeAll; pass the instance the denylist
	// middleware reads. It is written whether or not the denylist check is enabled.
	Denylist *Denylist
	// Auth supplies AccessToken.TTL and the RefreshToken settings; start from config.Defaults().
	Auth   config.Auth
	Clock  clock.Clock      // nil: clock.System
	Events event.Dispatcher // nil: event.Nop
	// Claims adds the host's claims to every access token Mint signs. A name another claim of the
	// token already uses, or one Polaris reserves (ReservedClaim), fails the mint. nil: none.
	Claims func(ctx context.Context, p token.SessionPrincipal) (map[string]any, error)
}

// Service issues, refreshes and revokes sessions. It is safe for concurrent use: the races that
// matter (two presentations of one refresh secret) are settled by conditional updates in the
// database, not by locks in the process.
type Service struct {
	db         store.Adapter
	tokens     repository.RefreshTokens
	pepper     *security.Pepper
	access     Issuer
	principals PrincipalResolver
	denylist   *Denylist
	auth       config.Auth
	clock      clock.Clock
	events     event.Dispatcher
	claims     func(ctx context.Context, p token.SessionPrincipal) (map[string]any, error)
}

// New validates cfg and returns a Service.
func New(cfg Config) (*Service, error) {
	var missing []string
	for _, c := range []struct {
		name   string
		absent bool
	}{
		{"DB", cfg.DB == nil}, {"Pepper", cfg.Pepper == nil}, {"Access", cfg.Access == nil},
		{"Principals", cfg.Principals == nil}, {"Denylist", cfg.Denylist == nil},
	} {
		if c.absent {
			missing = append(missing, "Config."+c.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s required", ErrInvalidConfig, strings.Join(missing, ", "))
	}
	s := &Service{
		db: cfg.DB, tokens: repository.New(cfg.DB).RefreshTokens, pepper: cfg.Pepper, access: cfg.Access,
		principals: cfg.Principals, denylist: cfg.Denylist, auth: cfg.Auth, clock: cfg.Clock, events: cfg.Events,
		claims: cfg.Claims,
	}
	if s.clock == nil {
		s.clock = clock.System{}
	}
	if s.events == nil {
		s.events = event.Nop{}
	}
	return s, nil
}

// Issue opens a session after authentication: the first refresh token of a new family and an
// access token bound to it (sid). How the user authenticated (MFA, AMR, auth time) is stored on
// the session so refreshes restore it. A disabled account opens none (ErrInvalidGrant).
func (s *Service) Issue(ctx context.Context, p token.SessionPrincipal, client token.ClientContext) (token.IssuedTokens, error) {
	now := s.now()
	secret, err := newSecret()
	if err != nil {
		return token.IssuedTokens{}, err
	}
	row := s.newRow(p.UserID, p.OrganizationID, repository.NewID(), nil, secret, client, now.Add(s.auth.RefreshToken.TTL), now)
	row.MFA = p.MFA
	row.AMR = ptr(strings.Join(amrOf(p), ","))
	row.AuthTime = p.AuthTime
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lockOpen(ctx, p.UserID); err != nil {
			return err
		}
		return s.tokens.Insert(ctx, row)
	})
	if err != nil {
		return token.IssuedTokens{}, fmt.Errorf("session: issue: %w", err)
	}
	access, err := s.Mint(ctx, p, row.FamilyID, token.Claims{})
	if err != nil {
		return token.IssuedTokens{}, err
	}
	return s.issued(access, secret, row.ExpiresAt, row.FamilyID), nil
}

// Refresh exchanges a refresh secret for a new pair, rotating it within its family (or, with
// rotation off, minting a new access token only). Roles and scope are re-resolved; the session's
// authentication context is carried forward.
//
// An unknown, expired or intentionally revoked token returns ErrInvalidGrant. A token already
// consumed by rotation, replayed (or losing a race against its own rotation), revokes the whole
// family, dispatches event.RefreshReuseDetected and returns ErrRefreshReuse; with reuse
// detection off it is a plain ErrInvalidGrant.
func (s *Service) Refresh(ctx context.Context, presented string, client token.ClientContext) (token.IssuedTokens, error) {
	now := s.now()
	current, err := s.tokens.ByTokenHash(ctx, s.pepper.Hash(pepperContext, presented))
	if errors.Is(err, repository.ErrNotFound) {
		return token.IssuedTokens{}, fmt.Errorf("%w: the refresh token is not recognized", ErrInvalidGrant)
	}
	if err != nil {
		return token.IssuedTokens{}, fmt.Errorf("session: refresh: %w", err)
	}
	if current.RevokedAt != nil {
		return token.IssuedTokens{}, s.revokedPresented(ctx, current, client, now)
	}
	if !current.ExpiresAt.After(now) {
		return token.IssuedTokens{}, fmt.Errorf("%w: the refresh token has expired", ErrInvalidGrant)
	}
	if !s.auth.RefreshToken.Rotation {
		return s.refreshInPlace(ctx, current, presented, now)
	}
	// Compare-and-swap on revoked_at: of two concurrent presentations exactly one claims the
	// rotation; the loser sees a just-rotated token and takes the replay path. The claim and the
	// child's insert share a transaction that holds the user's lock, so a revocation (every one
	// takes it) runs before the claim, which then fails, or after the child exists, which it ends.
	var (
		claimed   bool
		p         token.SessionPrincipal
		secret    string
		expiresAt time.Time
	)
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		err := s.lock(ctx, current.UserID)
		if err != nil {
			return err
		}
		if claimed, err = s.tokens.ClaimRotation(ctx, current.ID, now); err != nil || !claimed {
			return err
		}
		// The token as it was claimed: a step-up or an organization switch may have changed it since
		// it was read.
		if current, err = s.tokens.Get(ctx, current.ID); err != nil {
			return err
		}
		if p, err = s.resolveStored(ctx, current); err != nil {
			return err
		}
		if expiresAt, err = s.nextExpiry(ctx, current, now); err != nil {
			return err
		}
		if secret, err = newSecret(); err != nil {
			return err
		}
		next := s.newRow(current.UserID, deref(current.OrganizationID), current.FamilyID, &current.ID, secret,
			token.ClientContext{IP: or(client.IP, current.IP), UserAgent: or(client.UserAgent, current.UserAgent)}, expiresAt, now)
		next.MFA, next.AMR, next.AuthTime = current.MFA, current.AMR, current.AuthTime
		return s.tokens.Insert(ctx, next)
	})
	if err != nil {
		return token.IssuedTokens{}, fmt.Errorf("session: refresh: %w", err)
	}
	if !claimed {
		// Read again: rotated by another request, or ended on purpose. Outside the transaction: the
		// family revocation must commit even though this request fails.
		current, err = s.tokens.Get(ctx, current.ID)
		if errors.Is(err, repository.ErrNotFound) {
			return token.IssuedTokens{}, fmt.Errorf("%w: the refresh token is no longer valid", ErrInvalidGrant)
		}
		if err != nil {
			return token.IssuedTokens{}, fmt.Errorf("session: refresh: %w", err)
		}
		return token.IssuedTokens{}, s.revokedPresented(ctx, current, client, now)
	}
	access, err := s.Mint(ctx, p, current.FamilyID, token.Claims{})
	if err != nil {
		return token.IssuedTokens{}, err
	}
	s.events.Dispatch(ctx, event.TokenRefreshed{UserID: current.UserID, FamilyID: current.FamilyID})
	return s.issued(access, secret, expiresAt, current.FamilyID), nil
}

func (s *Service) refreshInPlace(ctx context.Context, current model.RefreshToken, presented string, now time.Time) (token.IssuedTokens, error) {
	// Conditional: a token revoked since it was read mints nothing.
	n, err := s.db.Update(ctx, "auth_refresh_tokens", store.Criteria{"id": current.ID, "revoked_at": nil}, store.Data{"last_used_at": now})
	if err != nil {
		return token.IssuedTokens{}, fmt.Errorf("session: refresh: %w", err)
	}
	if n == 0 {
		return token.IssuedTokens{}, fmt.Errorf("%w: the refresh token is no longer valid", ErrInvalidGrant)
	}
	if current, err = s.tokens.Get(ctx, current.ID); err != nil { // as it is now, not as it was read
		return token.IssuedTokens{}, fmt.Errorf("session: refresh: %w", err)
	}
	p, err := s.resolveStored(ctx, current)
	if err != nil {
		return token.IssuedTokens{}, err
	}
	access, err := s.Mint(ctx, p, current.FamilyID, token.Claims{})
	if err != nil {
		return token.IssuedTokens{}, err
	}
	s.events.Dispatch(ctx, event.TokenRefreshed{UserID: current.UserID, FamilyID: current.FamilyID})
	return s.issued(access, presented, current.ExpiresAt, current.FamilyID), nil
}

// revokedPresented handles a presented token that is already revoked. Only a token consumed by
// rotation, replayed, is the theft signature (family revoked, alert); a token ended on purpose
// (logout, admin, password change) is a plain invalid grant.
func (s *Service) revokedPresented(ctx context.Context, t model.RefreshToken, client token.ClientContext, now time.Time) error {
	if !s.auth.RefreshToken.ReuseDetection || deref(t.RevokedReason) != model.RevokedRotated {
		return fmt.Errorf("%w: the refresh token is no longer valid", ErrInvalidGrant)
	}
	if err := s.revoke(ctx, t.UserID, store.Criteria{"family_id": t.FamilyID}, model.RevokedReuseDetected, now); err != nil {
		return err
	}
	s.events.Dispatch(ctx, event.RefreshReuseDetected{
		UserID: t.UserID, FamilyID: t.FamilyID, IP: nullable(client.IP), UserAgent: nullable(client.UserAgent),
	})
	return ErrRefreshReuse
}

// StepUp mints an access token for a live session recording a fresh strong authentication
// (mfa=true, amr=["pwd","otp"], auth_time=now), with roles and scope re-resolved, and stores that
// context on the session so later refreshes keep it. No refresh token is rotated. A session with
// no live token (logged out) returns ErrInvalidGrant: a still-valid access token must not outlive
// its session's revocation.
func (s *Service) StepUp(ctx context.Context, userID, organizationID, sessionID string) (string, error) {
	p, err := s.principals.Resolve(ctx, userID, organizationID)
	if err != nil {
		return "", fmt.Errorf("session: step-up: %w", err)
	}
	authTime := s.now().Unix()
	_, err = s.change(ctx, userID, sessionID, func(active model.RefreshToken) (store.Data, error) {
		amr := []string{"pwd", "otp"}
		if organizationBound(deref(active.AMR)) {
			// A factor proved on a session an identity provider opened does not make it the account
			// holder's: it stays bound to its organization.
			amr = []string{token.AMRSSO, "otp"}
		}
		p.MFA, p.AMR, p.AuthTime = true, amr, &authTime
		return store.Data{"mfa": true, "amr": strings.Join(amr, ","), "auth_time": authTime}, nil
	})
	if err != nil {
		return "", err
	}
	return s.Mint(ctx, p, sessionID, token.Claims{})
}

// SwitchOrganization re-scopes a live session to organizationID: the live refresh token now
// points at it (so refreshes stay scoped there) and a new access token carries its roles and
// scope, with the session's stored authentication context. It dispatches
// event.OrganizationSwitched. The caller has already checked the user is an active member.
// A session with no live token returns ErrInvalidGrant.
func (s *Service) SwitchOrganization(ctx context.Context, userID, organizationID, sessionID string) (string, error) {
	active, err := s.change(ctx, userID, sessionID, func(active model.RefreshToken) (store.Data, error) {
		if organizationBound(deref(active.AMR)) && deref(active.OrganizationID) != organizationID {
			return nil, ErrOrganizationBound
		}
		return store.Data{"organization_id": organizationID}, nil
	})
	if err != nil {
		return "", err
	}
	after := active
	after.OrganizationID = &organizationID
	p, err := s.resolveStored(ctx, after)
	if err != nil {
		return "", err
	}
	access, err := s.Mint(ctx, p, sessionID, token.Claims{})
	if err != nil {
		return "", err
	}
	s.events.Dispatch(ctx, event.OrganizationSwitched{UserID: userID, FromOrganizationID: active.OrganizationID, ToOrganizationID: organizationID})
	return access, nil
}

// RevokeFamily revokes every live token of a session with reason (a model.Revoked* value). Tokens
// already revoked keep their original reason.
func (s *Service) RevokeFamily(ctx context.Context, familyID, reason string) error {
	row, err := s.tokens.FindOne(ctx, store.Criteria{"family_id": familyID})
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("session: revoke: %w", err)
	}
	return s.revoke(ctx, row.UserID, store.Criteria{"family_id": familyID}, reason, s.now())
}

// revoke ends the user's live tokens that match c, under the user's lock. One conditional UPDATE:
// only rows still live are touched, so an earlier rotation or revocation keeps its reason and
// nothing is resurrected.
func (s *Service) revoke(ctx context.Context, userID string, c store.Criteria, reason string, now time.Time) error {
	live := maps.Clone(c)
	live["user_id"], live["revoked_at"] = userID, nil
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lock(ctx, userID); err != nil {
			return err
		}
		_, err := s.db.Update(ctx, "auth_refresh_tokens", live, store.Data{"revoked_at": now, "revoked_reason": reason})
		return err
	})
	if err != nil {
		return fmt.Errorf("session: revoke: %w", err)
	}
	return nil
}

// lock makes opening, rotating and revoking a user's sessions run one after the other: a no-op
// UPDATE of the user's row takes its row lock on PostgreSQL and MySQL and the database's write lock
// on SQLite, held until the transaction in ctx ends; memstore transactions are serial already. It
// holds under PostgreSQL's read committed and MySQL's repeatable read. Everything locks the user
// before the user's tokens, and before an organization.
func (s *Service) lock(ctx context.Context, userID string) error {
	_, err := s.db.Update(ctx, "auth_users", store.Criteria{"id": userID}, store.Data{"id": userID})
	return err
}

// lockOpen is lock that refuses a disabled account, and one that does not exist. The status is a criterion of the locking UPDATE,
// so it is the current one whatever the transaction read before.
func (s *Service) lockOpen(ctx context.Context, userID string) error {
	n, err := s.db.Update(ctx, "auth_users", store.Criteria{"id": userID, "status": store.Ne(model.UserStatusDisabled)}, store.Data{"id": userID})
	if err != nil || n == 1 {
		return err
	}
	return fmt.Errorf("%w: the account is disabled, or none", ErrInvalidGrant)
}

// Mint signs an access token for p. With a sessionID it carries sid; without one it belongs to no
// session (it cannot be refreshed, stepped up, switched or logged out) and lives exactly the
// access-token TTL. extra claims (impersonated_by, act, …) ride along; standard claims win.
// auth_time is p's, never re-stamped: it is the last full authentication. Config.Claims adds the
// host's claims last.
func (s *Service) Mint(ctx context.Context, p token.SessionPrincipal, sessionID string, extra token.Claims) (string, error) {
	if slices.Contains(amrOf(p), token.AMRSSO) && slices.Contains(p.Roles, authz.RoleSuperadmin) {
		// A session an organization's identity provider opened never carries the platform
		// override (authz.Gate resolves it the same way): the token says so too.
		p.Roles, p.Scope = []string{}, nil
	}
	claims, err := token.AccessClaims{
		Subject: p.UserID, ID: repository.NewID(), SessionID: sessionID, OrganizationID: p.OrganizationID,
		Roles: p.Roles, Scope: p.Scope, EmailVerified: p.EmailVerified, MFA: p.MFA, AMR: amrOf(p),
		AuthTime: p.AuthTime, Extra: extra,
	}.Claims()
	if err != nil {
		return "", fmt.Errorf("session: mint: %w", err)
	}
	if claims, err = s.hostClaims(ctx, p, claims); err != nil {
		return "", fmt.Errorf("session: mint: %w", err)
	}
	raw, err := s.access.Issue(claims)
	if err != nil {
		return "", fmt.Errorf("session: mint: %w", err)
	}
	return raw, nil
}

// change writes what data answers to the session's live token, under the user's lock, so it is the
// token the session has then: not one a concurrent rotation replaced or a revocation ended. It
// returns the token as it was.
func (s *Service) change(ctx context.Context, userID, sessionID string, data func(active model.RefreshToken) (store.Data, error)) (model.RefreshToken, error) {
	var active model.RefreshToken
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		if err := s.lock(ctx, userID); err != nil {
			return fmt.Errorf("session: %w", err)
		}
		var err error
		if active, err = s.liveToken(ctx, sessionID); err != nil {
			return err
		}
		d, err := data(active)
		if err != nil {
			return err
		}
		n, err := s.db.Update(ctx, "auth_refresh_tokens", store.Criteria{"id": active.ID, "revoked_at": nil}, d)
		if err != nil {
			return fmt.Errorf("session: %w", err)
		}
		if n == 0 { // the caller's transaction reads an older snapshot
			return fmt.Errorf("%w: the session is no longer active", ErrInvalidGrant)
		}
		return nil
	})
	return active, err
}

// liveToken returns the session's unrevoked, unexpired token or ErrInvalidGrant.
func (s *Service) liveToken(ctx context.Context, sessionID string) (model.RefreshToken, error) {
	t, err := s.tokens.ActiveInFamily(ctx, sessionID)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && !t.ExpiresAt.After(s.now())) {
		return t, fmt.Errorf("%w: the session is no longer active", ErrInvalidGrant)
	}
	if err != nil {
		return t, fmt.Errorf("session: %w", err)
	}
	return t, nil
}

// resolveStored resolves the authorization context afresh and overlays the session's stored
// authentication context (a row with no AMR reads as ["pwd"]).
func (s *Service) resolveStored(ctx context.Context, t model.RefreshToken) (token.SessionPrincipal, error) {
	p, err := s.principals.Resolve(ctx, t.UserID, deref(t.OrganizationID))
	if err != nil {
		return p, fmt.Errorf("session: resolve principal: %w", err)
	}
	p.MFA, p.AMR, p.AuthTime = t.MFA, []string{"pwd"}, t.AuthTime
	if a := deref(t.AMR); a != "" {
		p.AMR = strings.Split(a, ",")
	}
	return p, nil
}

// nextExpiry is the family's fixed expiry (absolute mode), or now+TTL capped at the family's
// start + MaxLifetime (sliding mode).
func (s *Service) nextExpiry(ctx context.Context, current model.RefreshToken, now time.Time) (time.Time, error) {
	if !s.auth.RefreshToken.Sliding {
		return current.ExpiresAt, nil
	}
	start := current.CreatedAt
	root, err := s.tokens.FamilyRoot(ctx, current.FamilyID)
	switch {
	case err == nil:
		start = root.CreatedAt
	case !errors.Is(err, repository.ErrNotFound):
		return time.Time{}, err
	}
	candidate, limit := now.Add(s.auth.RefreshToken.TTL), start.Add(s.auth.RefreshToken.MaxLifetime)
	if candidate.Before(limit) {
		return candidate, nil
	}
	return limit, nil
}

func (s *Service) newRow(userID, organizationID, familyID string, parentID *string, secret string, client token.ClientContext, expiresAt, now time.Time) model.RefreshToken {
	return model.RefreshToken{
		ID: repository.NewID(), UserID: userID, OrganizationID: nullable(organizationID), FamilyID: familyID,
		ParentID: parentID, TokenHash: s.pepper.Hash(pepperContext, secret), UserAgent: nullable(client.UserAgent),
		IP: nullable(client.IP), ExpiresAt: expiresAt, CreatedAt: now,
	}
}

func (s *Service) issued(access, refresh string, refreshExpiresAt time.Time, sessionID string) token.IssuedTokens {
	return token.IssuedTokens{
		AccessToken: access, RefreshToken: refresh, AccessExpiresIn: int(s.auth.AccessToken.TTL / time.Second),
		RefreshExpiresAt: refreshExpiresAt, SessionID: sessionID,
	}
}

// now is the clock's time to the second: rows store seconds, and expiry comparisons must agree
// with what was stored.
func (s *Service) now() time.Time { return s.clock.Now().UTC().Truncate(time.Second) }

func newSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("session: random secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// organizationBound reports whether a session's stored amr ("sso", "sso,otp") is an identity
// provider's: see token.Token.OrganizationBound.
func organizationBound(amr string) bool {
	return slices.Contains(strings.Split(amr, ","), token.AMRSSO)
}

func amrOf(p token.SessionPrincipal) []string {
	if p.AMR == nil {
		return []string{"pwd"}
	}
	return p.AMR
}

func ptr[T any](v T) *T { return &v }

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func or(s string, fallback *string) string {
	if s != "" {
		return s
	}
	return deref(fallback)
}
