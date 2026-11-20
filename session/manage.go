package session

import (
	"context"
	"fmt"
	"time"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/token"
)

// Info is one active session (device) of a user, as GET /auth/sessions lists it.
type Info struct {
	ID         string // the session id (refresh family)
	Current    bool   // the calling session
	IP         *string
	UserAgent  *string
	CreatedAt  time.Time // when the session was opened (its first token)
	LastUsedAt time.Time // last refresh, or creation of the live token
}

// List returns the user's active sessions (a live, unexpired token), in the order their first
// token is stored; currentSessionID flags the caller's own.
func (s *Service) List(ctx context.Context, userID, currentSessionID string) ([]Info, error) {
	now := s.now()
	rows, err := s.tokens.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("session: list: %w", err)
	}
	type family struct{ root, active *model.RefreshToken }
	var order []string
	families := map[string]*family{}
	for i := range rows {
		t := &rows[i]
		f, ok := families[t.FamilyID]
		if !ok {
			f = &family{root: t}
			families[t.FamilyID] = f
			order = append(order, t.FamilyID)
		}
		if t.ParentID == nil {
			f.root = t
		}
		if t.RevokedAt == nil && t.ExpiresAt.After(now) {
			f.active = t
		}
	}
	out := []Info{}
	for _, id := range order {
		f := families[id]
		if f.active == nil {
			continue
		}
		last := f.active.CreatedAt
		if f.active.LastUsedAt != nil {
			last = *f.active.LastUsedAt
		}
		out = append(out, Info{
			ID: id, Current: id == currentSessionID, IP: f.active.IP, UserAgent: f.active.UserAgent,
			CreatedAt: f.root.CreatedAt, LastUsedAt: last,
		})
	}
	return out, nil
}

// Logout revokes the caller's session (the sid of its access token).
func (s *Service) Logout(ctx context.Context, sessionID string) error {
	return s.RevokeFamily(ctx, sessionID, model.RevokedLogout)
}

// LogoutAll revokes every session of the user (logout everywhere), watermarks the denylist and
// dispatches event.SessionsRevoked.
func (s *Service) LogoutAll(ctx context.Context, userID string, client token.ClientContext) error {
	n, err := s.RevokeAll(ctx, userID, model.RevokedLogout)
	if err != nil {
		return err
	}
	s.events.Dispatch(ctx, event.SessionsRevoked{UserID: userID, IP: nullable(client.IP), Count: n, Reason: model.RevokedLogout})
	return nil
}

// RevokeAll revokes every session of the user with reason and returns how many sessions there
// were; no event (the password flows use it). It also watermarks the access-token denylist, so
// with the denylist on every outstanding access token of the user dies with the sessions.
func (s *Service) RevokeAll(ctx context.Context, userID, reason string) (int, error) {
	n, err := s.RevokeAllExcept(ctx, userID, "", reason)
	if err != nil {
		return 0, err
	}
	if err := s.denylist.RevokeAllFor(ctx, userID); err != nil {
		return 0, err
	}
	return n, nil
}

// RevokeAllExcept revokes every session of the user except exceptSessionID ("" keeps none) and
// returns how many sessions it touched (every family of the user, revoked ones included, as
// upstream counts). It does not watermark the denylist: that would kill the kept session's own
// access token.
func (s *Service) RevokeAllExcept(ctx context.Context, userID, exceptSessionID, reason string) (int, error) {
	rows, err := s.tokens.ListByUser(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("session: revoke: %w", err)
	}
	return s.revokeFamilies(ctx, rows, reason, func(t model.RefreshToken) bool {
		return exceptSessionID == "" || t.FamilyID != exceptSessionID
	})
}

// RevokeAllForOrganization revokes the user's sessions whose current organization context is
// organizationID (an admin suspension cuts org access at once); sessions pointed elsewhere stay.
// Only live tokens identify a session's current context: rotated ancestors keep a stale one.
func (s *Service) RevokeAllForOrganization(ctx context.Context, userID, organizationID, reason string) error {
	rows, err := s.tokens.ListByUserAndOrganization(ctx, userID, organizationID)
	if err != nil {
		return fmt.Errorf("session: revoke: %w", err)
	}
	_, err = s.revokeFamilies(ctx, rows, reason, func(t model.RefreshToken) bool { return t.RevokedAt == nil })
	return err
}

// Revoke revokes one session of the user (reason logout). It returns false, and revokes nothing,
// when no such session belongs to the user: the endpoint answers 404, never disclosing another
// user's session.
func (s *Service) Revoke(ctx context.Context, userID, sessionID string) (bool, error) {
	rows, err := s.tokens.ListByFamily(ctx, sessionID)
	if err != nil {
		return false, fmt.Errorf("session: revoke: %w", err)
	}
	for _, t := range rows {
		if t.UserID == userID {
			return true, s.RevokeFamily(ctx, sessionID, model.RevokedLogout)
		}
	}
	return false, nil
}

// revokeFamilies revokes each distinct family among rows that keep accepts, returning how many.
func (s *Service) revokeFamilies(ctx context.Context, rows []model.RefreshToken, reason string, keep func(model.RefreshToken) bool) (int, error) {
	seen := map[string]bool{}
	for _, t := range rows {
		if seen[t.FamilyID] || !keep(t) {
			continue
		}
		seen[t.FamilyID] = true
		if err := s.RevokeFamily(ctx, t.FamilyID, reason); err != nil {
			return 0, err
		}
	}
	return len(seen), nil
}
