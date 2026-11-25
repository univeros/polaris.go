package session

import (
	"context"
	"errors"
	"fmt"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

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
// with the denylist on every outstanding access token of the user dies with the sessions. The
// watermark also ends the tokens that belong to no session; the sessions' entries end one that a
// racing refresh signs after it.
func (s *Service) RevokeAll(ctx context.Context, userID, reason string) (int, error) {
	n, ended, err := s.endFamilies(ctx, userID, "", reason)
	if err != nil {
		return 0, err
	}
	if err := errors.Join(s.denylist.RevokeAllFor(ctx, userID), s.denylist.RevokeSessions(ctx, ended...)); err != nil {
		return 0, err
	}
	return n, nil
}

// RevokeAllExcept revokes every session of the user except exceptSessionID ("" keeps none) and
// returns how many sessions it touched (every family of the user, revoked ones included). With the
// denylist on their access tokens die too, session by session: the per-user watermark would kill the
// kept session's own. A token that belongs to no session therefore lives until it expires. It ends
// the login_mfa tickets issued before.
func (s *Service) RevokeAllExcept(ctx context.Context, userID, exceptSessionID, reason string) (int, error) {
	n, ended, err := s.endFamilies(ctx, userID, exceptSessionID, reason)
	if err != nil {
		return 0, err
	}
	return n, errors.Join(s.denylist.RevokeSessions(ctx, ended...), s.denylist.RevokeTicketsFor(ctx, userID))
}

// endFamilies ends every session of the user but except ("" for none), returning how many there
// were and those to record in the denylist. By user, not by the sessions it counted: one opened since
// is ended too.
func (s *Service) endFamilies(ctx context.Context, userID, except, reason string) (int, []string, error) {
	rows, err := s.tokens.ListByUser(ctx, userID)
	if err != nil {
		return 0, nil, fmt.Errorf("session: revoke: %w", err)
	}
	families := map[string]bool{}
	for _, t := range rows {
		if t.FamilyID != except {
			families[t.FamilyID] = true
		}
	}
	c := store.Criteria{}
	if except != "" {
		c["family_id"] = store.Ne(except)
	}
	ended, err := s.end(ctx, userID, c, reason, s.now())
	return len(families), ended, err
}

// RevokeAllForOrganization revokes the user's sessions whose current organization context is
// organizationID (an admin suspension cuts org access at once); sessions pointed elsewhere stay.
// Only live tokens identify a session's current context: rotated ancestors keep a stale one. With the
// denylist on the access tokens of the sessions it ends die too.
func (s *Service) RevokeAllForOrganization(ctx context.Context, userID, organizationID, reason string) error {
	return s.revoke(ctx, userID, store.Criteria{"organization_id": organizationID}, reason, s.now())
}

// Revoke revokes one session of the user (reason logout). With the denylist on its access tokens die
// too, also when it had ended before. It returns false, and revokes nothing, when no such session
// belongs to the user: the endpoint answers 404, never disclosing another user's session.
func (s *Service) Revoke(ctx context.Context, userID, sessionID string) (bool, error) {
	rows, err := s.tokens.ListByFamily(ctx, sessionID)
	if err != nil {
		return false, fmt.Errorf("session: revoke: %w", err)
	}
	for _, t := range rows {
		if t.UserID == userID {
			return true, s.revoke(ctx, userID, store.Criteria{"family_id": sessionID}, model.RevokedLogout, s.now())
		}
	}
	return false, nil
}
