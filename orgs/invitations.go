package orgs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"slices"
	"time"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
)

// Messages of the invitation refusals.
const (
	MsgRolesRequired        = "At least one role is required."
	MsgAlreadyMember        = "That user is already an active member of this organization."
	MsgMemberSuspended      = "That user's membership is suspended; reactivate it instead."
	MsgInvitationNotFound   = "No such pending invitation."
	MsgInvalidInvitation    = "The invitation is invalid or has expired."
	MsgInvitationEmail      = "The invitation was issued to a different email address."
	MsgOwnMembershipSuspend = "Your membership in this organization is suspended."
)

// InvitationTTL is how long an invitation can be accepted.
const InvitationTTL = 7 * 24 * time.Hour

const (
	invitePepperContext = "org_invite"
	invitationsTable    = "auth_invitations"
	inviteSecretBytes   = 32
)

// Invitation is a pending invitation as listed.
type Invitation struct {
	ID        string
	Email     string
	RoleSlugs []string
	InvitedBy string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Invite invites email (normalized: trimmed, ASCII-lowercased) into the organization with
// roleSlugs, or refreshes the pending invitation of that email, rotating its token and expiry
// (one pending invitation per email per organization). The token, a 256-bit random secret, is
// stored only as its keyed hash and travels once, in plaintext, on event.MemberInvited for the
// mailer. The invitee may have no account yet.
//
// The escalation check runs now, against the inviter's current authority: demoting the inviter
// later does not retract the invitation. Refusals, in order: ErrInvalid (an unknown slug, or
// none), ErrConflict (an active or suspended member: a suspension is lifted by a status change,
// never by an invitation), forbidden (escalation).
func (s *Service) Invite(ctx context.Context, actorUserID, organizationID, email string, roleSlugs []string) (Invitation, error) {
	email = normalizeEmail(email)
	token := newInviteToken()
	now := s.clock.Now()
	var inv model.Invitation
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		roleIDs := make([]string, 0, len(roleSlugs))
		for _, slug := range roleSlugs {
			role, err := s.r.Roles.ByOrganizationAndSlug(ctx, &organizationID, slug)
			if ok, err := found(err); err != nil {
				return err
			} else if !ok {
				return refuse(ErrInvalid, msgUnknownRole+slug)
			}
			roleIDs = append(roleIDs, role.ID)
		}
		if len(roleIDs) == 0 {
			return refuse(ErrInvalid, MsgRolesRequired)
		}
		if err := s.refuseMember(ctx, organizationID, email); err != nil {
			return err
		}
		actor, err := s.resolver.Resolve(ctx, actorUserID, organizationID)
		if err != nil {
			return err
		}
		if err := s.guard.CheckRoles(ctx, actor, roleIDs); err != nil {
			return err
		}
		pending, exists, err := s.pendingInvitation(ctx, organizationID, email)
		if err != nil {
			return err
		}
		inv = pending
		if !exists {
			inv = model.Invitation{ID: repository.NewID(), OrganizationID: organizationID, Email: email, CreatedAt: now}
		}
		inv.RoleIDs = roleIDs
		inv.TokenHash = s.pepper.Hash(invitePepperContext, token)
		inv.InvitedBy = actorUserID
		inv.ExpiresAt = now.Add(InvitationTTL)
		if exists {
			return s.r.Invitations.Update(ctx, pending, inv)
		}
		return s.r.Invitations.Insert(ctx, inv)
	})
	if err != nil {
		return Invitation{}, wrap("invite", err)
	}
	s.events.Dispatch(ctx, event.MemberInvited{OrganizationID: organizationID, Email: email, InvitedBy: actorUserID, InviteToken: token})
	return Invitation{
		ID: inv.ID, Email: inv.Email, RoleSlugs: slices.Clone(roleSlugs), InvitedBy: inv.InvitedBy,
		ExpiresAt: inv.ExpiresAt, CreatedAt: inv.CreatedAt,
	}, nil
}

// refuseMember refuses inviting the email of an active or suspended member.
func (s *Service) refuseMember(ctx context.Context, organizationID, email string) error {
	user, err := s.r.Users.ByEmail(ctx, email)
	if ok, err := found(err); !ok {
		return err
	}
	m, err := s.r.Memberships.ByUserAndOrganization(ctx, user.ID, organizationID)
	if ok, err := found(err); !ok {
		return err
	}
	switch m.Status {
	case model.MembershipStatusActive:
		return refuse(ErrConflict, MsgAlreadyMember)
	case model.MembershipStatusSuspended:
		return refuse(ErrConflict, MsgMemberSuspended)
	}
	return nil
}

// pendingInvitation returns the email's unaccepted invitation to the organization, expired or
// not: an expired one is recycled.
func (s *Service) pendingInvitation(ctx context.Context, organizationID, email string) (model.Invitation, bool, error) {
	invs, err := s.r.Invitations.ListByOrganizationAndEmail(ctx, organizationID, email)
	if err != nil {
		return model.Invitation{}, false, err
	}
	for _, inv := range invs {
		if inv.AcceptedAt == nil {
			return inv, true, nil
		}
	}
	return model.Invitation{}, false, nil
}

// ListInvitations returns the organization's pending invitations: not accepted, not expired.
func (s *Service) ListInvitations(ctx context.Context, organizationID string) ([]Invitation, error) {
	invs, err := s.r.Invitations.ListByOrganization(ctx, organizationID)
	if err != nil {
		return nil, wrap("list invitations", err)
	}
	now := s.clock.Now()
	pending := []Invitation{}
	for _, inv := range invs {
		if inv.AcceptedAt != nil || !inv.ExpiresAt.After(now) {
			continue
		}
		slugs, err := s.roleSlugs(ctx, inv.RoleIDs)
		if err != nil {
			return nil, wrap("list invitations", err)
		}
		pending = append(pending, Invitation{
			ID: inv.ID, Email: inv.Email, RoleSlugs: slugs, InvitedBy: inv.InvitedBy,
			ExpiresAt: inv.ExpiresAt, CreatedAt: inv.CreatedAt,
		})
	}
	return pending, nil
}

// RevokeInvitation deletes an unaccepted invitation of the organization. Another organization's
// invitation, an accepted one or an unknown id is ErrNotFound.
func (s *Service) RevokeInvitation(ctx context.Context, organizationID, invitationID string) error {
	inv, err := s.r.Invitations.Get(ctx, invitationID)
	if ok, err := found(err); err != nil {
		return wrap("revoke invitation", err)
	} else if !ok || inv.OrganizationID != organizationID || inv.AcceptedAt != nil {
		return refuse(ErrNotFound, MsgInvitationNotFound)
	}
	return wrap("revoke invitation", s.r.Invitations.Delete(ctx, inv))
}

// AcceptInvitation lets userID accept the invitation of token: their membership is created, or an
// invited one activated, with the invited roles added to any they hold (roles deleted since are
// skipped), and the invitation is spent. It returns the organization joined and dispatches
// event.MemberJoined.
//
// An unknown, spent or expired token, an organization no longer active and an unknown user are
// all ErrInvalidInvitation, indistinguishably. A user whose email is not the invitee's, or whose
// membership is suspended (only members.update lifts a suspension), is forbidden.
func (s *Service) AcceptInvitation(ctx context.Context, userID, token string) (string, error) {
	var inv model.Invitation
	var user model.User
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		now := s.clock.Now()
		var err error
		if inv, err = s.claimInvitation(ctx, token, now); err != nil {
			return err
		}
		if user, err = s.acceptingUser(ctx, inv, userID); err != nil {
			return err // rolls the claim back
		}
		membership, err := s.joiningMembership(ctx, inv, userID, now)
		if err != nil {
			return err
		}
		return s.grantInvitedRoles(ctx, membership.ID, inv.RoleIDs)
	})
	if err != nil {
		return "", wrap("accept invitation", err)
	}
	s.events.Dispatch(ctx, event.MemberJoined{OrganizationID: inv.OrganizationID, UserID: userID, Email: user.Email})
	return inv.OrganizationID, nil
}

// claimInvitation spends the unaccepted, unexpired invitation of token with one conditional
// UPDATE, the first statement of the accept transaction: of concurrent accepts of one token,
// exactly one claims it (the others wait for its write lock, then match no row) and the rest
// are ErrInvalidInvitation. It returns the claimed invitation.
func (s *Service) claimInvitation(ctx context.Context, token string, now time.Time) (model.Invitation, error) {
	invalid := refuse(ErrInvalidInvitation, MsgInvalidInvitation)
	hash := s.pepper.Hash(invitePepperContext, token)
	at := now.UTC().Truncate(time.Second) // the stored precision
	n, err := s.db.Update(ctx, invitationsTable,
		store.Criteria{"token_hash": hash, "accepted_at": nil, "expires_at": store.Gt(at)},
		store.Data{"accepted_at": at})
	if err != nil {
		return model.Invitation{}, err
	}
	if n != 1 {
		return model.Invitation{}, invalid
	}
	return s.r.Invitations.ByTokenHash(ctx, hash)
}

// acceptingUser checks the claimed invitation can make userID a member and returns the user.
func (s *Service) acceptingUser(ctx context.Context, inv model.Invitation, userID string) (model.User, error) {
	invalid := refuse(ErrInvalidInvitation, MsgInvalidInvitation)
	// An invitation into a soft-deleted organization must not create rows that would go live on a
	// restore.
	org, err := s.r.Organizations.Get(ctx, inv.OrganizationID)
	if ok, err := found(err); !ok || org.Status != model.OrganizationStatusActive {
		return model.User{}, orElse(err, invalid)
	}
	user, err := s.r.Users.Get(ctx, userID)
	if ok, err := found(err); !ok {
		return user, orElse(err, invalid)
	}
	if normalizeEmail(user.Email) != inv.Email {
		return user, authz.Forbidden(MsgInvitationEmail)
	}
	return user, nil
}

// joiningMembership activates the user's invited membership or creates an active one.
func (s *Service) joiningMembership(ctx context.Context, inv model.Invitation, userID string, now time.Time) (model.Membership, error) {
	m, err := s.r.Memberships.ByUserAndOrganization(ctx, userID, inv.OrganizationID)
	exists, err := found(err)
	if err != nil {
		return m, err
	}
	if !exists {
		m = model.Membership{
			ID: repository.NewID(), UserID: userID, OrganizationID: inv.OrganizationID,
			InvitedBy: &inv.InvitedBy, CreatedAt: now,
		}
	} else if m.Status == model.MembershipStatusSuspended {
		return m, authz.Forbidden(MsgOwnMembershipSuspend)
	}
	joined := m
	joined.Status = model.MembershipStatusActive
	if joined.JoinedAt == nil {
		joined.JoinedAt = &now
	}
	joined.UpdatedAt = now
	if exists {
		return joined, s.r.Memberships.Update(ctx, m, joined)
	}
	return joined, s.r.Memberships.Insert(ctx, joined)
}

func (s *Service) grantInvitedRoles(ctx context.Context, membershipID string, roleIDs []string) error {
	links, err := s.r.MembershipRoles.ListByMembership(ctx, membershipID)
	if err != nil {
		return err
	}
	held := make([]string, 0, len(links)+len(roleIDs))
	for _, link := range links {
		held = append(held, link.RoleID)
	}
	for _, roleID := range roleIDs {
		if slices.Contains(held, roleID) {
			continue
		}
		// A role deleted between invite and accept is skipped.
		_, err := s.r.Roles.Get(ctx, roleID)
		if ok, err := found(err); err != nil {
			return err
		} else if !ok {
			continue
		}
		if err := s.r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: membershipID, RoleID: roleID}); err != nil {
			return err
		}
		held = append(held, roleID)
	}
	return nil
}

// roleSlugs maps role ids to slugs, skipping roles that no longer exist.
func (s *Service) roleSlugs(ctx context.Context, roleIDs []string) ([]string, error) {
	slugs := make([]string, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := s.r.Roles.Get(ctx, id)
		if ok, err := found(err); err != nil {
			return nil, err
		} else if ok {
			slugs = append(slugs, role.Slug)
		}
	}
	return slugs, nil
}

// newInviteToken returns 32 random bytes, base64url without padding.
func newInviteToken() string {
	b := make([]byte, inviteSecretBytes)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return base64.RawURLEncoding.EncodeToString(b)
}

// orElse returns err when it is not nil, else fallback.
func orElse(err, fallback error) error {
	if err != nil {
		return err
	}
	return fallback
}
