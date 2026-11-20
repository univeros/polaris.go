package scim

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/orgs"
	"github.com/univeros/polaris-go/store"
)

// A Polaris account is global, a directory belongs to one organization. A directory therefore
// changes an account's email, name and global status only when it owns the account: this
// connection created it and it belongs to no other organization. Every other account is changed
// through its membership in the connection's organization only (stricter than upstream, which let
// any organization's directory rename, disable or delete any account by email).

// VerifiedDomains is what a directory asks the sso plugin (found as g.Plugin("sso")): whether the
// organization verified domain. A directory links an existing account to its organization only
// when the account's email is on a verified domain; without sso there is none.
type VerifiedDomains interface {
	DomainVerified(ctx context.Context, organizationID, domain string) (bool, error)
}

// owns reports whether conn owns user: its provenance row was written with the user's own
// creation time (createUser writes both in one transaction) and the user is a member of no other
// organization.
func (d *directory) owns(ctx context.Context, conn Connection, user model.User) (bool, error) {
	row, err := d.db.FindOne(ctx, TableProvenance, store.Criteria{"organization_id": conn.OrganizationID, "user_id": user.ID, "connection_id": conn.ID})
	if err != nil || row == nil {
		return false, err
	}
	created, _ := row.Time("created_at")
	if !created.UTC().Truncate(time.Second).Equal(user.CreatedAt.UTC().Truncate(time.Second)) {
		return false, nil
	}
	memberships, err := d.repos.Memberships.ListByUser(ctx, user.ID)
	if err != nil {
		return false, err
	}
	for _, m := range memberships {
		if m.OrganizationID != conn.OrganizationID {
			return false, nil
		}
	}
	return true, nil
}

// mayLink reports whether an existing account with email may join conn's organization: its
// domain is one the organization verified.
func (d *directory) mayLink(ctx context.Context, conn Connection, email string) (bool, error) {
	v, ok := d.domains().(VerifiedDomains)
	_, domain, found := strings.Cut(email, "@")
	if !ok || !found {
		return false, nil
	}
	return v.DomainVerified(ctx, conn.OrganizationID, strings.ToLower(domain))
}

// active is what the directory sees as the user's active attribute: an enabled account whose
// membership in the organization is active.
func (d *directory) active(ctx context.Context, conn Connection, user model.User) (bool, error) {
	if user.Status == model.UserStatusDisabled {
		return false, nil
	}
	m, found, err := d.membership(ctx, conn, user.ID)
	return found && m.Status == model.MembershipStatusActive, err
}

// setMembershipActive suspends or reactivates the user's membership through the organizations
// service (last-active-owner guard, the organization's sessions revoked on suspension); an owned
// account that is disabled is enabled again.
func (d *directory) setMembershipActive(ctx context.Context, conn Connection, user model.User, active bool) error {
	status := model.MembershipStatusSuspended
	if active {
		status = model.MembershipStatusActive
	}
	if err := fromOrgs(d.orgs.SetMemberStatus(ctx, actor, conn.OrganizationID, user.ID, status)); err != nil {
		return err
	}
	if !active || user.Status != model.UserStatusDisabled {
		return nil
	}
	owned, err := d.owns(ctx, conn, user)
	if err != nil || !owned {
		return err
	}
	return d.identity.EnableUser(ctx, actor, user.ID)
}

// keepOwner runs fn under the organizations service's owner guarantee: an organization with an
// active owner keeps one.
func (d *directory) keepOwner(ctx context.Context, conn Connection, fn func(ctx context.Context) error) error {
	return fromOrgs(d.orgs.KeepOwner(ctx, conn.OrganizationID, fn))
}

// fromOrgs answers the organizations service's refusals as SCIM errors.
func fromOrgs(err error) error {
	var e *orgs.Error
	switch {
	case !errors.As(err, &e):
		return err
	case errors.Is(err, orgs.ErrConflict):
		return &Error{Status: 409, Detail: e.Message}
	case errors.Is(err, orgs.ErrNotFound):
		return notFound("User")
	}
	return &Error{Status: 400, Type: TypeInvalidValue, Detail: e.Message}
}
