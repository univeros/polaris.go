package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
)

func none() Authority { return Authority{Roles: []string{}, Scope: []string{}} }

// Resolver resolves effective authority from the database:
//
//	effective(user, org) = every permission, when the user holds the system superadmin role
//	                       else ∪ of the permissions of the user's roles in org
//
// A disabled user resolves to nothing; so does a user with no active membership of org, an org
// that is not active, or no org. Superadmin is assigned out of band by linking any membership of
// the user to the global superadmin role. Safe for concurrent use.
type Resolver struct{ r *repository.Repos }

// NewResolver returns a Resolver over repos.
func NewResolver(repos *repository.Repos) *Resolver { return &Resolver{r: repos} }

// Resolve returns the authority of userID in organizationID ("" for no active organization).
func (s *Resolver) Resolve(ctx context.Context, userID, organizationID string) (Authority, error) {
	a, err := s.resolve(ctx, userID, organizationID)
	if err != nil {
		return Authority{}, fmt.Errorf("authz: resolve authority: %w", err)
	}
	return a, nil
}

func (s *Resolver) resolve(ctx context.Context, userID, organizationID string) (Authority, error) {
	user, err := s.r.Users.Get(ctx, userID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return Authority{}, err
	}
	if err == nil && user.Status == model.UserStatusDisabled {
		return none(), nil
	}
	super, err := s.isSuperadmin(ctx, userID)
	if err != nil {
		return Authority{}, err
	}
	if super {
		perms, err := s.r.Permissions.List(ctx)
		if err != nil {
			return Authority{}, err
		}
		scope := make([]string, 0, len(perms))
		for _, p := range perms {
			scope = append(scope, p.Key)
		}
		return Authority{Roles: []string{RoleSuperadmin}, Scope: scope}, nil
	}
	if organizationID == "" {
		return none(), nil
	}
	org, err := s.r.Organizations.Get(ctx, organizationID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return Authority{}, err
	}
	// An allow-list: any status but active (a future one included) grants nothing.
	if err == nil && org.Status != model.OrganizationStatusActive {
		return none(), nil
	}
	m, err := s.r.Memberships.ByUserAndOrganization(ctx, userID, organizationID)
	if errors.Is(err, repository.ErrNotFound) || (err == nil && m.Status != model.MembershipStatusActive) {
		return none(), nil
	}
	if err != nil {
		return Authority{}, err
	}
	links, err := s.r.MembershipRoles.ListByMembership(ctx, m.ID)
	if err != nil {
		return Authority{}, err
	}
	a := none()
	for _, l := range links {
		role, err := s.r.Roles.Get(ctx, l.RoleID)
		if errors.Is(err, repository.ErrNotFound) {
			continue
		}
		if err != nil {
			return Authority{}, err
		}
		// Only the system role (no organization) is the platform superadmin (isSuperadmin above);
		// an organization's own role with that slug is an ordinary role and must not carry the
		// override into the authority or the roles claim minted from it.
		if role.Slug == RoleSuperadmin {
			continue
		}
		if !slices.Contains(a.Roles, role.Slug) {
			a.Roles = append(a.Roles, role.Slug)
		}
	}
	keys, err := permissionKeysByID(ctx, s.r)
	if err != nil {
		return Authority{}, err
	}
	for _, l := range links {
		grants, err := s.r.RolePermissions.ListByRole(ctx, l.RoleID)
		if err != nil {
			return Authority{}, err
		}
		for _, g := range grants {
			if key, ok := keys[g.PermissionID]; ok && !slices.Contains(a.Scope, key) {
				a.Scope = append(a.Scope, key)
			}
		}
	}
	return a, nil
}

func (s *Resolver) isSuperadmin(ctx context.Context, userID string) (bool, error) {
	role, err := s.r.Roles.ByOrganizationAndSlug(ctx, nil, RoleSuperadmin)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	memberships, err := s.r.Memberships.ListByUser(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, m := range memberships {
		_, err := s.r.MembershipRoles.Get(ctx, m.ID, role.ID)
		if err == nil {
			return true, nil
		}
		if !errors.Is(err, repository.ErrNotFound) {
			return false, err
		}
	}
	return false, nil
}

func permissionKeysByID(ctx context.Context, r *repository.Repos) (map[string]string, error) {
	perms, err := r.Permissions.List(ctx)
	if err != nil {
		return nil, err
	}
	keys := make(map[string]string, len(perms))
	for _, p := range perms {
		keys[p.ID] = p.Key
	}
	return keys, nil
}
