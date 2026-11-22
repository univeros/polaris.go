package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/token"
)

// Caller is who asks the Gate: an authenticated user and the active organization of the request.
//
// Delegated marks a principal a plugin's bearer resolver built for a delegate (an API key, an
// OAuth client, an agent), with DelegatedPermissions the permissions its owner handed it (decision
// #3). It is set in-process by the resolver, never read from a token on
// the wire; core sessions leave it false. A delegated caller with no permissions holds nothing.
type Caller struct {
	UserID               string
	OrganizationID       string // "" when no organization is active
	Delegated            bool
	DelegatedPermissions []string
}

// Gate is the programmatic authorization check: does the
// caller hold the required permissions in their active organization? Authority is re-resolved
// from the database on every call, so the superadmin override, disabling a user and suspending a
// membership or an organization apply at once. Safe for concurrent use.
type Gate struct{ resolver *Resolver }

// NewGate returns a Gate over resolver.
func NewGate(resolver *Resolver) *Gate { return &Gate{resolver: resolver} }

// Authority returns the caller's database-resolved authority. For a delegated caller the scope is
// the intersection of the owner's scope and DelegatedPermissions, and the roles are the owner's
// without superadmin: the global override, and the escalation and cross-organization exemptions
// that follow it, stay with the owner.
func (g *Gate) Authority(ctx context.Context, c Caller) (Authority, error) {
	a, err := g.resolver.Resolve(ctx, c.UserID, c.OrganizationID)
	if err != nil || !c.Delegated {
		return a, err
	}
	out := none()
	for _, r := range a.Roles {
		if r != RoleSuperadmin {
			out.Roles = append(out.Roles, r)
		}
	}
	for _, p := range a.Scope {
		if slices.Contains(c.DelegatedPermissions, p) {
			out.Scope = append(out.Scope, p)
		}
	}
	return out, nil
}

// Allows reports whether the caller holds every one of permissions.
func (g *Gate) Allows(ctx context.Context, c Caller, permissions ...string) (bool, error) {
	a, err := g.Authority(ctx, c)
	if err != nil {
		return false, err
	}
	return a.Allows(permissions...), nil
}

// Authorize returns a *ForbiddenError (MsgForbidden) when the caller lacks any of permissions.
func (g *Gate) Authorize(ctx context.Context, c Caller, permissions ...string) error {
	ok, err := g.Allows(ctx, c, permissions...)
	if err != nil {
		return err
	}
	if !ok {
		return Forbidden(MsgForbidden)
	}
	return nil
}

// EscalationGuard enforces no privilege escalation, shared by role changes
// and invitations: an actor may only grant what they hold themselves. A superadmin is exempt.
// Safe for concurrent use.
type EscalationGuard struct{ r *repository.Repos }

// NewEscalationGuard returns a guard over repos.
func NewEscalationGuard(repos *repository.Repos) *EscalationGuard { return &EscalationGuard{r: repos} }

// CheckRoles returns a *ForbiddenError (MsgEscalation) when any of roleIDs grants a permission
// actor does not hold.
func (g *EscalationGuard) CheckRoles(ctx context.Context, actor Authority, roleIDs []string) error {
	if actor.IsSuperadmin() {
		return nil
	}
	keys, err := permissionKeysByID(ctx, g.r)
	if err != nil {
		return fmt.Errorf("authz: escalation check: %w", err)
	}
	for _, id := range roleIDs {
		grants, err := g.r.RolePermissions.ListByRole(ctx, id)
		if err != nil {
			return fmt.Errorf("authz: escalation check: %w", err)
		}
		for _, gr := range grants {
			if key, ok := keys[gr.PermissionID]; ok && !slices.Contains(actor.Scope, key) {
				return Forbidden(MsgEscalation)
			}
		}
	}
	return nil
}

// CheckPermissions returns a *ForbiddenError (MsgEscalation) when any of permissionKeys is outside
// actor's own authority: putting it into a role (creating or editing one) would be
// self-escalation.
func (g *EscalationGuard) CheckPermissions(actor Authority, permissionKeys []string) error {
	if actor.IsSuperadmin() || actor.Allows(permissionKeys...) {
		return nil
	}
	return Forbidden(MsgEscalation)
}

// Principals resolves the session principal minted into access tokens: the user's email_verified flag and their role slugs in the
// active organization, plus the flattened permission keys when EmbedScope is on
// (config.AccessToken.EmbedScope). MFA, AMR and auth time are left at their zero values: the
// session service owns them. It satisfies session.PrincipalResolver. Safe for concurrent use.
type Principals struct {
	r          *repository.Repos
	resolver   *Resolver
	embedScope bool
}

// NewPrincipals returns the RBAC principal resolver.
func NewPrincipals(repos *repository.Repos, resolver *Resolver, embedScope bool) *Principals {
	return &Principals{r: repos, resolver: resolver, embedScope: embedScope}
}

// Resolve returns the principal of userID in organizationID ("" for none).
func (p *Principals) Resolve(ctx context.Context, userID, organizationID string) (token.SessionPrincipal, error) {
	verified, err := emailVerified(ctx, p.r, userID)
	if err != nil {
		return token.SessionPrincipal{}, err
	}
	a, err := p.resolver.Resolve(ctx, userID, organizationID)
	if err != nil {
		return token.SessionPrincipal{}, err
	}
	sp := token.SessionPrincipal{UserID: userID, OrganizationID: organizationID, Roles: a.Roles, EmailVerified: verified}
	if p.embedScope {
		sp.Scope = a.Scope
	}
	return sp, nil
}

func emailVerified(ctx context.Context, r *repository.Repos, userID string) (bool, error) {
	u, err := r.Users.Get(ctx, userID)
	if err == nil {
		return u.EmailVerifiedAt != nil, nil
	}
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	return false, fmt.Errorf("authz: resolve principal: %w", err)
}
