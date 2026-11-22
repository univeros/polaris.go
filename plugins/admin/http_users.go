package admin

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/mfa"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

const msgNoUser = "The user does not exist."

var userStatuses = []string{model.UserStatusActive, model.UserStatusDisabled, model.UserStatusLocked}

// roleOrder ranks the operator roles, lowest first.
var roleOrder = []Role{RoleViewer, RoleSupport, RoleAdmin, RoleOwner}

// manageUser is Authorize(ctx, Manage, "") for a route that changes the account userID (ban,
// unban, password, MFA, delete): besides the capability, an operator below owner may not touch
// the account of a superadmin or of an operator whose grant is of its own role or above; changing
// that account's password or factors would be taking its role. An owner manages every account.
// A superadmin counts whatever the account's status, so a disabled one cannot be unbanned from
// below. An unknown userID passes: the route answers its own 404.
func (p *Plugin) manageUser(ctx context.Context, userID string) (Principal, endpoint.Result, bool) {
	op, res, ok := Authorize(ctx, Manage, "")
	if !ok || op.Role == RoleOwner {
		return op, res, ok
	}
	protected, err := p.isSuperadmin(ctx, userID)
	if err == nil && !protected {
		var grant Grant
		var held bool
		grant, held, err = p.grants.For(ctx, userID)
		protected = held && slices.Index(roleOrder, grant.Role) >= slices.Index(roleOrder, op.Role)
	}
	if err != nil {
		return Principal{}, p.fail(ctx, "authorize", err), false
	}
	if protected {
		return Principal{}, Forbidden("Only an owner manages the account of a superadmin or of an operator of your role or above."), false
	}
	return op, endpoint.Result{}, true
}

// isSuperadmin reports whether the user holds core's global superadmin role, whatever the
// account's status (the authority resolver grants a disabled user nothing, superadmin included).
func (p *Plugin) isSuperadmin(ctx context.Context, userID string) (bool, error) {
	repos := p.g.Repos()
	role, err := repos.Roles.ByOrganizationAndSlug(ctx, nil, authz.RoleSuperadmin)
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	memberships, err := repos.Memberships.ListByUser(ctx, userID)
	if err != nil {
		return false, err
	}
	for _, m := range memberships {
		if _, err := repos.MembershipRoles.Get(ctx, m.ID, role.ID); err == nil {
			return true, nil
		} else if !errors.Is(err, repository.ErrNotFound) {
			return false, err
		}
	}
	return false, nil
}

// user loads the user of a route, or the 404 (or 500) to answer.
func (p *Plugin) user(ctx context.Context, userID string) (model.User, endpoint.Result, bool) {
	u, err := p.g.Repos().Users.Get(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return u, NotFound(msgNoUser), false
	}
	if err != nil {
		return u, p.fail(ctx, "load user", err), false
	}
	return u, endpoint.Result{}, true
}

// userView is the operator's view of a user, with the last activity the audit plugin saw.
func (p *Plugin) userView(ctx context.Context, u model.User) (map[string]any, error) {
	var lastActive any
	if t, seen, err := p.audit.Activity().LastActiveAt(ctx, u.ID); err != nil {
		return nil, err
	} else if seen {
		lastActive = atom(&t)
	}
	return map[string]any{
		"id": u.ID, "email": u.Email, "display_name": u.DisplayName, "status": cmp.Or(u.Status, model.UserStatusActive),
		"email_verified": u.EmailVerifiedAt != nil, "mfa_enforced": u.MFAEnforced, "locked_until": atom(u.LockedUntil),
		"created_at": timestamp(u.CreatedAt), "last_login_at": atom(u.LastLoginAt), "last_active_at": lastActive,
	}, nil
}

// listUsers answers GET /admin/users: oldest first, filtered by exact email and status.
func (p *Plugin) listUsers(ctx context.Context, in *endpoint.Input) endpoint.Result {
	if _, res, ok := Authorize(ctx, Read, ""); !ok {
		return res
	}
	st := in.String("status")
	if st != "" && !slices.Contains(userStatuses, st) {
		return Invalid("status must be active, disabled or locked.")
	}
	limit, valid := positiveInt(in.Value("limit"), DefaultLimit)
	if !valid {
		return Invalid("limit must be a positive integer.")
	}
	c := store.Criteria{}
	if email := in.String("email"); email != "" {
		c["email"] = email
	}
	if st != "" {
		c["status"] = st
	}
	if cursor := in.String("cursor"); cursor != "" {
		c["id"] = store.Gt(cursor)
	}
	rows, err := p.g.Repos().Users.Find(ctx, c, store.Query{OrderBy: []store.Order{{Column: "id"}}, Limit: limit + 1})
	if err != nil {
		return p.fail(ctx, "list users", err)
	}
	users, next := pageOf(rows, limit, func(u model.User) string { return u.ID })
	data := make([]any, 0, len(users))
	for _, u := range users {
		view, err := p.userView(ctx, u)
		if err != nil {
			return p.fail(ctx, "list users", err)
		}
		data = append(data, view)
	}
	return endpoint.JSON(http.StatusOK, map[string]any{"data": data, "next_cursor": next})
}

// readUser answers GET /admin/users/{id}.
func (p *Plugin) readUser(ctx context.Context, in *endpoint.Input) endpoint.Result {
	if _, res, ok := Authorize(ctx, Read, ""); !ok {
		return res
	}
	u, res, found := p.user(ctx, in.String("id"))
	if !found {
		return res
	}
	view, err := p.userView(ctx, u)
	if err != nil {
		return p.fail(ctx, "read user", err)
	}
	return success(view)
}

// identityRefusal maps core's user administration refusals.
func (p *Plugin) identityRefusal(ctx context.Context, what string, err error) endpoint.Result {
	switch {
	case errors.Is(err, identity.ErrConflict):
		return Conflict(err.Error())
	case errors.Is(err, identity.ErrUserNotFound):
		return NotFound(err.Error())
	}
	return p.fail(ctx, what, err)
}

// banUser answers POST /admin/users/{id}/ban: core's disable, every session ends.
func (p *Plugin) banUser(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := p.manageUser(ctx, in.String("id"))
	if !ok {
		return res
	}
	userID := in.String("id")
	if err := p.g.Identity().DisableUser(ctx, op.ID, userID); err != nil {
		return p.identityRefusal(ctx, "ban user", err)
	}
	return p.recorded(ctx, status(model.UserStatusDisabled), AuditUserBanned, op, userID, "", nil)
}

// unbanUser answers POST /admin/users/{id}/unban: core's enable, the lockout cleared.
func (p *Plugin) unbanUser(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := p.manageUser(ctx, in.String("id"))
	if !ok {
		return res
	}
	userID := in.String("id")
	if err := p.g.Identity().EnableUser(ctx, op.ID, userID); err != nil {
		return p.identityRefusal(ctx, "unban user", err)
	}
	return p.recorded(ctx, status(model.UserStatusActive), AuditUserUnbanned, op, userID, "", nil)
}

// setPassword answers POST /admin/users/{id}/password: a password under the policy, as a reset
// sets it (every session ends, event.PasswordChanged with method reset).
func (p *Plugin) setPassword(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := p.manageUser(ctx, in.String("id"))
	if !ok {
		return res
	}
	password := in.String("password")
	if password == "" {
		return Invalid("password is required.")
	}
	u, res, found := p.user(ctx, in.String("id"))
	if !found {
		return res
	}
	var violations *identity.PasswordError
	if err := p.g.Identity().SetPassword(ctx, u.ID, password); errors.As(err, &violations) {
		return Invalid("The password does not meet the policy.", violations.Violations...)
	} else if err != nil {
		return p.fail(ctx, "set password", err)
	}
	return p.recorded(ctx, status("password_set"), AuditPasswordSet, op, u.ID, "", nil)
}

// deleteUser answers DELETE /admin/users/{id}: core's anonymisation.
func (p *Plugin) deleteUser(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := p.manageUser(ctx, in.String("id"))
	if !ok {
		return res
	}
	userID := in.String("id")
	if userID == op.ID {
		return Conflict("You cannot delete your own account.")
	}
	if err := p.g.Identity().AnonymizeUser(ctx, op.ID, userID); err != nil {
		return p.identityRefusal(ctx, "delete user", err)
	}
	return p.recorded(ctx, status("deleted"), AuditUserDeleted, op, userID, "", nil)
}

// impersonate answers POST /admin/users/{id}/impersonate: an access token acting as the user for
// one access-token lifetime, with no session behind it (no refresh, step-up, switch or logout).
func (p *Plugin) impersonate(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := Authorize(ctx, Impersonate, "")
	if !ok {
		return res
	}
	u, res, found := p.user(ctx, in.String("id"))
	if !found {
		return res
	}
	if cmp.Or(u.Status, model.UserStatusActive) != model.UserStatusActive {
		return Conflict("The account is not active.")
	}
	base, err := p.g.Principals().Resolve(ctx, u.ID, "")
	if err != nil {
		return p.fail(ctx, "impersonate", err)
	}
	if slices.Contains(base.Roles, authz.RoleSuperadmin) {
		return problem(http.StatusForbidden, "impersonation_denied", "Impersonation denied", "A superadmin cannot be impersonated.")
	}
	authTime := p.g.Clock().Now().Unix()
	access, err := p.g.Sessions().Mint(ctx, token.SessionPrincipal{
		UserID: u.ID, Roles: base.Roles, Scope: base.Scope, EmailVerified: base.EmailVerified,
		AMR: []string{AMRImpersonation}, AuthTime: &authTime,
	}, "", token.Claims{}.With(ClaimImpersonatedBy, op.ID).With(ClaimImpersonatorType, op.Type))
	if err != nil {
		return p.fail(ctx, "impersonate", err)
	}
	ttl := int(p.g.Auth().AccessToken.TTL.Seconds())
	data := map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": ttl, "impersonated_by": op.ID}
	return p.recorded(ctx, endpoint.Data(http.StatusCreated, data), AuditUserImpersonated, op, u.ID, "", map[string]any{"expires_in": ttl})
}

// listSessions answers GET /admin/users/{id}/sessions: the active sessions.
func (p *Plugin) listSessions(ctx context.Context, in *endpoint.Input) endpoint.Result {
	if _, res, ok := Authorize(ctx, Read, ""); !ok {
		return res
	}
	u, res, found := p.user(ctx, in.String("id"))
	if !found {
		return res
	}
	infos, err := p.g.Sessions().List(ctx, u.ID, "")
	if err != nil {
		return p.fail(ctx, "list sessions", err)
	}
	out := make([]any, 0, len(infos))
	for _, s := range infos {
		out = append(out, map[string]any{
			"id": s.ID, "current": s.Current, "ip": s.IP, "user_agent": s.UserAgent,
			"created_at": atom(&s.CreatedAt), "last_used_at": atom(&s.LastUsedAt),
		})
	}
	return success(out)
}

// revokeSession answers DELETE /admin/users/{id}/sessions/{sessionId}.
func (p *Plugin) revokeSession(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := Authorize(ctx, Support, "")
	if !ok {
		return res
	}
	userID, sessionID := in.String("id"), in.String("sessionId")
	revoked, err := p.g.Sessions().Revoke(ctx, userID, sessionID)
	if err != nil {
		return p.fail(ctx, "revoke session", err)
	}
	if !revoked {
		return NotFound("The session does not exist for this user.")
	}
	return p.recorded(ctx, status("revoked"), AuditSessionRevoked, op, userID, "", map[string]any{"session_id": sessionID})
}

// revokeAllSessions answers DELETE /admin/users/{id}/sessions.
func (p *Plugin) revokeAllSessions(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := Authorize(ctx, Support, "")
	if !ok {
		return res
	}
	u, res, found := p.user(ctx, in.String("id"))
	if !found {
		return res
	}
	n, err := p.g.Sessions().RevokeAll(ctx, u.ID, model.RevokedAdmin)
	if err != nil {
		return p.fail(ctx, "revoke sessions", err)
	}
	return p.recorded(ctx, success(map[string]any{"status": "revoked", "count": n}), AuditSessionsRevoked, op, u.ID, "", map[string]any{"count": n})
}

// listFactors answers GET /admin/users/{id}/mfa: the factors without secrets or destinations.
func (p *Plugin) listFactors(ctx context.Context, in *endpoint.Input) endpoint.Result {
	if _, res, ok := Authorize(ctx, Read, ""); !ok {
		return res
	}
	u, res, found := p.user(ctx, in.String("id"))
	if !found {
		return res
	}
	factors, err := p.g.MFA().Factors(ctx, u.ID)
	if err != nil {
		return p.fail(ctx, "list factors", err)
	}
	out := make([]any, 0, len(factors))
	for _, f := range factors {
		out = append(out, map[string]any{
			"id": f.ID, "type": f.Type, "label": f.Label, "is_default": f.IsDefault,
			"confirmed_at": atom(f.ConfirmedAt), "last_used_at": atom(f.LastUsedAt), "created_at": timestamp(f.CreatedAt),
		})
	}
	return success(out)
}

// removeFactor answers DELETE /admin/users/{id}/mfa/{factorId}; the last confirmed factor under
// enforced MFA stays (reset instead).
func (p *Plugin) removeFactor(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := p.manageUser(ctx, in.String("id"))
	if !ok {
		return res
	}
	userID, factorID := in.String("id"), in.String("factorId")
	err := p.g.MFA().RemoveFactor(ctx, userID, factorID)
	var refusal *mfa.PolicyError
	switch {
	case errors.Is(err, mfa.ErrFactorNotFound):
		return NotFound("MFA factor not found.")
	case errors.As(err, &refusal) && errors.Is(err, mfa.ErrLastFactorProtected):
		return Conflict(refusal.Message)
	case err != nil:
		return p.fail(ctx, "remove factor", err)
	}
	return p.recorded(ctx, status("removed"), AuditMFAFactorRemoved, op, userID, "", map[string]any{"factor_id": factorID})
}

// resetMFA answers DELETE /admin/users/{id}/mfa: every factor and recovery code removed, enforced
// MFA or not, so a locked-out user enrols again at their next sign-in.
func (p *Plugin) resetMFA(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := p.manageUser(ctx, in.String("id"))
	if !ok {
		return res
	}
	u, res, found := p.user(ctx, in.String("id"))
	if !found {
		return res
	}
	var removed []model.MFAFactor
	err := p.g.DB().Tx(ctx, func(ctx context.Context) error {
		var err error
		if removed, err = p.g.Repos().MFAFactors.ListByUser(ctx, u.ID); err != nil {
			return err
		}
		if _, err = p.g.Repos().MFAFactors.DeleteByUser(ctx, u.ID); err != nil {
			return err
		}
		_, err = p.g.DB().Delete(ctx, "auth_recovery_codes", store.Criteria{"user_id": u.ID})
		return err
	})
	if err != nil {
		return p.fail(ctx, "reset mfa", err)
	}
	for _, f := range removed {
		p.g.Events().Dispatch(ctx, event.MFAFactorRemoved{UserID: u.ID, FactorID: f.ID})
	}
	n := len(removed)
	return p.recorded(ctx, success(map[string]any{"status": "reset", "factors": n}), AuditMFAReset, op, u.ID, "", map[string]any{"factors": n})
}
