package httpapi

import (
	"context"
	"net/http"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/orgs"
	"github.com/univeros/polaris-go/token"
	"github.com/univeros/polaris-go/wiring"
)

// Members, invitations and roles of the path organization (the cross-tenant guard already passed).

const (
	orgMsgTargetRequired = "A target user is required."
	orgMsgRoleSlugs      = "role_slugs must be an array of role slugs."
	orgMsgPermissionKeys = "permission_keys must be an array of permission keys."
	orgMsgRoleIDRequired = "A role id is required."
)

func (a orgAPI) listMembers(ctx context.Context, _ *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	// Superadmins resolve to the whole catalog, so they need no exemption here.
	authority, _ := wiring.Authority(ctx)
	members, err := a.g.Orgs().ListMembers(ctx, orgID, authority.Allows(authz.MembersInvite))
	if err != nil {
		return a.fail(ctx, err)
	}
	data := make([]map[string]any, 0, len(members))
	for _, m := range members {
		data = append(data, map[string]any{
			"user_id":      m.UserID,
			"email":        m.Email,
			"display_name": m.DisplayName,
			"status":       m.Status,
			"roles":        orgList(m.Roles),
		})
	}
	return endpoint.Data(http.StatusOK, data)
}

func (a orgAPI) changeMemberRoles(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	target := in.String("userId")
	if target == "" {
		return endpoint.Unprocessable([]string{orgMsgTargetRequired})
	}
	slugs, ok := orgStringList(in.Value("role_slugs"))
	if !ok {
		return endpoint.Unprocessable([]string{orgMsgRoleSlugs})
	}
	if err := a.g.Orgs().ChangeMemberRoles(ctx, tok.Subject(), orgID, target, slugs); err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"user_id": target, "roles": slugs})
}

func (a orgAPI) changeMemberStatus(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	target := in.String("userId")
	if target == "" {
		return endpoint.Unprocessable([]string{orgMsgTargetRequired})
	}
	status := in.String("status")
	if status == "" {
		return endpoint.Unprocessable([]string{orgs.MsgBadStatus})
	}
	if err := a.g.Orgs().ChangeMemberStatus(ctx, tok.Subject(), orgID, target, status); err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"user_id": target, "status": status})
}

func (a orgAPI) removeMember(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	target := in.String("userId")
	if target == "" {
		return endpoint.Unprocessable([]string{orgMsgTargetRequired})
	}
	if err := a.g.Orgs().RemoveMember(ctx, tok.Subject(), orgID, target); err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"removed": true})
}

func (a orgAPI) invite(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	email, ok := in.Value("email").(string)
	if !ok || !manifest.IsEmail(email) { // IsEmail also caps the length at 320 bytes
		return endpoint.Unprocessable([]string{"A valid email is required."})
	}
	slugs, ok := orgStringList(in.Value("role_slugs"))
	if !ok {
		return endpoint.Unprocessable([]string{orgMsgRoleSlugs})
	}
	inv, err := a.g.Orgs().Invite(ctx, tok.Subject(), orgID, email, slugs)
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusCreated, map[string]any{
		"id":         inv.ID,
		"email":      inv.Email,
		"role_slugs": orgList(inv.RoleSlugs),
		"expires_at": orgTime(inv.ExpiresAt),
	})
}

func (a orgAPI) listInvites(ctx context.Context, _ *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	list, err := a.g.Orgs().ListInvitations(ctx, orgID)
	if err != nil {
		return a.fail(ctx, err)
	}
	data := make([]map[string]any, 0, len(list))
	for _, inv := range list {
		data = append(data, map[string]any{
			"id":         inv.ID,
			"email":      inv.Email,
			"role_slugs": orgList(inv.RoleSlugs),
			"invited_by": inv.InvitedBy,
			"expires_at": orgTime(inv.ExpiresAt),
			"created_at": orgTime(inv.CreatedAt),
		})
	}
	return endpoint.Data(http.StatusOK, data)
}

func (a orgAPI) revokeInvite(ctx context.Context, in *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	inviteID := in.String("inviteId")
	if inviteID == "" {
		return endpoint.Unprocessable([]string{"An invitation id is required."})
	}
	if err := a.g.Orgs().RevokeInvitation(ctx, orgID, inviteID); err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"revoked": true})
}

func orgRoleView(r orgs.Role) map[string]any {
	return map[string]any{
		"id":              r.ID,
		"name":            r.Name,
		"slug":            r.Slug,
		"description":     r.Description,
		"is_system":       r.IsSystem,
		"permission_keys": orgList(r.PermissionKeys),
	}
}

func (a orgAPI) listRoles(ctx context.Context, _ *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	roles, err := a.g.Orgs().ListRoles(ctx, orgID)
	if err != nil {
		return a.fail(ctx, err)
	}
	data := make([]map[string]any, 0, len(roles))
	for _, r := range roles {
		data = append(data, orgRoleView(r))
	}
	return endpoint.Data(http.StatusOK, data)
}

func (a orgAPI) createRole(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	name, okName := in.Value("name").(string)
	slug, okSlug := in.Value("slug").(string)
	if !okName || !okSlug {
		return endpoint.Unprocessable([]string{"A name and a slug are required."})
	}
	keys, ok := orgStringList(in.Value("permission_keys"))
	if !ok {
		return endpoint.Unprocessable([]string{orgMsgPermissionKeys})
	}
	role, err := a.g.Orgs().CreateRole(ctx, tok.Subject(), orgID, orgs.NewRole{
		Name:           name,
		Slug:           slug,
		Description:    orgOptionalString(in.Value("description")),
		PermissionKeys: keys,
	})
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusCreated, orgRoleView(role))
}

func (a orgAPI) updateRole(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	roleID := in.String("roleId")
	if roleID == "" {
		return endpoint.Unprocessable([]string{orgMsgRoleIDRequired})
	}
	changes := orgs.RoleChanges{
		Name:        orgOptionalString(in.Value("name")),
		Description: orgOptionalString(in.Value("description")),
	}
	if raw := in.Value("permission_keys"); raw != nil {
		keys, ok := orgStringList(raw)
		if !ok {
			return endpoint.Unprocessable([]string{orgMsgPermissionKeys})
		}
		changes.PermissionKeys = &keys
	}
	role, err := a.g.Orgs().UpdateRole(ctx, tok.Subject(), orgID, roleID, changes)
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, orgRoleView(role))
}

func (a orgAPI) deleteRole(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	roleID := in.String("roleId")
	if roleID == "" {
		return endpoint.Unprocessable([]string{orgMsgRoleIDRequired})
	}
	if err := a.g.Orgs().DeleteRole(ctx, tok.Subject(), orgID, roleID); err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"deleted": true})
}

// orgOptionalString is v when it is a string, nil otherwise (upstream ignores other types).
func orgOptionalString(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}
