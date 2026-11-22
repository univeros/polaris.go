package httpapi

import (
	"context"
	"errors"
	"github.com/univeros/polaris.go/internal/services"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/orgs"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// The organization, membership, invitation, role, permission and user-administration routes,
// plus switch-org and invites-accept.
//
// Input is checked by each endpoint with its own messages, not by manifest.Validate: the
// contract fixtures freeze those messages ("A name is required.", not the validator's).

const (
	orgMsgNotActiveOrg = "That organization is not your active organization."
	orgMsgOrgNotFound  = "The organization does not exist."
	// orgAtom is RFC 3339 with a numeric offset: UTC is written "+00:00", never "Z".
	orgAtom = "2006-01-02T15:04:05-07:00"
)

// orgAPI serves the routes over the graph's services.
type orgAPI struct{ g *wiring.Graph }

func orgEndpoints(g *wiring.Graph) map[string]endpoint.Endpoint {
	a := orgAPI{g: g}
	return map[string]endpoint.Endpoint{
		"polaris.orgs.create":               a.authed(a.createOrg),
		"polaris.orgs.list":                 a.authed(a.listOrgs),
		"polaris.orgs.read":                 a.inOrg(a.readOrg),
		"polaris.orgs.update":               a.inOrg(a.updateOrg),
		"polaris.orgs.delete":               a.inOrg(a.deleteOrg),
		"polaris.orgs.members-list":         a.inOrg(a.listMembers),
		"polaris.orgs.member-roles-update":  a.inOrg(a.changeMemberRoles),
		"polaris.orgs.member-status-update": a.inOrg(a.changeMemberStatus),
		"polaris.orgs.member-remove":        a.inOrg(a.removeMember),
		"polaris.orgs.invites-create":       a.inOrg(a.invite),
		"polaris.orgs.invites-list":         a.inOrg(a.listInvites),
		"polaris.orgs.invite-revoke":        a.inOrg(a.revokeInvite),
		"polaris.orgs.roles-create":         a.inOrg(a.createRole),
		"polaris.orgs.roles-list":           a.inOrg(a.listRoles),
		"polaris.orgs.role-update":          a.inOrg(a.updateRole),
		"polaris.orgs.role-delete":          a.inOrg(a.deleteRole),
		"polaris.permissions.list":          a.authed(a.listPermissions),
		"polaris.users.read":                a.authed(a.readUser),
		"polaris.users.update":              a.authed(a.updateUser),
		"polaris.users.delete":              a.authed(a.deleteUser),
		"polaris.users.disable":             a.authed(a.disableUser),
		"polaris.users.enable":              a.authed(a.enableUser),
		"polaris.auth.switch-org":           a.authed(a.switchOrg),
		"polaris.auth.invites-accept":       a.authed(a.acceptInvite),
	}
}

// orgCall is an endpoint body run for an authenticated principal.
type orgCall func(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result

// orgScoped is an endpoint body run on the path organization, the guard passed.
type orgScoped func(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result

// authed answers 401 without a principal.
func (a orgAPI) authed(f orgCall) endpoint.Func {
	return func(ctx context.Context, in *endpoint.Input) endpoint.Result {
		tok := endpoint.Token(ctx)
		if tok == nil {
			return endpoint.Unauthorized()
		}
		return f(ctx, in, tok)
	}
}

// inOrg adds the cross-tenant guard: the path organization must be the caller's active one,
// unless the caller is a superadmin.
func (a orgAPI) inOrg(f orgScoped) endpoint.Func {
	return a.authed(func(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
		orgID := in.String("id")
		if orgDeniesActiveOrg(ctx, tok, orgID) {
			return endpoint.Forbidden(orgMsgNotActiveOrg)
		}
		return f(ctx, in, tok, orgID)
	})
}

// orgDeniesActiveOrg reports whether the caller may not act on orgID: it is not the token's
// active organization and the caller is not a superadmin, by the authority the authorization step
// resolved, or else by the token's roles claim.
func orgDeniesActiveOrg(ctx context.Context, tok *token.Token, orgID string) bool {
	if a, ok := wiring.Authority(ctx); ok {
		if a.IsSuperadmin() {
			return false
		}
	} else if slices.Contains(orgStrings(tok.Claim("roles")), authz.RoleSuperadmin) {
		return false
	}
	return orgID != tok.Organization()
}

// fail maps a domain refusal to its wire answer; anything else is a logged 500.
func (a orgAPI) fail(ctx context.Context, err error) endpoint.Result {
	var oe *orgs.Error
	var ie *identity.Error
	var fe *authz.ForbiddenError
	switch {
	case errors.As(err, &fe):
		return endpoint.Forbidden(fe.Message)
	case errors.As(err, &oe):
		switch {
		case errors.Is(oe.Kind, orgs.ErrInvalid):
			return endpoint.Unprocessable([]string{oe.Message})
		case errors.Is(oe.Kind, orgs.ErrNotFound):
			return endpoint.NotFound(oe.Message)
		case errors.Is(oe.Kind, orgs.ErrConflict):
			return orgConflict(oe.Message)
		case errors.Is(oe.Kind, orgs.ErrInvalidInvitation):
			return endpoint.JSON(http.StatusBadRequest, map[string]any{"message": oe.Message})
		}
	case errors.As(err, &ie):
		switch {
		case errors.Is(ie.Kind, identity.ErrUserNotFound):
			return endpoint.NotFound(ie.Message)
		case errors.Is(ie.Kind, identity.ErrConflict):
			return orgConflict(ie.Message)
		case errors.Is(ie.Kind, identity.ErrInvalidProfile):
			return endpoint.Unprocessable([]string{ie.Message})
		}
	}
	a.g.Logger().ErrorContext(ctx, "polaris: endpoint failed", "route", orgRouteName(ctx), "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

func orgRouteName(ctx context.Context) string {
	if r := endpoint.Route(ctx); r != nil {
		return r.Name
	}
	return ""
}

func orgConflict(message string) endpoint.Result {
	return endpoint.Error(http.StatusConflict, "conflict", message)
}

// activeOrg loads orgID when it exists and is active (a soft-deleted organization reads as unknown).
func (a orgAPI) activeOrg(ctx context.Context, orgID string) (model.Organization, bool, error) {
	org, err := a.g.Repos().Organizations.Get(ctx, orgID)
	if errors.Is(err, repository.ErrNotFound) {
		return model.Organization{}, false, nil
	}
	if err != nil {
		return model.Organization{}, false, err
	}
	return org, org.Status == model.OrganizationStatusActive, nil
}

// orgStringList is v as a list of strings; ok is false when v is not a list or holds anything
// but strings (the whole list is rejected then).
func orgStringList(v any) ([]string, bool) {
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// orgStrings is the string items of a claim value, whatever its decoded list type.
func orgStrings(v any) []string {
	if s, ok := v.([]string); ok {
		return s
	}
	out, _ := orgStringList(v)
	return out
}

// orgList never encodes as null.
func orgList[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func orgTime(t time.Time) string { return t.UTC().Format(orgAtom) }

func orgView(o model.Organization) map[string]any {
	return map[string]any{"id": o.ID, "name": o.Name, "slug": o.Slug, "status": o.Status}
}

func (a orgAPI) createOrg(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	userID := tok.Subject()
	if userID == "" {
		return endpoint.Unauthorized()
	}
	if tok.Claim("email_verified") != true {
		return endpoint.Error(http.StatusForbidden, "email_unverified", "Verify your email address before creating an organization.")
	}
	var problems []string
	name := strings.TrimSpace(in.String("name"))
	switch {
	case name == "":
		problems = append(problems, "A name is required.")
	case utf8.RuneCountInString(name) > 160:
		problems = append(problems, "The name must be at most 160 characters.")
	}
	slug := ""
	if raw := in.Value("slug"); raw != nil && raw != "" {
		s, ok := raw.(string)
		if !ok || !orgSlugPattern(s) || utf8.RuneCountInString(s) > 160 {
			problems = append(problems, "The slug must be URL-safe (lowercase letters, digits and hyphens) and at most 160 characters.")
		}
		slug = s
	}
	if problems != nil {
		return endpoint.Unprocessable(problems)
	}
	org, err := services.Of(a.g).Orgs.CreateOrganization(ctx, name, slug, userID)
	if errors.Is(err, orgs.ErrConflict) {
		return orgConflict("That slug is already taken.")
	}
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusCreated, map[string]any{"id": org.ID, "name": org.Name, "slug": org.Slug, "role": authz.RoleOwner})
}

// orgSlugPattern reports whether s is lowercase ASCII letters, digits and hyphens, allowing one
// trailing newline (the accepted set is part of the contract; existing slugs may carry it).
func orgSlugPattern(s string) bool {
	s = strings.TrimSuffix(s, "\n")
	return s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}

func (a orgAPI) listOrgs(ctx context.Context, _ *endpoint.Input, tok *token.Token) endpoint.Result {
	userID := tok.Subject()
	if userID == "" {
		return endpoint.Unauthorized()
	}
	list, err := services.Of(a.g).Orgs.ListOrganizations(ctx, userID)
	if err != nil {
		return a.fail(ctx, err)
	}
	data := make([]map[string]any, 0, len(list))
	for _, o := range list {
		data = append(data, map[string]any{"id": o.ID, "name": o.Name, "slug": o.Slug})
	}
	return endpoint.Data(http.StatusOK, data)
}

func (a orgAPI) readOrg(ctx context.Context, _ *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	org, err := a.g.Repos().Organizations.Get(ctx, orgID)
	if errors.Is(err, repository.ErrNotFound) {
		return endpoint.NotFound(orgMsgOrgNotFound)
	}
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, orgView(org))
}

func (a orgAPI) updateOrg(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	name, ok := in.Value("name").(string)
	if !ok {
		return endpoint.Unprocessable([]string{"A name is required."})
	}
	org, active, err := a.activeOrg(ctx, orgID)
	if err != nil {
		return a.fail(ctx, err)
	}
	if !active {
		return endpoint.NotFound(orgMsgOrgNotFound)
	}
	org, err = services.Of(a.g).Orgs.UpdateOrganization(ctx, org, name, tok.Subject())
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, orgView(org))
}

func (a orgAPI) deleteOrg(ctx context.Context, _ *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	org, active, err := a.activeOrg(ctx, orgID)
	if err != nil {
		return a.fail(ctx, err)
	}
	if !active {
		return endpoint.NotFound(orgMsgOrgNotFound)
	}
	if err := a.g.Orgs().DeleteOrganization(ctx, org, tok.Subject()); err != nil {
		// The organization is deleted by now; only some session revocations failed.
		a.g.Logger().ErrorContext(ctx, "polaris: organization deleted, revoking sessions failed", "organization", org.ID, "error", err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"deleted": true})
}

func (a orgAPI) listPermissions(ctx context.Context, _ *endpoint.Input, _ *token.Token) endpoint.Result {
	perms, err := services.Of(a.g).Orgs.Permissions(ctx)
	if err != nil {
		return a.fail(ctx, err)
	}
	data := make([]map[string]any, 0, len(perms))
	for _, p := range perms {
		data = append(data, map[string]any{"key": p.Key, "description": p.Description})
	}
	return endpoint.Data(http.StatusOK, data)
}
