package admin

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/store"
)

const (
	msgNoOrganization = "The organization does not exist."
	msgNoDrain        = "The drain does not exist for this organization."
	msgBadRoles       = "roles must be a non-empty list of role slugs."
	minDrainSecret    = 16
)

// refusal carries a client answer out of a transaction.
type refusal struct{ res endpoint.Result }

func (refusal) Error() string { return "admin: refused" }

// organization loads the organization of a route, or the 404 (or 500) to answer.
func (p *Plugin) organization(ctx context.Context, id string) (model.Organization, endpoint.Result, bool) {
	org, err := p.g.Repos.Organizations.Get(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return org, NotFound(msgNoOrganization), false
	}
	if err != nil {
		return org, p.fail(ctx, "load organization", err), false
	}
	return org, endpoint.Result{}, true
}

func orgView(o model.Organization) map[string]any {
	return map[string]any{
		"id": o.ID, "name": o.Name, "slug": o.Slug, "status": cmp.Or(o.Status, model.OrganizationStatusActive),
		"created_by": o.CreatedBy, "created_at": o.CreatedAt.Format(dateAtom), "updated_at": o.UpdatedAt.Format(dateAtom),
	}
}

// listOrganizations answers GET /admin/organizations: oldest first, filtered by status.
func (p *Plugin) listOrganizations(ctx context.Context, in *endpoint.Input) endpoint.Result {
	if _, res, ok := Authorize(ctx, Read, ""); !ok {
		return res
	}
	st := in.String("status")
	if st != "" && st != model.OrganizationStatusActive && st != model.OrganizationStatusSuspended {
		return Invalid("status must be active or suspended.")
	}
	limit, valid := positiveInt(in.Value("limit"), DefaultLimit)
	if !valid {
		return Invalid("limit must be a positive integer.")
	}
	c := store.Criteria{}
	if st != "" {
		c["status"] = st
	}
	if cursor := in.String("cursor"); cursor != "" {
		c["id"] = store.Gt(cursor)
	}
	rows, err := p.g.Repos.Organizations.Find(ctx, c, store.Query{OrderBy: []store.Order{{Column: "id"}}, Limit: limit + 1})
	if err != nil {
		return p.fail(ctx, "list organizations", err)
	}
	orgs, next := pageOf(rows, limit, func(o model.Organization) string { return o.ID })
	data := make([]any, 0, len(orgs))
	for _, o := range orgs {
		data = append(data, orgView(o))
	}
	return endpoint.JSON(http.StatusOK, map[string]any{"data": data, "next_cursor": next})
}

// readOrganization answers GET /admin/organizations/{id}: with its members, emails included.
func (p *Plugin) readOrganization(ctx context.Context, in *endpoint.Input) endpoint.Result {
	orgID := in.String("id")
	if _, res, ok := Authorize(ctx, Read, orgID); !ok {
		return res
	}
	org, res, found := p.organization(ctx, orgID)
	if !found {
		return res
	}
	members, err := p.g.Orgs.ListMembers(ctx, org.ID, true)
	if err != nil {
		return p.fail(ctx, "read organization", err)
	}
	list := make([]any, 0, len(members))
	for _, m := range members {
		list = append(list, map[string]any{"user_id": m.UserID, "email": m.Email, "display_name": m.DisplayName, "status": m.Status, "roles": m.Roles})
	}
	view := orgView(org)
	view["members"] = list
	return success(view)
}

// deleteOrganization answers DELETE /admin/organizations/{id}: core's soft deletion.
func (p *Plugin) deleteOrganization(ctx context.Context, in *endpoint.Input) endpoint.Result {
	orgID := in.String("id")
	op, res, ok := Authorize(ctx, Manage, orgID)
	if !ok {
		return res
	}
	org, res, found := p.organization(ctx, orgID)
	if !found {
		return res
	}
	if err := p.g.Orgs.DeleteOrganization(ctx, org, op.ID); err != nil {
		return p.fail(ctx, "delete organization", err)
	}
	return p.recorded(ctx, status(model.OrganizationStatusSuspended), AuditOrganizationDeleted, op, "", orgID, nil)
}

// setMemberRoles answers PATCH /admin/organizations/{id}/members/{userId}/roles: an instance
// operator may grant any role of the organization; the organization keeps an active owner.
func (p *Plugin) setMemberRoles(ctx context.Context, in *endpoint.Input) endpoint.Result {
	orgID := in.String("id")
	op, res, ok := Authorize(ctx, Manage, orgID)
	if !ok {
		return res
	}
	slugs, valid := nonEmptyStrings(in.Value("roles"))
	if !valid || len(slugs) == 0 {
		return Invalid(msgBadRoles)
	}
	if _, res, found := p.organization(ctx, orgID); !found {
		return res
	}
	userID := in.String("userId")
	err := p.g.DB.Tx(ctx, func(ctx context.Context) error { return p.replaceRoles(ctx, orgID, userID, slugs) })
	var refused refusal
	if errors.As(err, &refused) {
		return refused.res
	}
	if err != nil {
		return p.fail(ctx, "set member roles", err)
	}
	p.g.Events.Dispatch(ctx, event.MemberRolesChanged{OrganizationID: orgID, UserID: userID, RoleSlugs: slugs, ActorUserID: op.ID})
	return p.recorded(ctx, success(map[string]any{"roles": slugs}), AuditMemberRolesChanged, op, userID, orgID, map[string]any{"roles": slugs})
}

// replaceRoles runs in a transaction, the organization's row locked first (as core's role
// changes) so two concurrent demotions cannot both see a co-owner.
func (p *Plugin) replaceRoles(ctx context.Context, orgID, userID string, slugs []string) error {
	r := p.g.Repos
	if _, err := p.g.DB.Update(ctx, "auth_organizations", store.Criteria{"id": orgID}, store.Data{"id": orgID}); err != nil {
		return err
	}
	membership, err := r.Memberships.ByUserAndOrganization(ctx, userID, orgID)
	if errors.Is(err, repository.ErrNotFound) {
		return refusal{NotFound("The user is not a member of this organization.")}
	} else if err != nil {
		return err
	}
	var wanted []string
	for _, slug := range slugs {
		role, err := r.Roles.ByOrganizationAndSlug(ctx, &orgID, slug)
		if errors.Is(err, repository.ErrNotFound) {
			return refusal{Invalid("Unknown role for this organization: " + slug)}
		} else if err != nil {
			return err
		}
		if !slices.Contains(wanted, role.ID) {
			wanted = append(wanted, role.ID)
		}
	}
	held, err := r.MembershipRoles.ListByMembership(ctx, membership.ID)
	if err != nil {
		return err
	}
	if err := p.keepsOwner(ctx, orgID, held, wanted); err != nil {
		return err
	}
	for _, link := range held {
		if i := slices.Index(wanted, link.RoleID); i >= 0 {
			wanted = slices.Delete(wanted, i, i+1)
		} else if err := r.MembershipRoles.Delete(ctx, link); err != nil {
			return err
		}
	}
	for _, roleID := range wanted {
		if err := r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: membership.ID, RoleID: roleID}); err != nil {
			return err
		}
	}
	return nil
}

// keepsOwner refuses dropping the owner role from a member when no other active member holds it.
func (p *Plugin) keepsOwner(ctx context.Context, orgID string, held []model.MembershipRole, wanted []string) error {
	r := p.g.Repos
	owner, err := r.Roles.ByOrganizationAndSlug(ctx, &orgID, authz.RoleOwner)
	if errors.Is(err, repository.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	drops := slices.ContainsFunc(held, func(l model.MembershipRole) bool { return l.RoleID == owner.ID }) && !slices.Contains(wanted, owner.ID)
	if !drops {
		return nil
	}
	links, err := r.MembershipRoles.ListByRole(ctx, owner.ID)
	if err != nil {
		return err
	}
	active := 0
	for _, link := range links {
		m, err := r.Memberships.Get(ctx, link.MembershipID)
		if err != nil && !errors.Is(err, repository.ErrNotFound) {
			return err
		}
		if err == nil && m.OrganizationID == orgID && m.Status == model.MembershipStatusActive {
			active++
		}
	}
	if active <= 1 {
		return refusal{Conflict("The organization must keep at least one owner.")}
	}
	return nil
}

// orgDrain authorizes c on the route's organization and loads its drain, or the answer.
func (p *Plugin) orgDrain(ctx context.Context, in *endpoint.Input) (Principal, string, map[string]any, endpoint.Result, bool) {
	orgID := in.String("id")
	op, res, ok := Authorize(ctx, Own, orgID)
	if !ok {
		return op, "", nil, res, false
	}
	drain, found, err := p.audit.Drains().Find(ctx, in.String("drainId"))
	if err != nil {
		return op, "", nil, p.fail(ctx, "load drain", err), false
	}
	if !found || drain.OrganizationID != orgID {
		return op, "", nil, NotFound(msgNoDrain), false
	}
	return op, drain.ID, drain.Map(), endpoint.Result{}, true
}

// listDrains answers GET /admin/organizations/{id}/drains (never their secrets).
func (p *Plugin) listDrains(ctx context.Context, in *endpoint.Input) endpoint.Result {
	orgID := in.String("id")
	if _, res, ok := Authorize(ctx, Read, orgID); !ok {
		return res
	}
	if _, res, found := p.organization(ctx, orgID); !found {
		return res
	}
	drains, err := p.audit.Drains().ForOrganization(ctx, orgID, false)
	if err != nil {
		return p.fail(ctx, "list drains", err)
	}
	out := make([]any, 0, len(drains))
	for _, d := range drains {
		out = append(out, d.Map())
	}
	return success(out)
}

// createDrain answers POST /admin/organizations/{id}/drains: a signed webhook drain.
func (p *Plugin) createDrain(ctx context.Context, in *endpoint.Input) endpoint.Result {
	orgID := in.String("id")
	op, res, ok := Authorize(ctx, Own, orgID)
	if !ok {
		return res
	}
	target := in.String("endpoint")
	if u, err := url.ParseRequestURI(target); err != nil || u.Host == "" || !strings.HasPrefix(target, "https://") {
		return Invalid("endpoint must be an https URL.")
	}
	secret := in.String("secret")
	if len(secret) < minDrainSecret {
		return Invalid("secret must be at least 16 characters.")
	}
	filter, valid := nonEmptyStrings(in.Value("filter"))
	if !valid {
		return Invalid("filter must be a list of event names or prefix.* patterns.")
	}
	if _, res, found := p.organization(ctx, orgID); !found {
		return res
	}
	drain, err := p.audit.Drains().Create(ctx, orgID, target, secret, filter, op.ID)
	if err != nil {
		return p.fail(ctx, "create drain", err)
	}
	return p.recorded(ctx, endpoint.Data(http.StatusCreated, drain.Map()), AuditDrainCreated, op, "", orgID,
		map[string]any{"drain_id": drain.ID, "endpoint": target})
}

// deleteDrain answers DELETE /admin/organizations/{id}/drains/{drainId}.
func (p *Plugin) deleteDrain(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, drainID, _, res, ok := p.orgDrain(ctx, in)
	if !ok {
		return res
	}
	if _, err := p.audit.Drains().Delete(ctx, drainID); err != nil {
		return p.fail(ctx, "delete drain", err)
	}
	return p.recorded(ctx, status("deleted"), AuditDrainDeleted, op, "", in.String("id"), map[string]any{"drain_id": drainID})
}

// testDrain answers POST /admin/organizations/{id}/drains/{drainId}/test: records
// admin.drain_tested for the organization (delivered to its drains like any event) and answers
// the drain's delivery state afterwards.
func (p *Plugin) testDrain(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, drainID, before, res, ok := p.orgDrain(ctx, in)
	if !ok {
		return res
	}
	if err := p.Record(ctx, AuditDrainTested, op, "", in.String("id"), map[string]any{"drain_id": drainID}); err != nil {
		return p.fail(ctx, "test drain", err)
	}
	after, found, err := p.audit.Drains().Find(ctx, drainID)
	if err != nil {
		return p.fail(ctx, "test drain", err)
	}
	if found {
		before = after.Map()
	}
	return success(before)
}
