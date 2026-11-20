package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/plugins/audit"
)

// Wire constants of the SCIM routes.
const (
	ContentType  = "application/scim+json"
	ListSchema   = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	ErrorSchema  = "urn:ietf:params:scim:api:messages:2.0:Error"
	MaxCount     = 200
	defaultCount = 100
)

// Route names.
const (
	RouteServiceProviderConfig = "polaris.scim.service-provider-config"
	RouteSchemas               = "polaris.scim.schemas"
	RouteResourceTypes         = "polaris.scim.resource-types"
	RouteUsersList             = "polaris.scim.users-list"
	RouteUsersCreate           = "polaris.scim.users-create"
	RouteUsersRead             = "polaris.scim.users-read"
	RouteUsersReplace          = "polaris.scim.users-replace"
	RouteUsersPatch            = "polaris.scim.users-patch"
	RouteUsersDelete           = "polaris.scim.users-delete"
	RouteGroupsList            = "polaris.scim.groups-list"
	RouteGroupsCreate          = "polaris.scim.groups-create"
	RouteGroupsRead            = "polaris.scim.groups-read"
	RouteGroupsReplace         = "polaris.scim.groups-replace"
	RouteGroupsPatch           = "polaris.scim.groups-patch"
	RouteGroupsDelete          = "polaris.scim.groups-delete"
)

// scimRoute is a /scim/v2/{connectionId} route: the bearer must be the path's active connection.
type scimRoute func(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result

func (p *Plugin) directoryRoute(f scimRoute) endpoint.Endpoint {
	return endpoint.Func(func(ctx context.Context, in *endpoint.Input) endpoint.Result {
		bearer, found := strings.CutPrefix(in.Request.Header.Get("Authorization"), "Bearer ")
		if !found {
			return scimError(&Error{Status: http.StatusUnauthorized, Detail: "A valid connection token is required."})
		}
		conn, ok, err := p.conns.Authenticate(ctx, bearer)
		if err != nil {
			return p.serverError(ctx, err)
		}
		if !ok || conn.ID != in.String("connectionId") {
			return scimError(&Error{Status: http.StatusUnauthorized, Detail: "A valid connection token is required."})
		}
		if err := p.conns.touch(ctx, conn); err != nil {
			return p.serverError(ctx, err)
		}
		return f(ctx, in, conn)
	})
}

func scim(status int, document any) endpoint.Result {
	return endpoint.Result{Status: status, Body: document, Header: http.Header{"Content-Type": {ContentType}}}
}

// scimError is the SCIM error document of e, which also carries error and message.
func scimError(e *Error) endpoint.Result {
	doc := map[string]any{"schemas": []string{ErrorSchema}, "status": strconv.Itoa(e.Status), "detail": e.Detail,
		"error": "scim_error", "message": e.Detail}
	if e.Type != "" {
		doc["scimType"], doc["error"] = e.Type, "scim_"+e.Type
	}
	return scim(e.Status, doc)
}

func (p *Plugin) serverError(ctx context.Context, err error) endpoint.Result {
	p.g.Logger.ErrorContext(ctx, "polaris scim: request failed", "error", err)
	return scimError(&Error{Status: http.StatusInternalServerError, Detail: "The server could not complete the request."})
}

// refuse answers err; a refusal is recorded as scim.request_rejected when audited.
func (p *Plugin) refuse(ctx context.Context, conn Connection, err error, audited bool) endpoint.Result {
	e, ok := asError(err)
	if !ok {
		return p.serverError(ctx, err)
	}
	if audited {
		p.record(ctx, AuditRequestRejected, conn, "", map[string]any{"status": e.Status, "reason": e.Detail})
	}
	return scimError(e)
}

// record dispatches a directory's action: the connection is the actor.
func (p *Plugin) record(ctx context.Context, name string, conn Connection, subjectID string, data map[string]any) {
	c := endpoint.Client(ctx)
	merged := map[string]any{"connection_name": conn.Name}
	for k, v := range data {
		merged[k] = v
	}
	p.g.Events.Dispatch(ctx, Event{Name: name, ActorType: audit.ActorAPIKey, ActorID: conn.ID, SubjectID: subjectID,
		OrganizationID: conn.OrganizationID, Data: merged, IP: c.IP, UserAgent: c.UserAgent})
}

func (p *Plugin) location(conn Connection) string { return p.BaseURL(conn.ID) }

func listResponse(pg page, startIndex int) endpoint.Result {
	resources := pg.resources
	if resources == nil {
		resources = []map[string]any{}
	}
	return scim(http.StatusOK, map[string]any{"schemas": []string{ListSchema}, "totalResults": pg.total,
		"startIndex": startIndex, "itemsPerPage": len(resources), "Resources": resources})
}

// body is the request document without the route parameters.
func body(in *endpoint.Input) map[string]any {
	all := in.All()
	delete(all, "connectionId")
	delete(all, "id")
	return all
}

var numericPattern = regexp.MustCompile(`^[ \t\n\r\v\f]*[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?[ \t\n\r\v\f]*$`)

// numeric is PHP's (int) of an is_numeric value; ok false when the value is not numeric.
func numeric(v any) (int, bool) {
	var s string
	switch v := v.(type) {
	case string:
		s = v
	case json.Number:
		s = v.String()
	default:
		return 0, false
	}
	if !numericPattern.MatchString(s) {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, false
	}
	return int(max(-1e9, min(1e9, f))), true
}

func startIndex(in *endpoint.Input) int {
	if n, ok := numeric(in.Value("startIndex")); ok {
		return max(1, n)
	}
	return 1
}

func count(in *endpoint.Input) int {
	if n, ok := numeric(in.Value("count")); ok {
		return max(0, min(MaxCount, n))
	}
	return defaultCount
}

func (p *Plugin) scimEndpoints() map[string]endpoint.Endpoint {
	r := p.directoryRoute
	return map[string]endpoint.Endpoint{
		RouteServiceProviderConfig: r(p.serviceProviderConfig),
		RouteSchemas:               r(p.schemas),
		RouteResourceTypes:         r(p.resourceTypes),
		RouteUsersList:             r(p.listUsers),
		RouteUsersCreate:           r(p.createUser),
		RouteUsersRead:             r(p.readUser),
		RouteUsersReplace:          r(p.replaceUser),
		RouteUsersPatch:            r(p.patchUser),
		RouteUsersDelete:           r(p.deleteUser),
		RouteGroupsList:            r(p.listGroups),
		RouteGroupsCreate:          r(p.createGroup),
		RouteGroupsRead:            r(p.readGroup),
		RouteGroupsReplace:         r(p.replaceGroup),
		RouteGroupsPatch:           r(p.patchGroup),
		RouteGroupsDelete:          r(p.deleteGroup),
	}
}

func (p *Plugin) listUsers(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	f, err := parseFilter(in.String("filter"))
	if err != nil {
		return p.refuse(ctx, conn, err, true)
	}
	start := startIndex(in)
	pg, err := p.dir.listUsers(ctx, conn, f, start, count(in), p.location(conn))
	if err != nil {
		return p.refuse(ctx, conn, err, false)
	}
	return listResponse(pg, start)
}

func (p *Plugin) userResult(ctx context.Context, conn Connection, status int, user model.User) endpoint.Result {
	res, err := p.dir.userResource(ctx, conn, user, p.location(conn))
	if err != nil {
		return p.serverError(ctx, err)
	}
	return scim(status, res)
}

func (p *Plugin) createUser(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	user, err := p.dir.createUser(ctx, conn, body(in))
	if err != nil {
		return p.refuse(ctx, conn, err, true)
	}
	p.record(ctx, AuditUserCreated, conn, user.ID, nil)
	return p.userResult(ctx, conn, http.StatusCreated, user)
}

func (p *Plugin) readUser(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	user, err := p.dir.findUser(ctx, conn, in.String("id"))
	if err != nil {
		return p.refuse(ctx, conn, err, false)
	}
	return p.userResult(ctx, conn, http.StatusOK, user)
}

func (p *Plugin) replaceUser(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	return p.changeUser(ctx, in, conn, func(user model.User) (model.User, error) {
		return p.dir.replaceUser(ctx, conn, user, body(in))
	})
}

func (p *Plugin) patchUser(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	return p.changeUser(ctx, in, conn, func(user model.User) (model.User, error) {
		ops, err := parsePatch(body(in))
		if err != nil {
			return user, err
		}
		return p.dir.patchUser(ctx, conn, user, ops)
	})
}

// changeUser runs a PUT or PATCH and records it as the status transition it made.
func (p *Plugin) changeUser(ctx context.Context, in *endpoint.Input, conn Connection, change func(model.User) (model.User, error)) endpoint.Result {
	user, err := p.dir.findUser(ctx, conn, in.String("id"))
	if err != nil {
		return p.refuse(ctx, conn, err, true)
	}
	was, err := p.dir.active(ctx, conn, user)
	if err != nil {
		return p.serverError(ctx, err)
	}
	if user, err = change(user); err != nil {
		return p.refuse(ctx, conn, err, true)
	}
	is, err := p.dir.active(ctx, conn, user)
	if err != nil {
		return p.serverError(ctx, err)
	}
	name := AuditUserUpdated
	switch {
	case was && !is:
		name = AuditUserDeactivated
	case !was && is:
		name = AuditUserReactivated
	}
	p.record(ctx, name, conn, user.ID, nil)
	return p.userResult(ctx, conn, http.StatusOK, user)
}

func (p *Plugin) deleteUser(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	user, err := p.dir.findUser(ctx, conn, in.String("id"))
	if err != nil {
		return p.refuse(ctx, conn, err, false)
	}
	outcome, err := p.dir.deleteUser(ctx, conn, user)
	if err != nil {
		return p.refuse(ctx, conn, err, true)
	}
	name := AuditUserDeactivated
	if outcome == "deleted" {
		name = AuditUserDeleted
	}
	p.record(ctx, name, conn, user.ID, map[string]any{"deprovision": outcome})
	return endpoint.NoContent()
}

func (p *Plugin) listGroups(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	f, err := parseFilter(in.String("filter"))
	if err != nil {
		return p.refuse(ctx, conn, err, true)
	}
	start := startIndex(in)
	pg, err := p.dir.listGroups(ctx, conn, f, start, count(in), p.location(conn))
	if err != nil {
		return p.refuse(ctx, conn, err, false)
	}
	return listResponse(pg, start)
}

func (p *Plugin) groupResult(ctx context.Context, conn Connection, status int, role model.Role) endpoint.Result {
	res, err := p.dir.groupResource(ctx, conn, role, p.location(conn))
	if err != nil {
		return p.serverError(ctx, err)
	}
	return scim(status, res)
}

func (p *Plugin) createGroup(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	role, err := p.dir.createGroup(ctx, conn, body(in))
	if err != nil {
		return p.refuse(ctx, conn, err, true)
	}
	p.record(ctx, AuditGroupCreated, conn, role.ID, map[string]any{"name": role.Name})
	return p.groupResult(ctx, conn, http.StatusCreated, role)
}

func (p *Plugin) readGroup(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	role, err := p.dir.findGroup(ctx, conn, in.String("id"))
	if err != nil {
		return p.refuse(ctx, conn, err, false)
	}
	return p.groupResult(ctx, conn, http.StatusOK, role)
}

func (p *Plugin) replaceGroup(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	return p.changeGroup(ctx, in, conn, func(role model.Role) (model.Role, error) {
		return p.dir.replaceGroup(ctx, conn, role, body(in))
	})
}

func (p *Plugin) patchGroup(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	return p.changeGroup(ctx, in, conn, func(role model.Role) (model.Role, error) {
		ops, err := parsePatch(body(in))
		if err != nil {
			return role, err
		}
		return p.dir.patchGroup(ctx, conn, role, ops)
	})
}

func (p *Plugin) changeGroup(ctx context.Context, in *endpoint.Input, conn Connection, change func(model.Role) (model.Role, error)) endpoint.Result {
	role, err := p.dir.findGroup(ctx, conn, in.String("id"))
	if err == nil {
		role, err = change(role)
	}
	if err != nil {
		return p.refuse(ctx, conn, err, true)
	}
	p.record(ctx, AuditGroupUpdated, conn, role.ID, map[string]any{"name": role.Name})
	return p.groupResult(ctx, conn, http.StatusOK, role)
}

func (p *Plugin) deleteGroup(ctx context.Context, in *endpoint.Input, conn Connection) endpoint.Result {
	role, err := p.dir.findGroup(ctx, conn, in.String("id"))
	if err == nil {
		err = p.dir.deleteGroup(ctx, conn, role)
	}
	if err != nil {
		return p.refuse(ctx, conn, err, true)
	}
	p.record(ctx, AuditGroupDeleted, conn, role.ID, map[string]any{"name": role.Name})
	return endpoint.NoContent()
}
