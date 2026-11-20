package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/univeros/polaris-go/endpoint"
)

// Route names (polaris.admin.<file>).
const (
	RouteUsersList         = "polaris.admin.users-list"
	RouteUsersRead         = "polaris.admin.users-read"
	RouteUsersBan          = "polaris.admin.users-ban"
	RouteUsersUnban        = "polaris.admin.users-unban"
	RouteUsersPassword     = "polaris.admin.users-password"
	RouteUsersDelete       = "polaris.admin.users-delete"
	RouteUsersImpersonate  = "polaris.admin.users-impersonate"
	RouteSessionsList      = "polaris.admin.sessions-list"
	RouteSessionsRevoke    = "polaris.admin.sessions-revoke"
	RouteSessionsRevokeAll = "polaris.admin.sessions-revoke-all"
	RouteMFAList           = "polaris.admin.mfa-list"
	RouteMFARemove         = "polaris.admin.mfa-remove"
	RouteMFAReset          = "polaris.admin.mfa-reset"
	RouteOrgsList          = "polaris.admin.organizations-list"
	RouteOrgsRead          = "polaris.admin.organizations-read"
	RouteOrgsMemberRoles   = "polaris.admin.organizations-member-roles"
	RouteOrgsDelete        = "polaris.admin.organizations-delete"
	RouteAuditQuery        = "polaris.admin.audit-query"
	RouteDrainsList        = "polaris.admin.drains-list"
	RouteDrainsCreate      = "polaris.admin.drains-create"
	RouteDrainsDelete      = "polaris.admin.drains-delete"
	RouteDrainsTest        = "polaris.admin.drains-test"
	RouteStats             = "polaris.admin.stats"
	RouteKeysList          = "polaris.admin.keys-list"
	RouteKeysCreate        = "polaris.admin.keys-create"
	RouteKeysDelete        = "polaris.admin.keys-delete"
	RouteGrantsList        = "polaris.admin.grants-list"
	RouteGrantsCreate      = "polaris.admin.grants-create"
	RouteGrantsDelete      = "polaris.admin.grants-delete"
)

// Page sizes of the lists.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	return map[string]endpoint.Endpoint{
		RouteUsersList: endpoint.Func(p.listUsers), RouteUsersRead: endpoint.Func(p.readUser),
		RouteUsersBan: endpoint.Func(p.banUser), RouteUsersUnban: endpoint.Func(p.unbanUser),
		RouteUsersPassword: endpoint.Func(p.setPassword), RouteUsersDelete: endpoint.Func(p.deleteUser),
		RouteUsersImpersonate: endpoint.Func(p.impersonate),
		RouteSessionsList:     endpoint.Func(p.listSessions), RouteSessionsRevoke: endpoint.Func(p.revokeSession),
		RouteSessionsRevokeAll: endpoint.Func(p.revokeAllSessions),
		RouteMFAList:           endpoint.Func(p.listFactors), RouteMFARemove: endpoint.Func(p.removeFactor),
		RouteMFAReset: endpoint.Func(p.resetMFA),
		RouteOrgsList: endpoint.Func(p.listOrganizations), RouteOrgsRead: endpoint.Func(p.readOrganization),
		RouteOrgsMemberRoles: endpoint.Func(p.setMemberRoles), RouteOrgsDelete: endpoint.Func(p.deleteOrganization),
		RouteAuditQuery: endpoint.Func(p.queryAudit),
		RouteDrainsList: endpoint.Func(p.listDrains), RouteDrainsCreate: endpoint.Func(p.createDrain),
		RouteDrainsDelete: endpoint.Func(p.deleteDrain), RouteDrainsTest: endpoint.Func(p.testDrain),
		RouteStats:    endpoint.Func(p.stats),
		RouteKeysList: endpoint.Func(p.listKeys), RouteKeysCreate: endpoint.Func(p.createKey),
		RouteKeysDelete: endpoint.Func(p.deleteKey),
		RouteGrantsList: endpoint.Func(p.listGrants), RouteGrantsCreate: endpoint.Func(p.createGrant),
		RouteGrantsDelete: endpoint.Func(p.deleteGrant),
	}
}

// fail logs err and answers core's 500.
func (p *Plugin) fail(ctx context.Context, what string, err error) endpoint.Result {
	p.g.Logger.ErrorContext(ctx, "admin: "+what+" failed", "error", err)
	return serverError()
}

// recorded records the action and answers res; a failing audit write answers 500.
func (p *Plugin) recorded(ctx context.Context, res endpoint.Result, name string, op Principal, subjectID, organizationID string, data map[string]any) endpoint.Result {
	if err := p.Record(ctx, name, op, subjectID, organizationID, data); err != nil {
		return p.fail(ctx, "audit "+name, err)
	}
	return res
}

func success(data any) endpoint.Result { return endpoint.Data(http.StatusOK, data) }

func status(s string) endpoint.Result { return success(map[string]any{"status": s}) }

// positiveInt reads an optional numeric value (PHP is_numeric, truncated) of at least 1, clamped
// to MaxLimit; def when absent or "".
func positiveInt(v any, def int) (int, bool) {
	var s string
	switch v := v.(type) {
	case nil:
		return def, true
	case string:
		s = strings.TrimSpace(v)
	case json.Number:
		s = v.String()
	default:
		return 0, false
	}
	if s == "" {
		return def, true
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 1 {
		return 0, false
	}
	return int(min(f, MaxLimit)), true
}

var timeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02"}

// parseTime reads an optional ISO-8601 datetime: nil for none, ok false when given and invalid.
func parseTime(v any) (*time.Time, bool) {
	if v == nil || v == "" {
		return nil, true
	}
	s, isString := v.(string)
	if !isString {
		return nil, false
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return &t, true
		}
	}
	return nil, false
}

// nonEmptyStrings reads a list whose items are all non-empty strings; nil (and ok) when absent.
func nonEmptyStrings(v any) ([]string, bool) {
	if v == nil {
		return nil, true
	}
	list, isList := v.([]any)
	if !isList {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, isString := item.(string)
		if !isString || s == "" {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// pageOf trims rows read with limit+1 to one page and returns the next cursor (nil on the last).
func pageOf[T any](rows []T, limit int, id func(T) string) ([]T, any) {
	if len(rows) <= limit {
		return rows, nil
	}
	return rows[:limit], id(rows[limit-1])
}
