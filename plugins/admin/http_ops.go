package admin

import (
	"cmp"
	"context"
	"errors"
	"maps"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// blankSet is the bytes a name is trimmed of: space, tab, newline, carriage return, NUL and
// vertical tab (not the other Unicode spaces).
const blankSet = " \t\n\r\x00\x0B"

const msgBadScope = `scope must be "instance" or an organization id.`

// orgOf is the organization a scope names, "" for the instance.
func orgOf(scope string) string {
	if scope == ScopeInstance {
		return ""
	}
	return scope
}

// queryAudit answers GET /admin/audit: the instance-wide trail, newest first, with the filters of
// /audit/me plus actor_id, subject_id and organization_id; an organization-scoped operator reads
// their organization only.
func (p *Plugin) queryAudit(ctx context.Context, in *endpoint.Input) endpoint.Result {
	orgID := in.String("organization_id")
	if caller, found := Operator(ctx); found && orgID == "" {
		orgID = orgOf(caller.Scope)
	}
	if _, res, ok := Authorize(ctx, Read, orgID); !ok {
		return res
	}
	from, okFrom := parseTime(in.Value("from"))
	to, okTo := parseTime(in.Value("to"))
	if !okFrom || !okTo {
		return auditInvalid("from and to must be ISO-8601 datetimes.")
	}
	q := audit.Query{
		ActorID: in.String("actor_id"), SubjectID: in.String("subject_id"), OrganizationID: orgID, Cursor: in.String("cursor"),
	}
	if from != nil {
		q.From = from.UTC()
	}
	if to != nil {
		q.To = to.UTC()
	}
	if raw := in.Value("limit"); raw != nil {
		n, valid := positiveInt(raw, 0)
		if !valid || n == 0 {
			return auditInvalid("limit must be a positive integer.")
		}
		q.Limit = n
	}
	for _, name := range strings.Split(in.String("names"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			q.Names = append(q.Names, name)
		}
	}
	page, err := p.audit.Store().Read(ctx, q)
	if err != nil {
		return p.fail(ctx, "query audit", err)
	}
	return endpoint.JSON(http.StatusOK, page.Map())
}

func auditInvalid(detail string) endpoint.Result {
	return endpoint.Problem(http.StatusUnprocessableEntity, "audit/invalid_query", "Invalid query", detail, nil)
}

// statsWindows are the periods the activity series count over.
var statsWindows = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

// stats answers GET /admin/stats: totals, and sign-ups, sign-ins and active users over the last
// day, week and month, counted from the audit tables.
func (p *Plugin) stats(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	if _, res, ok := Authorize(ctx, Read, ""); !ok {
		return res
	}
	now := p.g.Clock().Now().UTC()
	var errs []error
	count := func(table string, c store.Criteria) int64 {
		n, err := p.g.DB().Count(ctx, table, c)
		errs = append(errs, err)
		return n
	}
	series := func(table, column string, c store.Criteria) map[string]any {
		out := map[string]any{}
		for window, d := range statsWindows {
			wc := maps.Clone(c)
			wc[column] = store.Gte(now.Add(-d))
			out[window] = count(table, wc)
		}
		return out
	}
	data := map[string]any{
		"generated_at": now.Format(dateAtom),
		"totals": map[string]any{
			"users":           count("auth_users", store.Criteria{}),
			"organizations":   count("auth_organizations", store.Criteria{"status": model.OrganizationStatusActive}),
			"active_sessions": count("auth_refresh_tokens", store.Criteria{"revoked_at": nil, "expires_at": store.Gt(now)}),
		},
		"sign_ups":     series(audit.TableEvents, "occurred_at", store.Criteria{"name": audit.UserSignedUp}),
		"sign_ins":     series(audit.TableEvents, "occurred_at", store.Criteria{"name": audit.SessionSignedIn}),
		"active_users": series(audit.TableActivity, "last_active_at", store.Criteria{}),
	}
	if err := errors.Join(errs...); err != nil {
		return p.fail(ctx, "stats", err)
	}
	return success(data)
}

// scopeOrg checks an input scope: "" for the instance, the organization id when it exists; ok
// false with the answer otherwise.
func (p *Plugin) scopeExists(ctx context.Context, scope string) (endpoint.Result, bool) {
	if scope == ScopeInstance {
		return endpoint.Result{}, true
	}
	_, err := p.g.Repos().Organizations.Get(ctx, scope)
	if errors.Is(err, repository.ErrNotFound) {
		return Invalid(msgBadScope), false
	}
	if err != nil {
		return p.fail(ctx, "load organization", err), false
	}
	return endpoint.Result{}, true
}

// listKeys answers GET /admin/keys: every key, never the secrets.
func (p *Plugin) listKeys(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	if _, res, ok := Authorize(ctx, Own, ""); !ok {
		return res
	}
	keys, err := p.keys.All(ctx)
	if err != nil {
		return p.fail(ctx, "list keys", err)
	}
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Map())
	}
	return success(out)
}

// createKey answers POST /admin/keys: the secret is in this response only.
func (p *Plugin) createKey(ctx context.Context, in *endpoint.Input) endpoint.Result {
	scope := cmp.Or(in.String("scope"), ScopeInstance)
	op, res, ok := Authorize(ctx, Own, orgOf(scope))
	if !ok {
		return res
	}
	name := strings.Trim(in.String("name"), blankSet)
	if name == "" || utf8.RuneCountInString(name) > keyNameMax {
		return Invalid("name must be 1 to 120 characters.")
	}
	role, valid := ParseRole(in.String("role"))
	if !valid {
		return Invalid("role must be viewer, support, admin or owner.")
	}
	allow, valid := nonEmptyStrings(in.Value("ip_allowlist"))
	for _, entry := range allow {
		valid = valid && ValidAllowlistEntry(entry)
	}
	if !valid {
		return Invalid("ip_allowlist must be a list of addresses or CIDR blocks.")
	}
	expiresAt, valid := parseTime(in.Value("expires_at"))
	if !valid {
		return Invalid("expires_at must be an ISO-8601 datetime.")
	}
	if res, ok := p.scopeExists(ctx, scope); !ok {
		return res
	}
	key, secret, err := p.keys.Create(ctx, Key{Name: name, Role: role, Scope: scope, IPAllowlist: allow, ExpiresAt: expiresAt, CreatedBy: op.ID})
	if err != nil {
		return p.fail(ctx, "create key", err)
	}
	view := key.Map()
	view["key"] = secret
	return p.recorded(ctx, endpoint.Data(http.StatusCreated, view), AuditKeyCreated, op, key.ID, orgOf(scope),
		map[string]any{"name": name, "role": string(role)})
}

// deleteKey answers DELETE /admin/keys/{id}: the key stops working at once.
func (p *Plugin) deleteKey(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := Authorize(ctx, Own, "")
	if !ok {
		return res
	}
	id := in.String("id")
	deleted, err := p.keys.Delete(ctx, id)
	if err != nil {
		return p.fail(ctx, "delete key", err)
	}
	if !deleted {
		return NotFound("The key does not exist.")
	}
	return p.recorded(ctx, status("deleted"), AuditKeyDeleted, op, id, "", nil)
}

// listGrants answers GET /admin/grants.
func (p *Plugin) listGrants(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	if _, res, ok := Authorize(ctx, Own, ""); !ok {
		return res
	}
	grants, err := p.grants.All(ctx)
	if err != nil {
		return p.fail(ctx, "list grants", err)
	}
	out := make([]any, 0, len(grants))
	for _, g := range grants {
		out = append(out, g.Map())
	}
	return success(out)
}

// createGrant answers POST /admin/grants: a user's operator role, replacing their previous grant.
func (p *Plugin) createGrant(ctx context.Context, in *endpoint.Input) endpoint.Result {
	scope := cmp.Or(in.String("scope"), ScopeInstance)
	op, res, ok := Authorize(ctx, Own, orgOf(scope))
	if !ok {
		return res
	}
	userID := in.String("user_id")
	if userID == "" {
		return Invalid("user_id is required.")
	}
	role, valid := ParseRole(in.String("role"))
	if !valid {
		return Invalid("role must be viewer, support, admin or owner.")
	}
	expiresAt, valid := parseTime(in.Value("expires_at"))
	if !valid {
		return Invalid("expires_at must be an ISO-8601 datetime.")
	}
	if _, res, found := p.user(ctx, userID); !found {
		return res
	}
	if res, ok := p.scopeExists(ctx, scope); !ok {
		return res
	}
	grant, err := p.grants.Grant(ctx, Grant{UserID: userID, Role: role, Scope: scope, ExpiresAt: expiresAt, GrantedBy: op.ID})
	if err != nil {
		return p.fail(ctx, "create grant", err)
	}
	return p.recorded(ctx, endpoint.Data(http.StatusCreated, grant.Map()), AuditGrantCreated, op, userID, orgOf(scope),
		map[string]any{"grant_id": grant.ID, "role": string(role)})
}

// deleteGrant answers DELETE /admin/grants/{id}: the user is an operator no more.
func (p *Plugin) deleteGrant(ctx context.Context, in *endpoint.Input) endpoint.Result {
	op, res, ok := Authorize(ctx, Own, "")
	if !ok {
		return res
	}
	id := in.String("id")
	grant, found, err := p.grants.Find(ctx, id)
	if err != nil {
		return p.fail(ctx, "delete grant", err)
	}
	if found {
		found, err = p.grants.Revoke(ctx, id)
	}
	if err != nil {
		return p.fail(ctx, "delete grant", err)
	}
	if !found {
		return NotFound("The grant does not exist.")
	}
	return p.recorded(ctx, status("deleted"), AuditGrantDeleted, op, grant.UserID, orgOf(grant.Scope), map[string]any{"grant_id": id})
}
