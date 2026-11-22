package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// Route names.
const (
	RouteMe           = "polaris.audit.me"
	RouteOrganization = "polaris.audit.organization"
	RouteTypes        = "polaris.audit.types"
)

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	return map[string]endpoint.Endpoint{
		RouteMe:           endpoint.Func(p.me),
		RouteOrganization: endpoint.Func(p.organization),
		RouteTypes:        endpoint.Func(p.types),
	}
}

// me answers GET /audit/me: the events where the caller is the actor or the subject.
func (p *Plugin) me(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	q, problem, ok := parseQuery(in)
	if !ok {
		return problem
	}
	q.PrincipalID = tok.Subject()
	return p.read(ctx, q)
}

// organization answers GET /audit/organization/{id}: the organization's events, for a member
// with audit.read on their active organization only.
func (p *Plugin) organization(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	orgID := in.String("id")
	if orgID == "" || deniesActiveOrg(ctx, tok, orgID) {
		return endpoint.Problem(http.StatusForbidden, "audit/forbidden", "Forbidden", "That organization is not your active organization.", nil)
	}
	q, problem, ok := parseQuery(in)
	if !ok {
		return problem
	}
	q.OrganizationID = orgID
	return p.read(ctx, q)
}

// types answers GET /audit/types: the catalog.
func (p *Plugin) types(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	if endpoint.Token(ctx) == nil {
		return endpoint.Unauthorized()
	}
	return endpoint.Data(http.StatusOK, p.catalog.Types())
}

func (p *Plugin) read(ctx context.Context, q Query) endpoint.Result {
	page, err := p.store.Read(ctx, q)
	if err != nil {
		p.logger.ErrorContext(ctx, "polaris audit: read failed", "error", err)
		return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
	}
	return endpoint.JSON(http.StatusOK, page.Map())
}

// deniesActiveOrg: orgID is not the token's active organization and the caller is not a
// superadmin (by the authority the gate resolved, else the token's roles claim).
func deniesActiveOrg(ctx context.Context, tok *token.Token, orgID string) bool {
	if a, ok := wiring.Authority(ctx); ok {
		if a.IsSuperadmin() {
			return false
		}
	} else if roles, _ := tok.Claim("roles").([]any); slices.Contains(roles, any(authz.RoleSuperadmin)) {
		return false
	}
	return orgID != tok.Organization()
}

func invalidQuery(detail string) endpoint.Result {
	return endpoint.Problem(http.StatusUnprocessableEntity, "audit/invalid_query", "Invalid query", detail, nil)
}

// parseQuery reads names, from, to, cursor and limit, or the 422 problem to answer.
func parseQuery(in *endpoint.Input) (Query, endpoint.Result, bool) {
	from, okFrom := parseTime(in.Value("from"))
	to, okTo := parseTime(in.Value("to"))
	if !okFrom || !okTo {
		return Query{}, invalidQuery("from and to must be ISO-8601 datetimes."), false
	}
	q := Query{From: from, To: to, Cursor: in.String("cursor")}
	if raw := in.Value("limit"); raw != nil {
		n, ok := positiveInt(raw)
		if !ok {
			return Query{}, invalidQuery("limit must be a positive integer."), false
		}
		q.Limit = n
	}
	for _, name := range strings.Split(in.String("names"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			q.Names = append(q.Names, name)
		}
	}
	return q, endpoint.Result{}, true
}

// positiveInt reads a limit of at least 1, clamped to MaxLimit: a JSON integer, or a query value of
// decimal digits only (no sign, spaces, fraction or exponent).
func positiveInt(v any) (int, bool) {
	var s string
	switch v := v.(type) {
	case string:
		s = v
	case json.Number:
		s = v.String()
	default:
		return 0, false
	}
	if s == "" || strings.TrimLeft(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, false
	}
	return min(n, MaxLimit), true
}

// timeLayouts are the ISO-8601 forms accepted for from, to and expiry dates.
var timeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02"}

// parseTime reads an ISO-8601 datetime; zero time for none, ok false when given and invalid.
func parseTime(v any) (time.Time, bool) {
	if v == nil || v == "" {
		return time.Time{}, true
	}
	s, isString := v.(string)
	if !isString {
		return time.Time{}, false
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
