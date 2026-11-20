package admin

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
)

// Role is an operator role; each includes the ones below it (viewer < support < admin < owner).
type Role string

// The four roles.
const (
	RoleViewer  Role = "viewer"
	RoleSupport Role = "support"
	RoleAdmin   Role = "admin"
	RoleOwner   Role = "owner"
)

// Capability is what an admin route needs (the role matrix of the package doc).
type Capability string

// The capabilities, deny by default.
const (
	// Read users, sessions, MFA factors, organizations, audit, stats.
	Read Capability = "read"
	// Support actions: revoke sessions.
	Support Capability = "support"
	// Manage: ban, set a password, MFA removal and reset, member roles, delete users and organizations.
	Manage Capability = "manage"
	// Impersonate a user.
	Impersonate Capability = "impersonate"
	// Own: grants, API keys, audit drains, and what other plugins hang under /admin.
	Own Capability = "own"
)

// ParseRole returns the role named s; ok is false for anything else.
func ParseRole(s string) (Role, bool) {
	switch r := Role(s); r {
	case RoleViewer, RoleSupport, RoleAdmin, RoleOwner:
		return r, true
	}
	return "", false
}

// Allows reports whether the role has c. An unknown role allows nothing.
func (r Role) Allows(c Capability) bool {
	if _, known := ParseRole(string(r)); !known {
		return false
	}
	switch c {
	case Read:
		return true
	case Support:
		return r != RoleViewer
	case Manage, Impersonate:
		return r == RoleAdmin || r == RoleOwner
	case Own:
		return r == RoleOwner
	}
	return false
}

// Principal types and the instance scope.
const (
	TypeUser      = "user"
	TypeAPIKey    = "api_key"
	ScopeInstance = "instance"
)

// Principal is who calls an admin route: an admin user (a Polaris user with a grant, or a
// superadmin) or an operator API key, with a role and a scope (ScopeInstance, or one organization
// id).
type Principal struct {
	ID    string // the user id, or the API key id
	Type  string // TypeUser or TypeAPIKey
	Role  Role
	Scope string // ScopeInstance or an organization id
}

// Allows reports whether the principal's role has c.
func (p Principal) Allows(c Capability) bool { return p.Role.Allows(c) }

// Covers reports whether the principal may act on organizationID ("" for an instance-level
// action): an instance principal covers everything, an organization-scoped one its organization.
func (p Principal) Covers(organizationID string) bool {
	return p.Scope == ScopeInstance || (organizationID != "" && p.Scope == organizationID)
}

// Resolution is what a credential resolved to: an operator, nobody (Principal nil), or an
// impersonation token, which is never an operator.
type Resolution struct {
	Principal    *Principal
	Impersonated bool
}

type ctxKey struct{}

// Operator returns the operator the admin middleware resolved for the request, ok false when
// there is none (no credential, not an operator, an impersonation token, or a route not tagged
// "admin").
func Operator(ctx context.Context) (Principal, bool) {
	res, _ := ctx.Value(ctxKey{}).(Resolution)
	if res.Principal == nil {
		return Principal{}, false
	}
	return *res.Principal, true
}

// Authorize is the check every admin endpoint starts with: the operator of the request when it may
// perform c on the instance (organizationID "") or on the organization; otherwise ok is false and
// res is the problem to answer (403 admin/impersonation_denied, 401 admin/unauthorized, 403
// admin/forbidden).
//
//	op, res, ok := admin.Authorize(ctx, admin.Own, agent.OrganizationID)
//	if !ok {
//		return res
//	}
func Authorize(ctx context.Context, c Capability, organizationID string) (op Principal, res endpoint.Result, ok bool) {
	resolution, _ := ctx.Value(ctxKey{}).(Resolution)
	switch p := resolution.Principal; {
	case resolution.Impersonated:
		return Principal{}, problem(http.StatusForbidden, "impersonation_denied", "Impersonation denied", "An impersonation token cannot call the admin routes."), false
	case p == nil:
		return Principal{}, problem(http.StatusUnauthorized, "unauthorized", "Unauthorized", "An admin user or an API key is required."), false
	case !p.Allows(c):
		return Principal{}, Forbidden(fmt.Sprintf("The %s role does not allow this action.", p.Role)), false
	case !p.Covers(organizationID):
		return Principal{}, Forbidden("This action is outside the scope of your admin role."), false
	default:
		return *p, endpoint.Result{}, true
	}
}

// AuthorizeOperator is Authorize for a plugin that does not import this package (it
// type-asserts g.Plugin("admin") to an interface with this method): capability is a Capability
// value ("read", "own", …), organizationID "" for the instance; userID is the operator's user id,
// "" for an operator API key; refusal is the problem to answer when ok is false.
func (*Plugin) AuthorizeOperator(ctx context.Context, capability, organizationID string) (userID string, refusal endpoint.Result, ok bool) {
	op, refusal, ok := Authorize(ctx, Capability(capability), organizationID)
	if ok && op.Type == TypeUser {
		userID = op.ID
	}
	return userID, refusal, ok
}

// OperatorID is Operator for a plugin that does not import this package (it type-asserts
// g.Plugin("admin") to an interface with this method): id is the operator's user id or API key
// id, kind TypeUser or TypeAPIKey; ok is false when the request has no operator.
func (*Plugin) OperatorID(ctx context.Context) (id, kind string, ok bool) {
	op, ok := Operator(ctx)
	return op.ID, op.Type, ok
}

func problem(status int, name, title, detail string) endpoint.Result {
	return endpoint.Problem(status, "admin/"+name, title, detail, nil)
}

// Forbidden answers 403 admin/forbidden.
func Forbidden(detail string) endpoint.Result {
	return problem(http.StatusForbidden, "forbidden", "Forbidden", detail)
}

// NotFound answers 404 admin/not_found.
func NotFound(detail string) endpoint.Result {
	return problem(http.StatusNotFound, "not_found", "Not found", detail)
}

// Conflict answers 409 admin/conflict.
func Conflict(detail string) endpoint.Result {
	return problem(http.StatusConflict, "conflict", "Conflict", detail)
}

// Invalid answers 422 admin/invalid_input; errs, when given, are listed under "errors".
func Invalid(detail string, errs ...string) endpoint.Result {
	var ext map[string]any
	if len(errs) > 0 {
		ext = map[string]any{"errors": errs}
	}
	return endpoint.Problem(http.StatusUnprocessableEntity, "admin/invalid_input", "Invalid input", detail, ext)
}

// ValidAllowlistEntry reports whether entry is an IPv4 or IPv6 address or CIDR block.
func ValidAllowlistEntry(entry string) bool {
	_, ok := parseEntry(entry)
	return ok
}

// AllowlistAllows reports whether ip may use a key with allowlist: an empty list allows anywhere,
// a non-empty one needs a client address inside one entry, of the same family (an IPv4-mapped IPv6
// address does not match an IPv4 block).
func AllowlistAllows(allowlist []string, ip string) bool {
	if len(allowlist) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return false
	}
	for _, entry := range allowlist {
		if prefix, ok := parseEntry(entry); ok && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// parseEntry reads "address" or "address/bits" as a prefix (a plain address is its own /32 or
// /128). Zoned addresses are refused, as PHP's inet_pton refuses them.
func parseEntry(entry string) (netip.Prefix, bool) {
	address, bits, hasBits := strings.Cut(entry, "/")
	addr, err := netip.ParseAddr(address)
	if err != nil || addr.Zone() != "" {
		return netip.Prefix{}, false
	}
	n := addr.BitLen()
	if hasBits {
		if n, err = strconv.Atoi(bits); err != nil || n < 0 || n > addr.BitLen() {
			return netip.Prefix{}, false
		}
	}
	return netip.PrefixFrom(addr, n).Masked(), true
}
