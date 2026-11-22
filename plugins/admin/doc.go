// Package admin is the admin plugin: the operator API under /admin over
// users, sessions, MFA, organizations, audit drains and statistics, for admin users and operator
// API keys, every action recorded in the audit trail as admin.<action>. It needs the audit plugin
// (any registration order).
//
//	p, err := polaris.New(polaris.Config{
//		Secrets: secrets, Auth: auth, DB: db,
//		Plugins: []polaris.Plugin{audit.New(audit.Config{}), admin.New(admin.Config{})},
//	})
//	// the first operator:
//	admin.Of(p.Graph()).Grants().Grant(ctx, admin.Grant{UserID: id, Role: admin.RoleOwner})
//	_, secret, err := admin.Of(p.Graph()).Keys().Create(ctx, admin.Key{Name: "dashboard", Role: admin.RoleViewer})
//
// # Operators
//
// A caller of an admin route is a Principal: a user holding core's superadmin role (an owner on
// the instance, no grant needed), a user with a live Grant (one per user: a role, a scope, an
// optional expiry), or an operator API key ("Authorization: Bearer pak_…": a role, a scope, an
// optional IP allowlist and expiry, stored as a keyed hash, shown once). An impersonation token
// is never an operator (403 admin/impersonation_denied); a disabled user is no operator, a lapsed
// grant or key is refused (401 admin/unauthorized). The scope is ScopeInstance or one
// organization id; an organization-scoped operator acts on that organization only.
//
// The role matrix, deny by default, each role including the ones below it:
//
//	capability   viewer support admin owner
//	Read           ✓      ✓      ✓     ✓    users, sessions, MFA, organizations, audit, stats
//	Support               ✓      ✓     ✓    revoke sessions
//	Manage                       ✓     ✓    ban, passwords, MFA, member roles, deletions
//	Impersonate                  ✓     ✓    impersonate a user
//	Own                                ✓    grants, API keys, drains, other plugins' admin routes
//
// Manage on an account (ban, unban, password, MFA, delete) does not reach up: below owner, an
// operator is refused (403 admin/forbidden) on the account of a superadmin or of an operator whose
// grant is of its own role or above.
//
// # Admin routes of other plugins (agents, oauth, scim)
//
// A plugin adds an admin route by declaring it in its own manifest with tags: [admin, …] and
// auth: public (core's bearer step leaves pak_ keys alone); the admin middleware then resolves
// the operator before the endpoint runs, and the endpoint starts with Authorize:
//
//	func revoke(ctx context.Context, in *endpoint.Input) endpoint.Result {
//		agent := find(in.String("id"))
//		op, res, ok := admin.Authorize(ctx, admin.Own, agent.OrganizationID) // "" for the instance
//		if !ok {
//			return res // 401 admin/unauthorized, 403 admin/forbidden or admin/impersonation_denied
//		}
//		…
//		admin.Of(g).Record(ctx, "agents.revoked_by_operator", op, agent.ID, agent.OrganizationID, nil)
//		return endpoint.Data(200, …)
//	}
//
// Operator(ctx) returns the resolved operator without a capability check (to default a filter to
// an organization-scoped operator's organization); NotFound, Conflict, Invalid and Forbidden
// answer the other admin/* problem documents. Outside the admin routes, (*Plugin).OperatorOf
// resolves the operator of any request, IsOperator says whether a bare credential is an
// operator's (the MCP server), and Resolve gives the full Resolution. A plugin that does not
// import this package type-asserts g.Plugin("admin") to an interface with AuthorizeOperator (and
// OperatorID for the operator's user or API key id).
// Principal.Allows and Principal.Covers check a capability and a scope.
//
// # Impersonation
//
// POST /admin/users/{id}/impersonate answers an access token whose sub is the user, with amr
// ["impersonation"], mfa false, the impersonated_by and impersonator_type claims and no session:
// it cannot be refreshed, stepped up, switched or logged out, and lives one access-token TTL. A
// superadmin cannot be impersonated; a disabled or locked account is refused.
package admin
