package polaris

import (
	"context"
	"slices"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/token"
)

// Kind is the kind of credential a principal authenticated with.
type Kind = token.Kind

// The principal kinds.
const (
	KindUser        = token.KindUser        // a Polaris session (sign-in) token
	KindAPIKey      = token.KindAPIKey      // an API key (plugins/apikeys)
	KindOAuthClient = token.KindOAuthClient // an OAuth access token (plugins/oauth)
	KindAgent       = token.KindAgent       // an agent's OAuth access token (plugins/agents)
)

// Principal is who is calling: the authenticated user, API key, OAuth client or agent of a request
// that Protect (or a Polaris route) let through. Read it with PrincipalFrom. It is a plain value:
// keep it, log it, pass it to Can.
type Principal struct {
	// UserID is the account acting: the user, the owner of an API key, the user an OAuth client
	// or agent acts for. "" for an OAuth client acting for itself (client credentials).
	UserID string `json:"user_id"`
	// OrganizationID is the active organization, "" when none.
	OrganizationID string `json:"organization_id"`
	// Roles and Permissions are the caller's effective authority in OrganizationID, resolved from
	// the database for this request (a delegated credential's permissions are already intersected
	// with what it may use). Never nil.
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Kind        Kind     `json:"kind"`
	// Delegated is true for an API key, OAuth client or agent acting with a subset of its owner's
	// permissions; such a credential may not self-serve (create organizations, keys, factors).
	Delegated bool `json:"delegated"`
	// ClientID is the OAuth client (KindOAuthClient, KindAgent); AgentID the agent (KindAgent);
	// KeyID the API key (KindAPIKey). "" otherwise.
	ClientID string `json:"client_id,omitempty"`
	AgentID  string `json:"agent_id,omitempty"`
	KeyID    string `json:"key_id,omitempty"`
	// Claims are every claim of the credential, including the app's own (Hooks.Claims).
	Claims map[string]any `json:"claims,omitempty"`

	scope []string // what a delegated credential may use, for Can
}

// PrincipalFrom returns the principal of a request Protect or a Polaris route authenticated. ok
// is false on an unauthenticated request, and when the caller's authority cannot be resolved (the
// database failed; Polaris logs it): treat both as "no principal".
//
// Behind Protect without permissions, the first call resolves the authority (one query) and the
// request keeps it; a handler that never calls PrincipalFrom costs no query. Behind Protect with
// permissions it was resolved already.
//
//	mux.Handle("GET /api/invoices", p.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		who, _ := polaris.PrincipalFrom(r.Context())
//		list(w, who.UserID, who.OrganizationID)
//	}), "invoices.read"))
func PrincipalFrom(ctx context.Context) (Principal, bool) {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return Principal{}, false
	}
	scope, delegated := tok.Delegation()
	clientID, agentID, keyID := token.CredentialIDs(tok)
	p := Principal{
		UserID: tok.Subject(), OrganizationID: tok.Organization(), Roles: []string{}, Permissions: []string{},
		Kind: token.KindOf(tok), Delegated: delegated, ClientID: clientID, AgentID: agentID, KeyID: keyID,
		Claims: tok.Claims(), scope: scope,
	}
	if p.Kind == KindOAuthClient && p.UserID == clientID {
		p.UserID = ""
	}
	resolved, err := endpoint.ResolveAuthority(ctx)
	if err != nil {
		return Principal{}, false
	}
	if a, ok := resolved.(authz.Authority); ok {
		p.Roles, p.Permissions = slices.Clone(a.Roles), slices.Clone(a.Scope)
	}
	return p, true
}

// Can reports whether principal holds every one of permissions in its active organization,
// re-resolved from the database now (roles, superadmin, a disabled user or a suspended membership
// apply at once; a delegated principal is limited to its credential's permissions). Use it for a
// check Protect cannot express, or for a principal outside a request (Principal{UserID: id,
// OrganizationID: org}). With no permissions, or when the database cannot answer (logged), it
// reports false.
func (p *Polaris) Can(ctx context.Context, principal Principal, permissions ...string) bool {
	if len(permissions) == 0 || principal.UserID == "" {
		return false
	}
	caller := authz.Caller{UserID: principal.UserID, OrganizationID: principal.OrganizationID}
	if principal.Delegated {
		caller.Delegated, caller.DelegatedPermissions = true, slices.Clone(principal.scope)
	}
	ok, err := p.graph.Gate().Allows(ctx, caller, permissions...)
	if err != nil {
		p.graph.Logger().ErrorContext(ctx, "polaris: Can could not resolve the authority", "user_id", principal.UserID, "error", err)
		return false
	}
	return ok
}
