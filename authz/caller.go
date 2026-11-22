package authz

// Caller is who asks the Gate: an authenticated user and the active organization of the request.
//
// Delegated marks a principal a plugin's bearer resolver built for a delegate (an API key, an
// OAuth client, an agent), with DelegatedPermissions the permissions its owner handed it (decision
// #3). It is set in-process by the resolver, never read from a token on
// the wire; core sessions leave it false. A delegated caller with no permissions holds nothing.
type Caller struct {
	UserID               string
	OrganizationID       string // "" when no organization is active
	Delegated            bool
	DelegatedPermissions []string
	// OrganizationBound marks a session an organization's identity provider opened
	// (token.Token.OrganizationBound): it holds what the user's roles in OrganizationID grant and
	// never the superadmin override, which a tenant's identity provider must not reach.
	OrganizationBound bool
}
