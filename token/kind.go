package token

// Kind is the kind of credential a principal authenticated with.
type Kind string

// The principal kinds. A principal a plugin's bearer resolver built is delegated (Delegate); its
// kind follows from the claims that resolver sets in-process.
const (
	KindUser        Kind = "user"         // a Polaris session token
	KindAPIKey      Kind = "api_key"      // plugins/apikeys
	KindOAuthClient Kind = "oauth_client" // plugins/oauth: an OAuth access token
	KindAgent       Kind = "agent"        // plugins/agents: an OAuth access token whose client is an agent
)

// Claims the bearer resolvers set on the principals they build (plugins/agents ClaimAgentID,
// plugins/oauth ClaimClientID, plugins/apikeys ClaimKey). They are read only on delegated
// principals, which never come from the wire (Delegate), so a JWT carrying them proves nothing.
const (
	claimAgentID  = "agent_id"
	claimClientID = "client_id"
	claimAPIKey   = "api_key"
)

// KindOf reports the kind of credential behind t, "" for nil. A Polaris session token is
// KindUser; so is a delegated principal from a resolver this package does not know.
func KindOf(t *Token) Kind {
	if t == nil {
		return ""
	}
	if t.delegation == nil {
		return KindUser
	}
	switch {
	case t.stringClaim(claimAgentID) != "":
		return KindAgent
	case t.stringClaim(claimClientID) != "":
		return KindOAuthClient
	case t.stringClaim(claimAPIKey) != "":
		return KindAPIKey
	}
	return KindUser
}

// CredentialIDs are the ids of the credential behind a delegated principal: the OAuth client (an
// agent's client too), the agent, the API key; "" where not applicable or not delegated.
func CredentialIDs(t *Token) (clientID, agentID, keyID string) {
	if t == nil || t.delegation == nil {
		return "", "", ""
	}
	return t.stringClaim(claimClientID), t.stringClaim(claimAgentID), t.stringClaim(claimAPIKey)
}

func (t *Token) stringClaim(name string) string { s, _ := t.claims[name].(string); return s }
