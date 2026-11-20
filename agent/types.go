package agent

import (
	"encoding/json"
	"time"
)

// Mode is how an agent acts: for its owner (Delegated) or as itself (Autonomous).
type Mode string

// The agent modes.
const (
	Delegated  Mode = "delegated"
	Autonomous Mode = "autonomous"
)

// Auth is how an agent authenticates at the token endpoint.
type Auth string

// The agent authentication methods.
const (
	PrivateKeyJWT  Auth = "private_key_jwt" // the agent's key signs assertions and request JWTs
	ClientSecret   Auth = "client_secret"   // a pcs_ secret, shown once at registration
	DelegatedToken Auth = "delegated_token" // a public client that only exchanges its user's token
)

// Configuration is the discovery document, GET <mount>/.well-known/agent-configuration.
type Configuration struct {
	Version           string            `json:"version"`
	ProviderName      string            `json:"provider_name"`
	Description       string            `json:"description"`
	Issuer            string            `json:"issuer"`
	DefaultLocation   string            `json:"default_location"`
	Algorithms        []string          `json:"algorithms"`
	Modes             []string          `json:"modes"`
	ApprovalMethods   []string          `json:"approval_methods"`
	ApprovalStrengths map[string]string `json:"approval_strengths"`
	// Endpoints are the absolute URLs by name (register, enroll, execute, token, mcp, ...).
	Endpoints     map[string]string `json:"-"`
	TokenEndpoint string            `json:"token_endpoint"`
	// Mount is where Polaris lives (prefix included), read off the execute endpoint; every route
	// the SDK calls is under it.
	Mount string `json:"-"`
}

// MCPEndpoint is the MCP server's URL when the server registers the mcp plugin, else "".
func (c *Configuration) MCPEndpoint() string { return c.Endpoints["mcp"] }

// Profile is an agent's record.
type Profile struct {
	ID             string     `json:"id"`
	OwnerType      string     `json:"owner_type"`
	OwnerID        string     `json:"owner_id"`
	OrganizationID string     `json:"organization_id"`
	Name           string     `json:"name"`
	Mode           Mode       `json:"mode"`
	HostID         string     `json:"host_id"`
	Auth           Auth       `json:"auth"`
	PublicJWK      *JWK       `json:"public_jwk"`
	Status         string     `json:"status"`
	CreatedBy      string     `json:"created_by"`
	SealedAt       *time.Time `json:"sealed_at"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// Registered is what POST /agents/register and /agents/enroll answer: the agent, its grants, its
// client secret (once, for a client_secret agent) and the approval its pending grants wait for.
type Registered struct {
	Profile
	ClientSecret string    `json:"client_secret"`
	Grants       []Grant   `json:"grants"`
	Approval     *Approval `json:"approval"`
}

// Registration is the agent POST /agents/register (and, name, mode and auth only,
// /agents/enroll) creates.
type Registration struct {
	Name string
	Mode Mode
	// Auth defaults to PrivateKeyJWT when the agent has a key (its public JWK is sent), else
	// ClientSecret.
	Auth Auth
	// OrganizationID registers the agent for an organization (register only).
	OrganizationID string
	// Capabilities are requested with the registration (register only).
	Capabilities []CapabilityRequest
}

// CapabilityRequest names a capability, optionally with constraints on its arguments (max, min,
// in, not_in, pattern per argument, and budget).
type CapabilityRequest struct {
	Name        string
	Constraints map[string]any
}

// MarshalJSON sends a bare name, or {name, constraints} when there are constraints.
func (c CapabilityRequest) MarshalJSON() ([]byte, error) {
	if c.Constraints == nil {
		return json.Marshal(c.Name)
	}
	return json.Marshal(struct {
		Name        string         `json:"name"`
		Constraints map[string]any `json:"constraints"`
	}{c.Name, c.Constraints})
}

// Grant is a capability granted to an agent, with its constraints, budget and status (active,
// pending, denied, revoked, exhausted).
type Grant struct {
	ID         string `json:"id"`
	AgentID    string `json:"agent_id"`
	Capability string `json:"capability"`
	// Constraints are as the server stored them ([] when there are none).
	Constraints json.RawMessage `json:"constraints"`
	Budget      *Budget         `json:"budget"`
	Status      string          `json:"status"`
	GrantedBy   string          `json:"granted_by"`
	ApprovedVia string          `json:"approved_via"`
	ApprovalID  string          `json:"approval_id"`
	ExpiresAt   *time.Time      `json:"expires_at"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// Budget is what a grant may still spend: calls (kind count) or an argument's amount.
type Budget struct {
	Kind      string `json:"kind"`
	Total     int    `json:"total"`
	Remaining int    `json:"remaining"`
	Field     string `json:"field"`
}

// Approval is a pending approval: the person approves it by device code (UserCode at
// VerificationURI), CIBA (BindingMessage pushed to them) or in their own app.
type Approval struct {
	ID                      string `json:"id"`
	Method                  string `json:"method"`
	Strength                string `json:"strength"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	// ExpiresIn and Interval are seconds.
	ExpiresIn      int    `json:"expires_in"`
	Interval       int    `json:"interval"`
	BindingMessage string `json:"binding_message"`
}

// GrantRequest is what POST /agents/grants/request asks for.
type GrantRequest struct {
	Capabilities []CapabilityRequest `json:"capabilities"`
	Reason       string              `json:"reason,omitempty"`
	// PreferredMethod is device_authorization, ciba or in_app.
	PreferredMethod string `json:"preferred_method,omitempty"`
	BindingMessage  string `json:"binding_message,omitempty"`
}

// GrantResult is AAP's answer to a grant request: the grants (what the policy approved is active
// at once) and, when some wait for a person, the Approval to wait for.
type GrantResult struct {
	AgentID  string    `json:"agent_id"`
	Grants   []Grant   `json:"agent_capability_grants"`
	Approval *Approval `json:"approval"`
}

// Session is GET /agents/session: the agent, its owner, its host and its grants with their
// remaining budgets.
type Session struct {
	Agent          Profile `json:"agent"`
	Mode           Mode    `json:"mode"`
	Owner          Owner   `json:"owner"`
	OrganizationID string  `json:"organization_id"`
	Host           *Host   `json:"host"`
	// AuthenticatedVia is jwt (a request JWT) or oauth (an access token).
	AuthenticatedVia string  `json:"authenticated_via"`
	Grants           []Grant `json:"grants"`
}

// Owner is who owns an agent: a user or an organization.
type Owner struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Host is the host an agent enrolled through.
type Host struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Capability is a capability the server offers.
type Capability struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	// Input is the JSON Schema of its arguments.
	Input      json.RawMessage `json:"input"`
	Permission string          `json:"permission"`
	// Risk is low, medium or high.
	Risk string `json:"risk"`
	// Location is the host URL the capability runs at (call it with Agent.Do); empty when it runs
	// through Execute.
	Location string `json:"location"`
	// GrantStatus (active, pending, none) is set when the agent authenticated the listing.
	GrantStatus string `json:"grant_status"`
}

// Result is what POST /agents/execute answers: the handler's result and the receipt appended to
// the agent's chain.
type Result struct {
	Data    json.RawMessage `json:"data"`
	Receipt ReceiptRef      `json:"receipt"`
}

// ReceiptRef identifies a receipt in the agent's chain.
type ReceiptRef struct {
	ID   string `json:"id"`
	Seq  int    `json:"seq"`
	Hash string `json:"hash"`
}

// TokenRequest asks the token endpoint for an access token.
type TokenRequest struct {
	Scope string
	// Resource is the resource the token is for (the MCP endpoint for the MCP server).
	Resource string
	Audience string
	// SubjectToken is a user's access token: set, the request is the RFC 8693 exchange of it for a
	// delegated token; empty, it is client credentials.
	SubjectToken string
}

// Token is an RFC 6749 token response.
type Token struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
	RefreshToken    string `json:"refresh_token"`
	IssuedTokenType string `json:"issued_token_type"`
}
