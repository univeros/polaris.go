package agents

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/univeros/polaris.go/store"
)

// Owner types, modes, credentials and statuses of an agent.
const (
	OwnerUser         = "user"
	OwnerOrganization = "organization"

	ModeDelegated  = "delegated"
	ModeAutonomous = "autonomous"

	AuthPrivateKeyJWT  = "private_key_jwt"
	AuthClientSecret   = "client_secret"
	AuthDelegatedToken = "delegated_token"

	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusRevoked   = "revoked"
	// A registration through the Agent Auth Protocol that a person must approve, and one denied.
	StatusExpired  = "expired" // past its lifetimes (Lifetimes); computed, never stored
	StatusPending  = "pending"
	StatusRejected = "rejected"
)

// Grant statuses, budget kinds and the auto-approval marker.
const (
	GrantActive    = "active"
	GrantPending   = "pending"
	GrantDenied    = "denied"
	GrantRevoked   = "revoked"
	GrantExhausted = "exhausted"

	BudgetCount  = "count"
	BudgetAmount = "amount"

	ViaAuto = "auto"
)

// Approval methods and statuses.
const (
	MethodDevice = "device_authorization"
	MethodCIBA   = "ciba"
	MethodInApp  = "in_app"

	ApprovalPending   = "pending"
	ApprovalApproved  = "approved"
	ApprovalDenied    = "denied"
	ApprovalExpired   = "expired"
	ApprovalCancelled = "cancelled"
)

// Receipt outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeFailed  = "failed"
	OutcomeSealed  = "sealed"
)

var (
	modes   = []string{ModeDelegated, ModeAutonomous}
	auths   = []string{AuthPrivateKeyJWT, AuthClientSecret, AuthDelegatedToken}
	methods = []string{MethodDevice, MethodCIBA, MethodInApp}
)

// timestamp is how the API writes a time: RFC 3339 in UTC, to the second ("Z").
func timestamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func timestampPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return timestamp(*t)
}

// null is nil for "", s otherwise: an optional column or JSON member.
func null(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}

// rowTime reads a datetime column.
func rowTime(r store.Row, col string) time.Time {
	t, _ := r.Time(col)
	return t
}

// rowInt reads a nullable integer column.
func rowInt(r store.Row, col string) *int64 {
	if r[col] == nil {
		return nil
	}
	n := r.Int(col)
	return &n
}

// rowJSON decodes a JSON column keeping numbers as json.Number: exact, as the request held them
// (an operand of 2^60 does not round through float64).
func rowJSON(r store.Row, col string) any {
	s, ok := r.NullString(col)
	if !ok || s == "" {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(s)))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil {
		return nil
	}
	return v
}

func jsonColumn(v any) any {
	s, err := store.JSONValue(v)
	if err != nil {
		return nil // only values this package built reach here
	}
	return s
}

func strings_(v any) []string {
	items, _ := v.([]any)
	out := []string{}
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Agent is an agent (polaris_agent). Its ID is the client_id of its OAuth client. A delegated agent
// acts for its owner; an autonomous one acts as itself, within its owner's authority.
type Agent struct {
	ID             string
	OwnerType      string // OwnerUser or OwnerOrganization
	OwnerID        string
	OrganizationID string // "" for none
	Name           string
	Mode           string // ModeDelegated or ModeAutonomous
	HostID         string // "" unless a host enrolled it
	Auth           string // AuthPrivateKeyJWT, AuthClientSecret or AuthDelegatedToken
	PublicJWK      map[string]any
	Status         string
	CreatedBy      string
	SealedAt       *time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
	ActivatedAt    *time.Time // when an agent a host's JWT registered was last activated; nil before
	LastUsedAt     *time.Time // its last request, to the minute; nil for other agents

	keyThumbprint string // of its key, when a host's JWT registered it: such a key is one agent of its host
}

// Subject is the user the agent acts as or for: its owner, or for an organization's agent the
// member who registered it.
func (a Agent) Subject() string {
	if a.OwnerType == OwnerUser {
		return a.OwnerID
	}
	return a.CreatedBy
}

// ofHostJWT reports whether a host's JWT registered the agent (Agent Auth Protocol), so its host has a key.
func (a Agent) ofHostJWT() bool { return a.keyThumbprint != "" }

// Active reports whether the agent may act.
func (a Agent) Active() bool { return a.Status == StatusActive }

func (a Agent) view() map[string]any {
	var jwk any
	if a.PublicJWK != nil {
		jwk = a.PublicJWK
	}
	return map[string]any{
		"id": a.ID, "owner_type": a.OwnerType, "owner_id": a.OwnerID, "organization_id": null(a.OrganizationID),
		"name": a.Name, "mode": a.Mode, "host_id": null(a.HostID), "auth": a.Auth, "public_jwk": jwk,
		"status": a.Status, "created_by": a.CreatedBy, "sealed_at": timestampPtr(a.SealedAt),
		"created_at": timestamp(a.CreatedAt), "updated_at": timestamp(a.UpdatedAt),
	}
}

func (a Agent) row() store.Row {
	var jwk any
	if a.PublicJWK != nil {
		jwk = jsonColumn(a.PublicJWK)
	}
	return store.Row{
		"id": a.ID, "owner_type": a.OwnerType, "owner_id": a.OwnerID, "organization_id": null(a.OrganizationID),
		"name": a.Name, "mode": a.Mode, "host_id": null(a.HostID), "auth": a.Auth, "public_jwk": jwk,
		"status": a.Status, "created_by": a.CreatedBy, "sealed_at": store.Nullable(a.SealedAt),
		"created_at": a.CreatedAt, "updated_at": a.UpdatedAt, "key_thumbprint": null(a.keyThumbprint),
		"activated_at": store.Nullable(a.ActivatedAt), "last_used_at": store.Nullable(a.LastUsedAt),
	}
}

func agentFromRow(r store.Row) Agent {
	a := Agent{
		ID: r.String("id"), OwnerType: r.String("owner_type"), OwnerID: r.String("owner_id"),
		OrganizationID: r.String("organization_id"), Name: r.String("name"), Mode: r.String("mode"),
		HostID: r.String("host_id"), Auth: r.String("auth"), Status: r.String("status"),
		CreatedBy: r.String("created_by"), SealedAt: r.TimePtr("sealed_at"),
		CreatedAt: rowTime(r, "created_at"), UpdatedAt: rowTime(r, "updated_at"), keyThumbprint: r.String("key_thumbprint"),
		ActivatedAt: r.TimePtr("activated_at"), LastUsedAt: r.TimePtr("last_used_at"),
	}
	if jwk, ok := rowJSON(r, "public_jwk").(map[string]any); ok {
		a.PublicJWK = jwk
	}
	return a
}

// Host is a runtime that enrols agents (polaris_agent_host): with its enrolment token, or, when it has
// a key, with JWTs it signs (the Agent Auth Protocol).
type Host struct {
	ID                  string
	OwnerType           string
	OwnerID             string
	OrganizationID      string
	Name                string
	DefaultCapabilities []string
	CreatedBy           string
	RevokedAt           *time.Time
	CreatedAt           time.Time
	PublicJWK           map[string]any // the host's Ed25519 key; nil with a JWKSURL or an enrolment token
	JWKSURL             string         // where the host publishes its keys; "" unless it does
	KeyThumbprint       string         // RFC 7638, of the key it signs with; "" before a JWKS host's first call

	tokenHash         string
	claimedThumbprint string // of the key it was rotated to, until that key's holder shows it knows the host
}

// hasKey reports whether the host signs with a key of its own.
func (h Host) hasKey() bool { return h.PublicJWK != nil || h.JWKSURL != "" }

func (h Host) view() map[string]any {
	out := map[string]any{
		"id": h.ID, "owner_type": h.OwnerType, "owner_id": h.OwnerID, "organization_id": null(h.OrganizationID),
		"name": h.Name, "default_capabilities": h.DefaultCapabilities, "created_by": h.CreatedBy,
		"revoked_at": timestampPtr(h.RevokedAt), "created_at": timestamp(h.CreatedAt),
	}
	if h.hasKey() {
		out["jwks_url"], out["key_thumbprint"], out["public_jwk"] = null(h.JWKSURL), null(h.KeyThumbprint), nil
		if h.PublicJWK != nil {
			out["public_jwk"] = h.PublicJWK
		}
	}
	return out
}

func (h Host) row() store.Row {
	var jwk any
	if h.PublicJWK != nil {
		jwk = jsonColumn(h.PublicJWK)
	}
	return store.Row{
		"id": h.ID, "owner_type": h.OwnerType, "owner_id": h.OwnerID, "organization_id": null(h.OrganizationID),
		"name": h.Name, "enrollment_token_hash": h.tokenHash, "default_capabilities": jsonColumn(h.DefaultCapabilities),
		"created_by": h.CreatedBy, "revoked_at": store.Nullable(h.RevokedAt), "created_at": h.CreatedAt,
		"public_jwk": jwk, "jwks_url": null(h.JWKSURL), "key_thumbprint": null(h.KeyThumbprint),
		"claimed_thumbprint": null(h.claimedThumbprint),
	}
}

func hostFromRow(r store.Row) Host {
	h := Host{
		ID: r.String("id"), OwnerType: r.String("owner_type"), OwnerID: r.String("owner_id"),
		OrganizationID: r.String("organization_id"), Name: r.String("name"),
		DefaultCapabilities: strings_(rowJSON(r, "default_capabilities")), CreatedBy: r.String("created_by"),
		RevokedAt: r.TimePtr("revoked_at"), CreatedAt: rowTime(r, "created_at"), tokenHash: r.String("enrollment_token_hash"),
		JWKSURL: r.String("jwks_url"), KeyThumbprint: r.String("key_thumbprint"), claimedThumbprint: r.String("claimed_thumbprint"),
	}
	if jwk, ok := rowJSON(r, "public_jwk").(map[string]any); ok {
		h.PublicJWK = jwk
	}
	return h
}

// Grant is a capability grant (polaris_agent_grant): the agent may execute the capability within
// the constraints on its arguments and its budget, until it expires, is revoked or is exhausted.
type Grant struct {
	ID          string
	AgentID     string
	Capability  string
	Constraints map[string]map[string]any // argument → operator → operand
	BudgetKind  string                    // "" (no budget), BudgetCount or BudgetAmount
	BudgetTotal *int64
	// BudgetRemaining is what is left; inside a handler, after this execution was charged.
	BudgetRemaining *int64
	BudgetField     string
	Status          string
	GrantedBy       string
	ApprovedVia     string
	ApprovalID      string
	ExpiresAt       *time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// Live reports whether the grant can be used at now.
func (g Grant) Live(now time.Time) bool {
	return g.Status == GrantActive && (g.ExpiresAt == nil || g.ExpiresAt.After(now))
}

func (g Grant) view() map[string]any {
	var budget any
	if g.BudgetKind != "" {
		budget = map[string]any{"kind": g.BudgetKind, "total": nullInt(g.BudgetTotal), "remaining": nullInt(g.BudgetRemaining), "field": null(g.BudgetField)}
	}
	return map[string]any{
		"id": g.ID, "agent_id": g.AgentID, "capability": g.Capability, "constraints": constraintsValue(g.Constraints),
		"budget": budget, "status": g.Status, "granted_by": null(g.GrantedBy), "approved_via": null(g.ApprovedVia),
		"approval_id": null(g.ApprovalID), "expires_at": timestampPtr(g.ExpiresAt),
		"created_at": timestamp(g.CreatedAt), "updated_at": timestamp(g.UpdatedAt),
	}
}

func constraintsValue(c map[string]map[string]any) map[string]any {
	out := make(map[string]any, len(c))
	for k, v := range c {
		out[k] = v
	}
	return out
}

func (g Grant) row() store.Row {
	return store.Row{
		"id": g.ID, "agent_id": g.AgentID, "capability": g.Capability, "constraints": jsonColumn(constraintsValue(g.Constraints)),
		"budget_total": nullInt(g.BudgetTotal), "budget_remaining": nullInt(g.BudgetRemaining),
		"budget_kind": null(g.BudgetKind), "budget_field": null(g.BudgetField), "status": g.Status,
		"granted_by": null(g.GrantedBy), "approved_via": null(g.ApprovedVia), "approval_id": null(g.ApprovalID),
		"expires_at": store.Nullable(g.ExpiresAt), "created_at": g.CreatedAt, "updated_at": g.UpdatedAt,
	}
}

func grantFromRow(r store.Row) Grant {
	g := Grant{
		ID: r.String("id"), AgentID: r.String("agent_id"), Capability: r.String("capability"),
		Constraints: map[string]map[string]any{}, BudgetTotal: rowInt(r, "budget_total"),
		BudgetRemaining: rowInt(r, "budget_remaining"), BudgetKind: r.String("budget_kind"),
		BudgetField: r.String("budget_field"), Status: r.String("status"), GrantedBy: r.String("granted_by"),
		ApprovedVia: r.String("approved_via"), ApprovalID: r.String("approval_id"), ExpiresAt: r.TimePtr("expires_at"),
		CreatedAt: rowTime(r, "created_at"), UpdatedAt: rowTime(r, "updated_at"),
	}
	if c, ok := rowJSON(r, "constraints").(map[string]any); ok {
		for field, ops := range c {
			switch m := ops.(type) {
			case map[string]any:
				g.Constraints[field] = m
			case []any: // rows written by earlier releases hold [] for no operators
				g.Constraints[field] = map[string]any{}
			}
		}
	}
	return g
}

// Approval is a person's pending decision on grants an agent asked for (polaris_agent_approval).
type Approval struct {
	ID             string
	AgentID        string
	GrantIDs       []string
	Method         string
	Strength       string
	UserCode       string
	BindingMessage string
	Status         string
	DecidedBy      string
	ExpiresAt      time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time

	reused bool // opened by an earlier request, which this one repeats
}

// Pending reports whether the approval still waits for a decision at now.
func (a Approval) Pending(now time.Time) bool {
	return a.Status == ApprovalPending && a.ExpiresAt.After(now)
}

func (a Approval) view() map[string]any {
	return map[string]any{
		"id": a.ID, "agent_id": a.AgentID, "grant_ids": a.GrantIDs, "method": a.Method, "strength": a.Strength,
		"user_code": a.UserCode, "binding_message": null(a.BindingMessage), "status": a.Status,
		"decided_by": null(a.DecidedBy), "expires_at": timestamp(a.ExpiresAt), "created_at": timestamp(a.CreatedAt),
		"updated_at": timestamp(a.UpdatedAt),
	}
}

func (a Approval) row() store.Row {
	return store.Row{
		"id": a.ID, "agent_id": a.AgentID, "grant_ids": jsonColumn(a.GrantIDs), "method": a.Method,
		"strength": a.Strength, "user_code": a.UserCode, "binding_message": null(a.BindingMessage),
		"status": a.Status, "decided_by": null(a.DecidedBy), "expires_at": a.ExpiresAt,
		"created_at": a.CreatedAt, "updated_at": a.UpdatedAt,
	}
}

func approvalFromRow(r store.Row) Approval {
	return Approval{
		ID: r.String("id"), AgentID: r.String("agent_id"), GrantIDs: strings_(rowJSON(r, "grant_ids")),
		Method: r.String("method"), Strength: r.String("strength"), UserCode: r.String("user_code"),
		BindingMessage: r.String("binding_message"), Status: r.String("status"), DecidedBy: r.String("decided_by"),
		ExpiresAt: rowTime(r, "expires_at"), CreatedAt: rowTime(r, "created_at"), UpdatedAt: rowTime(r, "updated_at"),
	}
}

// Receipt is one execution in an agent's hash chain (polaris_agent_receipt), signed with core's
// key. The arguments are kept as a hash only.
type Receipt struct {
	ID           string
	AgentID      string
	Seq          int64
	GrantID      string
	Capability   string
	InputHash    string
	Outcome      string
	BudgetBefore *int64
	BudgetAfter  *int64
	PrevHash     string
	Hash         string
	Signature    string
	CreatedAt    time.Time
}

// receiptTime is the layout of a receipt's created_at: the hash and signature cover that text, and
// verifiers (this plugin, the agent SDK) hash it as sent, so it keeps the form every receipt issued
// so far was hashed in, UTC written "+00:00". Unlike the other times the API writes, it is not "Z".
const receiptTime = "2006-01-02T15:04:05-07:00"

// hashed is what the hash covers.
func (r Receipt) hashed() map[string]any {
	return map[string]any{
		"agent_id": r.AgentID, "budget_after": nullInt(r.BudgetAfter), "budget_before": nullInt(r.BudgetBefore),
		"capability": null(r.Capability), "created_at": r.CreatedAt.UTC().Format(receiptTime), "grant_id": null(r.GrantID),
		"id": r.ID, "input_hash": r.InputHash, "outcome": r.Outcome, "prev_hash": null(r.PrevHash), "seq": r.Seq,
	}
}

func (r Receipt) view() map[string]any {
	v := r.hashed()
	v["hash"], v["signature"] = r.Hash, r.Signature
	return v
}

func (r Receipt) row() store.Row {
	return store.Row{
		"id": r.ID, "agent_id": r.AgentID, "seq": r.Seq, "grant_id": null(r.GrantID), "capability": null(r.Capability),
		"input_hash": r.InputHash, "outcome": r.Outcome, "budget_before": nullInt(r.BudgetBefore),
		"budget_after": nullInt(r.BudgetAfter), "prev_hash": null(r.PrevHash), "hash": r.Hash,
		"signature": r.Signature, "created_at": r.CreatedAt,
	}
}

func receiptFromRow(r store.Row) Receipt {
	return Receipt{
		ID: r.String("id"), AgentID: r.String("agent_id"), Seq: r.Int("seq"), GrantID: r.String("grant_id"),
		Capability: r.String("capability"), InputHash: r.String("input_hash"), Outcome: r.String("outcome"),
		BudgetBefore: rowInt(r, "budget_before"), BudgetAfter: rowInt(r, "budget_after"),
		PrevHash: r.String("prev_hash"), Hash: r.String("hash"), Signature: r.String("signature"),
		CreatedAt: rowTime(r, "created_at"),
	}
}
