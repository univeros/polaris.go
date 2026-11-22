package token

import (
	"maps"
	"slices"
)

// delegation is in-process state a bearer resolver attaches to a principal; it never comes from,
// or goes to, the wire.
type delegation struct {
	permissions []string
}

// NewPrincipal builds a principal that did not come from a Polaris JWT: what a plugin's bearer
// resolver (API key, OAuth access token, agent request) returns for the pipeline. claims hold the
// same metadata a session token carries (sub, org, roles, …); Raw is "". The map is copied.
func NewPrincipal(claims map[string]any) *Token {
	return &Token{claims: maps.Clone(claims), header: map[string]any{}}
}

// Delegate returns a copy of t marked as a delegated principal holding at most permissions
// (decision #3): the gate intersects the owner's authority with them and
// drops the owner's superadmin override. Only in-process code can set it; a parsed JWT never
// carries it, whatever its claims say.
func (t *Token) Delegate(permissions []string) *Token {
	cp := *t
	cp.delegation = &delegation{permissions: slices.Clone(permissions)}
	if cp.delegation.permissions == nil {
		cp.delegation.permissions = []string{}
	}
	return &cp
}

// Delegation reports whether t is a delegated principal and the permissions it may use.
func (t *Token) Delegation() (permissions []string, ok bool) {
	if t.delegation == nil {
		return nil, false
	}
	return slices.Clone(t.delegation.permissions), true
}

// AMRSSO is the authentication method (amr) of a session an organization's identity provider
// opened (plugins/sso).
const AMRSSO = "sso"

// OrganizationBound reports whether t is a session an organization's identity provider opened
// (amr holds AMRSSO). Whoever runs that provider can open such a session for any account the
// organization owns, so it speaks for the user in its organization only: it cannot switch
// organization, use the routes reserved to the account holder (pipeline.DeniesBound), or carry
// the superadmin override.
func (t *Token) OrganizationBound() bool {
	switch amr := t.claims["amr"].(type) {
	case []any:
		return slices.Contains(amr, any(AMRSSO))
	case []string:
		return slices.Contains(amr, AMRSSO)
	}
	return false
}

// Organization returns the org claim, "" when absent or null.
func (t *Token) Organization() string { s, _ := t.claims["org"].(string); return s }

// ClaimImpersonatedBy is the claim of a token an operator minted to act as a user (plugins/admin):
// the operator's id.
const ClaimImpersonatedBy = "impersonated_by"

// ImpersonatedBy returns the id of the operator a token acts for its subject on behalf of, "" for
// a token that is not an impersonation. Such a token reads as the user; it is not the account
// holder (pipeline.DeniesImpersonation).
func (t *Token) ImpersonatedBy() string { return t.stringClaim(ClaimImpersonatedBy) }
