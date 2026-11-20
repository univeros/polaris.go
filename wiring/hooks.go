package wiring

import (
	"context"
	"slices"
	"time"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/token"
)

// Hooks keep the host's own data in step with Polaris accounts and tokens. Every hook is
// optional.
type Hooks struct {
	// OnUserCreated runs inside the transaction that creates an account, on every path that
	// creates one (registration, passwordless and social sign-up, SSO and SCIM provisioning,
	// anonymous guests, Users().Create): write the app's profile row with ctx and it commits or
	// rolls back with the account. An error aborts the creation (the request answers 500).
	OnUserCreated func(ctx context.Context, u User) error
	// OnUserDeleted runs inside the transaction that erases (anonymizes) or removes an account:
	// the self-service erase, the admin and SCIM deletes, guest pruning, Users().Delete. An error
	// aborts the deletion.
	OnUserDeleted func(ctx context.Context, userID string) error
	// Claims adds claims to every access token a Polaris session mints (sign-in, refresh, step-up,
	// organization switch). Names must be the app's own: a registered JWT claim, an OAuth / OIDC
	// protocol claim, a claim Polaris or a plugin sets, or a name starting with "polaris" fails the
	// mint (see session.ReservedClaim); prefer "app_plan" or "https://example.com/plan". Keep it
	// fast: it runs on every refresh.
	Claims func(ctx context.Context, in ClaimsInput) (map[string]any, error)
}

// ClaimsInput is the session an access token is minted for.
type ClaimsInput struct {
	UserID         string
	OrganizationID string   // "" without an active organization
	Roles          []string // role slugs in OrganizationID
	Permissions    []string // permissions embedded in the token (empty unless EmbedScope)
	AMR            []string // how the session authenticated ("pwd", "otp", …)
}

// User is an account as the host sees it: profile and state, never credentials.
type User struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	DisplayName   string     `json:"display_name,omitempty"`
	EmailVerified bool       `json:"email_verified"`
	Status        string     `json:"status"` // "active", "disabled" or "locked"
	MFAEnforced   bool       `json:"mfa_enforced"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at,omitempty"`
}

// UserOf is the host's view of an account row.
func UserOf(u model.User) User {
	out := User{
		ID: u.ID, Email: u.Email, EmailVerified: u.EmailVerifiedAt != nil, Status: u.Status,
		MFAEnforced: u.MFAEnforced, CreatedAt: u.CreatedAt, LastLoginAt: u.LastLoginAt,
	}
	if u.DisplayName != nil {
		out.DisplayName = *u.DisplayName
	}
	if out.Status == "" {
		out.Status = model.UserStatusActive
	}
	return out
}

func (h Hooks) onUserCreated() func(context.Context, model.User) error {
	if h.OnUserCreated == nil {
		return nil
	}
	return func(ctx context.Context, u model.User) error { return h.OnUserCreated(ctx, UserOf(u)) }
}

func (h Hooks) claims() func(context.Context, token.SessionPrincipal) (map[string]any, error) {
	if h.Claims == nil {
		return nil
	}
	return func(ctx context.Context, p token.SessionPrincipal) (map[string]any, error) {
		return h.Claims(ctx, ClaimsInput{
			UserID: p.UserID, OrganizationID: p.OrganizationID, Roles: slices.Clone(p.Roles),
			Permissions: slices.Clone(p.Scope), AMR: slices.Clone(p.AMR),
		})
	}
}
