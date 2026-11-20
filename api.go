package polaris

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris-go/identity"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/orgs"
	"github.com/univeros/polaris-go/token"
	"github.com/univeros/polaris-go/wiring"
)

// systemActor is the actor recorded (events, audit) for a programmatic call: the host itself.
const systemActor = "system"

// User is an account as the host sees it: profile and state, never credentials.
type User = wiring.User

// Hooks keep the host's own data in step with Polaris accounts and tokens; set Config.Hooks.
type Hooks = wiring.Hooks

// ClaimsInput is the session an access token is minted for (Hooks.Claims).
type ClaimsInput = wiring.ClaimsInput

// NewUser is an account Users().Create makes.
type NewUser struct {
	Email       string
	Password    string // "" for an account that signs in another way (Sessions().Issue, passwordless, social)
	DisplayName string
	// EmailVerified creates the account verified; otherwise the verification email goes out, as
	// on registration.
	EmailVerified bool
}

// Users manages accounts in process, with the same rules, events and audit as the HTTP routes.
// The caller is trusted: no permission is checked (the actor recorded is "system").
type Users struct{ p *Polaris }

// Users returns the account API.
func (p *Polaris) Users() Users { return Users{p} }

// Get returns the account userID (ErrNotFound).
func (u Users) Get(ctx context.Context, userID string) (User, error) {
	m, err := u.p.graph.Repos().Users.Get(ctx, userID)
	if err != nil {
		return User{}, classify(fmt.Errorf("polaris: user %q: %w", userID, err))
	}
	return wiring.UserOf(m), nil
}

// ByEmail returns the account holding email, matched as sign-in matches it (ErrNotFound).
func (u Users) ByEmail(ctx context.Context, email string) (User, error) {
	m, err := u.p.graph.Repos().Users.ByEmail(ctx, identity.NormalizeEmail(email))
	if err != nil {
		return User{}, classify(fmt.Errorf("polaris: user by email: %w", err))
	}
	return wiring.UserOf(m), nil
}

// Create makes an account, running Hooks.OnUserCreated in its transaction. A taken email is
// ErrConflict; a bad email, name or password ErrInvalidInput (*PasswordError lists the rules).
func (u Users) Create(ctx context.Context, in NewUser) (User, error) {
	m, err := u.p.graph.Identity().CreateUser(ctx, identity.NewUser(in), token.ClientContext{})
	if err != nil {
		return User{}, classify(err)
	}
	return wiring.UserOf(m), nil
}

// SetPassword sets the account's password under the policy (ErrInvalidInput) and ends every
// session, as a password reset does.
func (u Users) SetPassword(ctx context.Context, userID, password string) error {
	return classify(u.p.graph.Identity().SetPassword(ctx, userID, password))
}

// Disable disables the account and ends every session; sign-in then refuses it. Disabling a
// disabled account is a no-op.
func (u Users) Disable(ctx context.Context, userID string) error {
	return classify(u.p.graph.Identity().DisableUser(ctx, systemActor, userID))
}

// Enable re-enables a disabled or locked account (ErrConflict for an erased one).
func (u Users) Enable(ctx context.Context, userID string) error {
	return classify(u.p.graph.Identity().EnableUser(ctx, systemActor, userID))
}

// Delete erases the account (right to erasure): the row stays as an anonymized tombstone so
// references hold, personal data and credentials go, every session ends, and Hooks.OnUserDeleted
// runs in the erasing transaction.
func (u Users) Delete(ctx context.Context, userID string) error {
	return classify(u.p.graph.Identity().AnonymizeUser(ctx, systemActor, userID))
}

// Organization is a tenant as the host sees it.
type Organization struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Status    string    `json:"status"` // "active" or "suspended"
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

func organizationOf(o model.Organization) Organization {
	return Organization{ID: o.ID, Name: o.Name, Slug: o.Slug, Status: o.Status, CreatedBy: o.CreatedBy, CreatedAt: o.CreatedAt}
}

// Orgs manages organizations and memberships in process, with the same rules (the last owner
// stays), events and audit as the HTTP routes. The caller is trusted: no actor authority is
// checked.
type Orgs struct{ p *Polaris }

// Orgs returns the organization API.
func (p *Polaris) Orgs() Orgs { return Orgs{p} }

var orgSlug = regexp.MustCompile(`^[a-z0-9-]+$`)

// Create makes an organization owned by ownerUserID, with the owner, admin and member roles. slug
// "" derives one from name. A taken slug is ErrConflict; a bad name or slug ErrInvalidInput; an
// unknown owner ErrNotFound.
func (o Orgs) Create(ctx context.Context, ownerUserID, name, slug string) (Organization, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 160 {
		return Organization{}, classify(&orgs.Error{Kind: orgs.ErrInvalid, Message: orgs.MsgOrgName})
	}
	if slug != "" && (!orgSlug.MatchString(slug) || len(slug) > 160) {
		return Organization{}, classify(&orgs.Error{Kind: orgs.ErrInvalid, Message: "The slug must be URL-safe (lowercase letters, digits and hyphens) and at most 160 characters."})
	}
	if _, err := o.p.Users().Get(ctx, ownerUserID); err != nil {
		return Organization{}, err
	}
	org, err := o.p.graph.Orgs().CreateOrganization(ctx, name, slug, ownerUserID)
	if err != nil {
		return Organization{}, classify(err)
	}
	return organizationOf(org), nil
}

// Get returns the organization (ErrNotFound), suspended ones included.
func (o Orgs) Get(ctx context.Context, organizationID string) (Organization, error) {
	org, err := o.p.graph.Repos().Organizations.Get(ctx, organizationID)
	if err != nil {
		return Organization{}, classify(fmt.Errorf("polaris: organization %q: %w", organizationID, err))
	}
	return organizationOf(org), nil
}

// ListFor returns the active organizations userID is an active member of.
func (o Orgs) ListFor(ctx context.Context, userID string) ([]Organization, error) {
	list, err := o.p.graph.Orgs().ListOrganizations(ctx, userID)
	if err != nil {
		return nil, classify(err)
	}
	out := make([]Organization, 0, len(list))
	for _, org := range list {
		out = append(out, organizationOf(org))
	}
	return out, nil
}

// AddMember makes userID an active member holding roles (slugs of the organization's roles:
// "owner", "admin", "member" or its own), without an invitation. ErrConflict when the user
// already has a membership; ErrInvalidInput for an unknown role.
func (o Orgs) AddMember(ctx context.Context, organizationID, userID string, roles ...string) error {
	return classify(o.p.graph.Orgs().AddMember(ctx, organizationID, userID, roles))
}

// SetRoles replaces a member's roles (ErrConflict when it would demote the last owner).
func (o Orgs) SetRoles(ctx context.Context, organizationID, userID string, roles ...string) error {
	return classify(o.p.graph.Orgs().SetMemberRoles(ctx, systemActor, organizationID, userID, roles))
}

// RemoveMember removes a member (ErrConflict for the last owner).
func (o Orgs) RemoveMember(ctx context.Context, organizationID, userID string) error {
	return classify(o.p.graph.Orgs().DropMember(ctx, systemActor, organizationID, userID))
}

// Tokens are a session's credentials, as the sign-in route answers them.
type Tokens struct {
	AccessToken      string    `json:"access_token"`
	RefreshToken     string    `json:"refresh_token"`
	TokenType        string    `json:"token_type"` // "Bearer"
	ExpiresIn        int       `json:"expires_in"` // access-token lifetime, seconds
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	SessionID        string    `json:"session_id"`
}

// LogValue keeps both bearer secrets out of logs.
func (t Tokens) LogValue() slog.Value {
	return slog.GroupValue(slog.String("session_id", t.SessionID), slog.Int("expires_in", t.ExpiresIn))
}

// String keeps both bearer secrets out of fmt output.
func (t Tokens) String() string { return "polaris.Tokens" + t.LogValue().String() }

// GoString keeps both bearer secrets out of %#v output.
func (t Tokens) GoString() string { return t.String() }

func tokensOf(t token.IssuedTokens) Tokens {
	return Tokens{
		AccessToken: t.AccessToken, RefreshToken: t.RefreshToken, TokenType: "Bearer",
		ExpiresIn: t.AccessExpiresIn, RefreshExpiresAt: t.RefreshExpiresAt, SessionID: t.SessionID,
	}
}

// SignIn is a sign-in the host verified itself (its own SSO, a magic link of its own, a device it
// trusts).
type SignIn struct {
	UserID string
	// AMR says how the user authenticated, RFC 8176 values ("pwd", "otp", "hwk", …); empty is
	// ["custom"].
	AMR       []string
	IP        string // recorded on the session; optional
	UserAgent string // recorded on the session; optional
}

// Sessions opens, refreshes and ends sessions in process, with the same rules, events and audit
// as the HTTP routes.
type Sessions struct{ p *Polaris }

// Sessions returns the session API.
func (p *Polaris) Sessions() Sessions { return Sessions{p} }

// Issue opens a session for a sign-in the host verified: the account checks of sign-in apply (a
// disabled account, or an unverified email when verification is required, is ErrForbidden) but
// not the password or the MFA gate. Access tokens carry Hooks.Claims.
func (s Sessions) Issue(ctx context.Context, in SignIn) (Tokens, error) {
	t, err := s.p.graph.Identity().SignIn(ctx, in.UserID, in.AMR, token.ClientContext{IP: in.IP, UserAgent: in.UserAgent})
	if err != nil {
		return Tokens{}, classify(err)
	}
	return tokensOf(t), nil
}

// Refresh exchanges a refresh token for new tokens, rotating it. An unknown, expired, revoked or
// reused one is ErrInvalidCredentials (reuse also ends the whole session).
func (s Sessions) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	t, err := s.p.graph.Sessions().Refresh(ctx, refreshToken, token.ClientContext{})
	if err != nil {
		return Tokens{}, classify(err)
	}
	return tokensOf(t), nil
}

// Revoke ends one session (Tokens.SessionID; the sid claim). Ending an ended session is a no-op.
func (s Sessions) Revoke(ctx context.Context, sessionID string) error {
	return classify(s.p.graph.Sessions().Logout(ctx, sessionID))
}

// RevokeAll ends every session of the user (logout everywhere).
func (s Sessions) RevokeAll(ctx context.Context, userID string) error {
	return classify(s.p.graph.Sessions().LogoutAll(ctx, userID, token.ClientContext{}))
}
