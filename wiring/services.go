package wiring

import (
	"context"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/mfa"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/orgs"
	"github.com/univeros/polaris.go/session"
	"github.com/univeros/polaris.go/token"
)

// The core services as a plugin sees them: only the methods plugins call, so the services behind
// them can change without breaking a plugin (API.md §2). A method is added here when a plugin needs
// it; removing or changing one is a breaking change. The types they name (model.User,
// authz.Authority, …) are stable with them.

// Identity manages accounts. Every path that creates or deletes an account goes through
// InsertUser and OnUserDeleted, so the host's hooks run.
type Identity interface {
	// InsertUser writes a new account and runs the host's OnUserCreated hook in one transaction (a
	// savepoint inside the caller's): a hook error leaves no account. A taken email matches
	// store.ErrDuplicate.
	InsertUser(ctx context.Context, u model.User) error
	// OnUserDeleted runs the host's OnUserDeleted hook; call it inside the transaction that removes
	// the account, so a hook error rolls the removal back.
	OnUserDeleted(ctx context.Context, userID string) error
	// Login checks a password sign-in: tokens, or an MFA challenge.
	Login(ctx context.Context, email, password string, client token.ClientContext) (identity.LoginResult, error)
	// SetPassword sets the password for a trusted caller, as a reset does: the policy applies
	// (*identity.PasswordError) and every session ends.
	SetPassword(ctx context.Context, userID, password string) error
	DisableUser(ctx context.Context, actorUserID, userID string) error
	EnableUser(ctx context.Context, actorUserID, userID string) error
	AnonymizeUser(ctx context.Context, actorUserID, userID string) error
}

// Sessions issues and revokes sessions (refresh-token families).
type Sessions interface {
	// Issue opens a session: an access and a refresh token.
	Issue(ctx context.Context, p token.SessionPrincipal, client token.ClientContext) (token.IssuedTokens, error)
	// Mint signs an access token for p, in sessionID when not empty; extra claims ride along.
	Mint(ctx context.Context, p token.SessionPrincipal, sessionID string, extra token.Claims) (string, error)
	List(ctx context.Context, userID, currentSessionID string) ([]session.Info, error)
	Revoke(ctx context.Context, userID, sessionID string) (bool, error)
	RevokeAll(ctx context.Context, userID, reason string) (int, error)
	RevokeFamily(ctx context.Context, familyID, reason string) error
}

// MFA reads and changes a user's factors and gates sign-ins on them.
type MFA interface {
	// BeginLogin opens the MFA step of a sign-in by a user with confirmed factors.
	BeginLogin(userID string, confirmed []model.MFAFactor) (mfa.LoginChallenge, error)
	// HasConfirmedFactor reports whether MFA (and so step-up) applies to the user.
	HasConfirmedFactor(ctx context.Context, userID string) (bool, error)
	Factors(ctx context.Context, userID string) ([]model.MFAFactor, error)
	ConfirmedFactors(ctx context.Context, userID string) ([]model.MFAFactor, error)
	ConfirmFactor(ctx context.Context, factor model.MFAFactor) (mfa.ConfirmResult, error)
	UpdateFactor(ctx context.Context, userID, factorID string, label *string, makeDefault bool) (model.MFAFactor, error)
	RemoveFactor(ctx context.Context, userID, factorID string) error
}

// Orgs manages organizations and their members.
type Orgs interface {
	ListMembers(ctx context.Context, organizationID string, withPendingEmails bool) ([]orgs.Member, error)
	SetMemberStatus(ctx context.Context, actor, organizationID, targetUserID, status string) error
	// KeepOwner runs fn in a transaction with the organization locked and rolls it back with
	// orgs.ErrConflict when fn left the organization without an active owner.
	KeepOwner(ctx context.Context, organizationID string, fn func(ctx context.Context) error) error
	DeleteOrganization(ctx context.Context, org model.Organization, actorUserID string) error
}

// Denylist answers whether a user's access tokens issued at a time are revoked.
type Denylist interface {
	IsRevoked(ctx context.Context, userID string, issuedAt time.Time) (bool, error)
}

// Catalog lists the permission keys: core's, Config.Permissions and the plugins'.
type Catalog interface {
	Permissions() []authz.Permission
}

// Resolver resolves a user's roles and permissions in an organization.
type Resolver interface {
	Resolve(ctx context.Context, userID, organizationID string) (authz.Authority, error)
}

// Gate authorizes a caller, delegation included.
type Gate interface {
	Allows(ctx context.Context, c authz.Caller, permissions ...string) (bool, error)
	Authority(ctx context.Context, c authz.Caller) (authz.Authority, error)
}

// Principals builds the session principal (roles, scope) a token is minted for.
type Principals interface {
	Resolve(ctx context.Context, userID, organizationID string) (token.SessionPrincipal, error)
}

// Pepper is the keyed hash of stored secrets (API keys, client secrets, one-time codes): the
// format is frozen, since stored hashes must keep matching.
type Pepper interface {
	// Hash returns the keyed HMAC of value for context, as 64 lowercase hex characters.
	Hash(context, value string) string
	// Matches reports, in constant time, whether value re-hashed for context equals hash.
	Matches(context, value, hash string) bool
}

func init() {
	services.Bind(func(graph any) *services.Services { return graph.(*Graph).core })
}

// Identity returns the account service.
func (g *Graph) Identity() Identity { return g.core.Identity }

// Sessions returns the session service.
func (g *Graph) Sessions() Sessions { return g.core.Sessions }

// MFA returns the MFA service.
func (g *Graph) MFA() MFA { return g.core.MFA }

// Orgs returns the organization service.
func (g *Graph) Orgs() Orgs { return g.core.Orgs }

// Denylist returns the access-token denylist.
func (g *Graph) Denylist() Denylist { return g.core.Denylist }

// Catalog returns the permission catalog (core, Config.Permissions, plugins).
func (g *Graph) Catalog() Catalog { return g.core.Catalog }

// Resolver returns the authority resolver.
func (g *Graph) Resolver() Resolver { return g.core.Resolver }

// Gate returns the authorization gate.
func (g *Graph) Gate() Gate { return g.core.Gate }

// Principals returns the session principal resolver.
func (g *Graph) Principals() Principals { return g.core.Principals }

// Pepper returns the keyed hash of stored secrets.
func (g *Graph) Pepper() Pepper { return g.core.Pepper }
