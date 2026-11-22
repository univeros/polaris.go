package wiring

import (
	"context"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/identity"
	iauthz "github.com/univeros/polaris.go/internal/authz"
	iidentity "github.com/univeros/polaris.go/internal/identity"
	imfa "github.com/univeros/polaris.go/internal/mfa"
	iorgs "github.com/univeros/polaris.go/internal/orgs"
	"github.com/univeros/polaris.go/internal/services"
	isession "github.com/univeros/polaris.go/internal/session"
	"github.com/univeros/polaris.go/mfa"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/orgs"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/session"
	"github.com/univeros/polaris.go/token"
)

// The core services as a plugin sees them: only the methods plugins call, so the services behind
// them can change without breaking a plugin. Polaris implements these interfaces and plugins only
// call them, so they are sealed (the unexported method): a 1.x release may add a method to one,
// and never removes or changes one (API.md). A test double embeds the interface
// (struct{ wiring.Identity }) and overrides what the test calls. The types they name (model.User,
// authz.Authority, …) are public with them.

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
	// ProveEmail records that the caller established control of the account's mailbox; every
	// path that does (a link or code sent there, a trusted provider, the identity provider of the
	// organization that verified the domain) calls it instead of writing email_verified_at. On
	// the first proof of an account (first true) it marks the account verified and removes what
	// could act as it before: password, factors, the plugins' AccessEraser rows, sessions.
	// confirmsRegistration (a registration's own verification message) keeps a password and then
	// removes nothing.
	ProveEmail(ctx context.Context, userID string, confirmsRegistration bool) (user model.User, first bool, err error)
	// Login checks a password sign-in: tokens, or an MFA challenge.
	Login(ctx context.Context, email, password string, client token.ClientContext) (identity.LoginResult, error)
	// SetPassword sets the password for a trusted caller, as a reset does: the policy applies
	// (*identity.PasswordError) and every session ends.
	SetPassword(ctx context.Context, userID, password string) error
	DisableUser(ctx context.Context, actorUserID, userID string) error
	EnableUser(ctx context.Context, actorUserID, userID string) error
	AnonymizeUser(ctx context.Context, actorUserID, userID string) error

	sealed()
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

	sealed()
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

	sealed()
}

// Orgs manages organizations and their members.
type Orgs interface {
	ListMembers(ctx context.Context, organizationID string, withPendingEmails bool) ([]orgs.Member, error)
	SetMemberStatus(ctx context.Context, actor, organizationID, targetUserID, status string) error
	// KeepOwner runs fn in a transaction with the organization locked and rolls it back with
	// orgs.ErrConflict when fn left the organization without an active owner.
	KeepOwner(ctx context.Context, organizationID string, fn func(ctx context.Context) error) error
	DeleteOrganization(ctx context.Context, org model.Organization, actorUserID string) error

	sealed()
}

// Denylist answers whether a user's access tokens issued at a time are revoked.
type Denylist interface {
	IsRevoked(ctx context.Context, userID string, issuedAt time.Time) (bool, error)

	sealed()
}

// Catalog lists the permission keys: core's, Config.Permissions and the plugins'.
type Catalog interface {
	Permissions() []authz.Permission

	sealed()
}

// Resolver resolves a user's roles and permissions in an organization.
type Resolver interface {
	Resolve(ctx context.Context, userID, organizationID string) (authz.Authority, error)

	sealed()
}

// Gate authorizes a caller, delegation included.
type Gate interface {
	Allows(ctx context.Context, c authz.Caller, permissions ...string) (bool, error)
	Authority(ctx context.Context, c authz.Caller) (authz.Authority, error)

	sealed()
}

// Principals builds the session principal (roles, scope) a token is minted for.
type Principals interface {
	Resolve(ctx context.Context, userID, organizationID string) (token.SessionPrincipal, error)

	sealed()
}

// Pepper is the keyed hash of stored secrets (API keys, client secrets, one-time codes): the
// format is frozen, since stored hashes must keep matching.
type Pepper interface {
	// Hash returns the keyed HMAC of value for context, as 64 lowercase hex characters.
	Hash(context, value string) string
	// Matches reports, in constant time, whether value re-hashed for context equals hash.
	Matches(context, value, hash string) bool

	sealed()
}

// The concrete services, sealed: each embeds the service and adds the unexported method that
// keeps the interface Polaris's to implement.
type (
	identityService   struct{ *iidentity.Service }
	sessionsService   struct{ *isession.Service }
	mfaService        struct{ *imfa.Service }
	orgsService       struct{ *iorgs.Service }
	denylistService   struct{ *isession.Denylist }
	catalogService    struct{ authz.Catalog }
	resolverService   struct{ *iauthz.Resolver }
	gateService       struct{ *iauthz.Gate }
	principalsService struct{ *iauthz.Principals }
	pepperService     struct{ *security.Pepper }
)

func (identityService) sealed()   {}
func (sessionsService) sealed()   {}
func (mfaService) sealed()        {}
func (orgsService) sealed()       {}
func (denylistService) sealed()   {}
func (catalogService) sealed()    {}
func (resolverService) sealed()   {}
func (gateService) sealed()       {}
func (principalsService) sealed() {}
func (pepperService) sealed()     {}

func init() {
	services.Bind(func(graph any) *services.Services { return graph.(*Graph).core })
}

// Identity returns the account service.
func (g *Graph) Identity() Identity { return identityService{g.core.Identity} }

// Sessions returns the session service.
func (g *Graph) Sessions() Sessions { return sessionsService{g.core.Sessions} }

// MFA returns the MFA service.
func (g *Graph) MFA() MFA { return mfaService{g.core.MFA} }

// Orgs returns the organization service.
func (g *Graph) Orgs() Orgs { return orgsService{g.core.Orgs} }

// Denylist returns the access-token denylist.
func (g *Graph) Denylist() Denylist { return denylistService{g.core.Denylist} }

// Catalog returns the permission catalog (core, Config.Permissions, plugins).
func (g *Graph) Catalog() Catalog { return catalogService{g.core.Catalog} }

// Resolver returns the authority resolver.
func (g *Graph) Resolver() Resolver { return resolverService{g.core.Resolver} }

// Gate returns the authorization gate.
func (g *Graph) Gate() Gate { return gateService{g.core.Gate} }

// Principals returns the session principal resolver.
func (g *Graph) Principals() Principals { return principalsService{g.core.Principals} }

// Pepper returns the keyed hash of stored secrets.
func (g *Graph) Pepper() Pepper { return pepperService{g.core.Pepper} }
