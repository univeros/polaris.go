// Package identity runs the account flows of docs/auth/flows.md §1–3, §8 and §10 (upstream
// Polaris\Identity): registration and email verification, password login with windowed lockout
// and the MFA hand-off, password forgot/reset/change, and user administration (read, update,
// disable, enable, erase).
//
// Anti-enumeration is part of the contract: an unknown email and a wrong password fail the same
// way (ErrInvalidCredentials) after the same Argon2id work, registering a taken email and
// requesting a reset or a verification resend for an unknown one succeed silently. Verification
// and reset tokens are 256-bit secrets of which only the keyed hash (security.Pepper) is stored.
//
// Errors are values: every refusal matches one of the Err* sentinels with errors.Is, and its
// Error() is the message upstream returns to the client.
package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/token"
)

// Sessions opens and revokes sessions; *session.Service is the implementation.
type Sessions interface {
	Issue(ctx context.Context, p token.SessionPrincipal, client token.ClientContext) (token.IssuedTokens, error)
	RevokeAll(ctx context.Context, userID, reason string) (int, error)
	RevokeAllExcept(ctx context.Context, userID, exceptSessionID, reason string) (int, error)
}

// MFAGate lists the confirmed second factors of a user: one or more turns a correct password into
// an MFA challenge instead of a session (upstream MfaLoginService::confirmedFactors).
type MFAGate interface {
	ConfirmedFactors(ctx context.Context, userID string) ([]model.MFAFactor, error)
}

// MFATickets mints the short-lived login_mfa ticket of an MFA challenge; *session.MFATickets is
// the implementation.
type MFATickets interface {
	Issue(userID string) (string, error)
}

// AuthorityResolver resolves an actor's permissions in an organization ("" for none) from the
// database; *authz.Resolver is the implementation.
type AuthorityResolver interface {
	Resolve(ctx context.Context, userID, organizationID string) (authz.Authority, error)
}

// Config wires a Service. Every field is required except Breaches, Clock and Events.
type Config struct {
	DB        store.Adapter
	Hasher    security.PasswordHasher // security.Argon2id{} in production
	Pepper    *security.Pepper        // hashes verification/reset tokens and erased emails
	Sessions  Sessions
	MFA       MFAGate
	Tickets   MFATickets
	Authority AuthorityResolver
	// Auth supplies Password.MinLength, Lockout and Flows.RequireVerifiedEmail; start from
	// config.Defaults().
	Auth config.Auth
	// Breaches screens new passwords (auth.password.breach_check); nil checks nothing.
	Breaches security.BreachedPasswordCheck
	Clock    clock.Clock      // nil: clock.System
	Events   event.Dispatcher // nil: event.Nop
	// OnUserCreated runs inside the transaction that creates an account (every path: InsertUser);
	// an error aborts the creation. nil: nothing.
	OnUserCreated func(ctx context.Context, u model.User) error
	// OnUserDeleted runs inside the transaction that erases or removes an account; an error
	// aborts it. nil: nothing.
	OnUserDeleted func(ctx context.Context, userID string) error
}

// Service runs the identity flows. It is immutable after New and safe for concurrent use.
type Service struct {
	db        store.Adapter
	repos     *repository.Repos
	hasher    security.PasswordHasher
	pepper    *security.Pepper
	sessions  Sessions
	mfa       MFAGate
	tickets   MFATickets
	authority AuthorityResolver
	policy    PasswordPolicy
	auth      config.Auth
	clock     clock.Clock
	events    event.Dispatcher
	onCreated func(ctx context.Context, u model.User) error
	onDeleted func(ctx context.Context, userID string) error
	// dummyHash is verified against when the account is missing or passwordless, so a login
	// costs one Argon2id verify either way (timing parity). Hashed once, lazily.
	dummyHash func() (string, error)
}

// Hashed only for timing parity, never stored or compared: only the algorithm and cost matter.
const dummySecret = "polaris-login-timing-parity-placeholder"

// New validates cfg and returns a Service. Errors wrap ErrInvalidConfig.
func New(cfg Config) (*Service, error) {
	var missing []string
	for _, c := range []struct {
		name   string
		absent bool
	}{
		{"DB", cfg.DB == nil}, {"Hasher", cfg.Hasher == nil}, {"Pepper", cfg.Pepper == nil},
		{"Sessions", cfg.Sessions == nil}, {"MFA", cfg.MFA == nil}, {"Tickets", cfg.Tickets == nil},
		{"Authority", cfg.Authority == nil},
	} {
		if c.absent {
			missing = append(missing, "Config."+c.name)
		}
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("%w: %s required", ErrInvalidConfig, strings.Join(missing, ", "))
	}
	if err := cfg.Auth.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
	}
	s := &Service{
		db: cfg.DB, repos: repository.New(cfg.DB), hasher: cfg.Hasher, pepper: cfg.Pepper,
		sessions: cfg.Sessions, mfa: cfg.MFA, tickets: cfg.Tickets, authority: cfg.Authority,
		policy: PasswordPolicy{MinLength: cfg.Auth.Password.MinLength, Breaches: cfg.Breaches},
		auth:   cfg.Auth, clock: cfg.Clock, events: cfg.Events,
		onCreated: cfg.OnUserCreated, onDeleted: cfg.OnUserDeleted,
	}
	if s.clock == nil {
		s.clock = clock.System{}
	}
	if s.events == nil {
		s.events = event.Nop{}
	}
	s.dummyHash = sync.OnceValues(func() (string, error) { return s.hasher.Hash(dummySecret) })
	return s, nil
}

func (s *Service) now() time.Time { return s.clock.Now().UTC() }

// newSecret returns a 256-bit CSPRNG secret, base64url without padding.
func newSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails (crypto/rand panics on an unusable source)
	return base64.RawURLEncoding.EncodeToString(b)
}

// optional maps "" (no value) to nil, as upstream's nullable strings.
func optional(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
