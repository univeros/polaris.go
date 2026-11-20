// Package orgs manages organizations, their members, invitations and roles (upstream
// OrganizationService, MembershipService, InvitationService and RoleService; docs/auth/rbac.md
// §3, §6–§8), enforcing the multi-tenant invariants a permission check alone cannot express:
//
//   - No privilege escalation: an actor only grants roles and permissions they hold themselves
//     (a superadmin is exempt), checked with authz.EscalationGuard.
//   - Owners are protected from non-owners: only an owner (or a superadmin) modifies, suspends or
//     removes an owner.
//   - Last-owner protection: an organization always keeps at least one active owner, absolutely.
//
// Callers have already passed the Gate for the route's permission; the actor's authority for the
// invariants is re-resolved from the database, never read from the token. Every write runs in one
// transaction; events are dispatched after it commits.
//
// Refusals are values: a *Error whose Kind is ErrInvalid (422), ErrNotFound (404), ErrConflict
// (409) or ErrInvalidInvitation (400), or an *authz.ForbiddenError (403). Their Message is the
// client-facing text upstream answers.
package orgs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/univeros/polaris-go/authz"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
)

// Kinds of refusal, matched with errors.Is on a *Error.
var (
	ErrInvalid           = errors.New("orgs: invalid input")      // 422 unprocessable
	ErrNotFound          = errors.New("orgs: not found")          // 404 not_found
	ErrConflict          = errors.New("orgs: conflict")           // 409 conflict
	ErrInvalidInvitation = errors.New("orgs: invalid invitation") // 400, never says why
	// ErrInvalidConfig reports a Config missing a dependency.
	ErrInvalidConfig = errors.New("orgs: invalid configuration")
)

// Error is a refusal of the domain: Kind is one of ErrInvalid, ErrNotFound, ErrConflict or
// ErrInvalidInvitation (errors.Is matches it), Message the text the endpoint answers.
type Error struct {
	Kind    error
	Message string
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns Kind.
func (e *Error) Unwrap() error { return e.Kind }

func refuse(kind error, message string) error { return &Error{Kind: kind, Message: message} }

// Sessions revokes the refresh-token sessions a member holds in an organization's context;
// *session.Service is the implementation.
type Sessions interface {
	RevokeAllForOrganization(ctx context.Context, userID, organizationID, reason string) error
}

// Config wires a Service. DB, Sessions and Pepper are required.
type Config struct {
	DB       store.Adapter
	Sessions Sessions
	Pepper   *security.Pepper // hashes invitation tokens (context "org_invite")
	Clock    clock.Clock      // nil: clock.System
	Events   event.Dispatcher // nil: event.Nop
}

// Service manages organizations, members, invitations and roles. Safe for concurrent use.
type Service struct {
	db       store.Adapter
	r        *repository.Repos
	resolver *authz.Resolver
	guard    *authz.EscalationGuard
	sessions Sessions
	pepper   *security.Pepper
	clock    clock.Clock
	events   event.Dispatcher
}

// New validates cfg and returns a Service.
func New(cfg Config) (*Service, error) {
	var missing []string
	if cfg.DB == nil {
		missing = append(missing, "DB")
	}
	if cfg.Sessions == nil {
		missing = append(missing, "Sessions")
	}
	if cfg.Pepper == nil {
		missing = append(missing, "Pepper")
	}
	if missing != nil {
		return nil, fmt.Errorf("%w: missing %s", ErrInvalidConfig, strings.Join(missing, ", "))
	}
	repos := repository.New(cfg.DB)
	s := &Service{
		db: cfg.DB, r: repos, resolver: authz.NewResolver(repos), guard: authz.NewEscalationGuard(repos),
		sessions: cfg.Sessions, pepper: cfg.Pepper, clock: cfg.Clock, events: cfg.Events,
	}
	if s.clock == nil {
		s.clock = clock.System{}
	}
	if s.events == nil {
		s.events = event.Nop{}
	}
	return s, nil
}

// found turns repository.ErrNotFound into ok=false and passes any other error through.
func found(err error) (bool, error) {
	if errors.Is(err, repository.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

var nonSlug = regexp.MustCompile(`[^a-z0-9]+`)

// asciiLower is PHP's strtolower: ASCII letters only, every other byte kept as is.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// phpTrim is PHP's trim with its default characters.
func phpTrim(s string) string { return strings.Trim(s, " \t\n\r\x00\x0B") }

// normalizeEmail is upstream EmailNormalizer: trim, then strtolower.
func normalizeEmail(email string) string { return asciiLower(phpTrim(email)) }
