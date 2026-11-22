// Package orgs manages organizations, their members, invitations and roles,
// enforcing the multi-tenant invariants a permission check alone cannot express:
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
// client-facing text.
package orgs

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/authz"
	"github.com/univeros/polaris.go/internal/strutil"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
)

// ErrInvalidConfig reports a Config missing a dependency.
var ErrInvalidConfig = errors.New("orgs: invalid configuration")

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
	// Catalog gives a new organization's owner, admin and member roles their grants; the zero
	// value is core's.
	Catalog authz.Catalog
}

// Service manages organizations, members, invitations and roles. Safe for concurrent use.
type Service struct {
	catalog  authz.Catalog
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
		catalog: cfg.Catalog, db: cfg.DB, r: repos, resolver: authz.NewResolver(repos), guard: authz.NewEscalationGuard(repos),
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

// asciiLower lowercases ASCII letters only, every other byte kept as is (locale-independent).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// normalizeEmail trims the edges, then lowercases ASCII letters (identity.NormalizeEmail's rule).
func normalizeEmail(email string) string { return asciiLower(strutil.Trim(email)) }
