// Package services hands core (package polaris, internal/httpapi, polaristest, cli) the concrete
// services of a wiring.Graph. Plugins see them only through wiring's narrow interfaces, so the
// concrete method sets stay free to change (API.md).
package services

import (
	"github.com/univeros/polaris.go/internal/authz"
	"github.com/univeros/polaris.go/internal/identity"
	"github.com/univeros/polaris.go/internal/mfa"
	"github.com/univeros/polaris.go/internal/orgs"
	"github.com/univeros/polaris.go/internal/session"
	"github.com/univeros/polaris.go/security"
)

// Services are the concrete services wiring.New built.
type Services struct {
	Identity   *identity.Service
	Sessions   *session.Service
	MFA        *mfa.Service
	Orgs       *orgs.Service
	Tickets    *session.MFATickets
	Denylist   *session.Denylist
	Catalog    authz.Catalog
	Resolver   *authz.Resolver
	Gate       *authz.Gate
	Principals *authz.Principals
	Escalation *authz.EscalationGuard
	Pepper     *security.Pepper
}

// of is bound by package wiring's init (wiring imports this package, not the reverse).
var of func(graph any) *Services

// Bind is called once, by package wiring.
func Bind(f func(graph any) *Services) { of = f }

// Of returns the concrete services of graph, a *wiring.Graph.
func Of(graph any) *Services { return of(graph) }
