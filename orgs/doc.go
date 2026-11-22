// Package orgs holds what the organization service hands its callers: a listed [Member] and the
// errors its refusals match ([Error] and its kinds).
//
// The service itself is internal to Polaris. A host uses polaris.Orgs; a plugin uses
// wiring.Graph.Orgs.
package orgs
