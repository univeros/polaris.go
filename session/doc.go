// Package session holds what the session service hands its callers: one listed session ([Info])
// and the errors its refusals match.
//
// The service itself is internal to Polaris. A host uses polaris.Sessions; a plugin uses
// wiring.Graph.Sessions.
package session
