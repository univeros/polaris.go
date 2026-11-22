// Package authz is the vocabulary of Polaris's role-based authorization: the core permission keys
// and system role slugs, the code-defined [Catalog], the [Authority] a user holds in an
// organization, the [Caller] a gate is asked about, and the forbidden error.
//
// The resolver, the gate and the seeder that work on them are internal to Polaris; a plugin
// reaches them as wiring.Graph's Resolver, Gate, Catalog and Principals. Authority is always read
// from the database, never trusted from token claims, so a role or membership change takes effect
// on the next request.
package authz
