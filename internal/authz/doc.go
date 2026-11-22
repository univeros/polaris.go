// Package authz is Polaris's role-based authorization: the
// code-defined permission catalog and its seeder, the resolver that turns a user and an active
// organization into an Authority (role slugs and permission keys), the Gate that checks it, the
// escalation guard and the session-principal resolver that puts roles into access tokens.
//
// Authority is always read from the database, never trusted from token claims, so a role or
// membership change takes effect on the next request.
//
// The vocabulary (permission keys, Catalog, Authority, Caller, the forbidden error) is the public
// package authz; public.go repeats its names here.
package authz
