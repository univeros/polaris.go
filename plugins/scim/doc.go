// Package scim is the SCIM plugin: a SCIM 2.0 server (RFC 7643, 7644) per
// organization. A directory (Okta, Entra ID, Google, JumpCloud, …) provisions the organization's
// members as Users and its roles as Groups with a connection token the organization creates and
// rotates itself; operators see every connection.
//
//	p, err := polaris.New(polaris.Config{
//		Secrets: secrets, Auth: auth, DB: db,
//		Plugins: []polaris.Plugin{audit.New(audit.Config{}), admin.New(admin.Config{}), scim.New(scim.Config{})},
//	})
//
// Config.BaseURL (default: the issuer followed by the path prefix) is where Polaris is mounted;
// every resource's meta.location and a connection's scim_base_url derive from it. The audit and
// admin plugins are optional: without audit nothing is recorded (events still fire), without admin
// the /admin/scim routes answer 401.
//
// # Connecting a directory
//
// An organization admin (org.update in the active organization) calls
// POST /orgs/{id}/scim/connections {name, deprovision?, sso_provider_id?} and receives the token
// (TokenPrefix and 256 random bits, stored as a keyed hash, shown once) and scim_base_url
// (<BaseURL>/scim/v2/{connectionId}). The directory sends it as "Authorization: Bearer"; POST
// .../rotate replaces it at once, DELETE decommissions the connection (the users stay).
// deprovision is DeprovisionDeactivate (a deleted or inactive user is disabled, their sessions end,
// and the membership this connection created is removed) or DeprovisionDelete (the account is
// anonymised).
//
// # The SCIM server
//
// Under /scim/v2/{connectionId}: ServiceProviderConfig, Schemas, ResourceTypes, Users and Groups
// (list, create, read, PUT, PATCH, delete). Documents are application/scim+json; refusals are SCIM
// error documents (schemas, status, detail, scimType) that also carry error and message. Filters are
// the subset directories send to look a resource up: attr eq|co|sw "value" joined by and; anything
// else is invalidFilter. A User is a Polaris user with a membership in the organization (id is the
// Polaris user id); a Group is one of its roles. The built-in owner, admin and member roles take
// members but are neither renamed nor deleted. Every directory request is a scim.* event (an
// audit.Auditable) with the connection as the actor.
//
// # Operators
//
// GET /admin/scim/connections (read; an organization-scoped operator sees their organization's)
// and DELETE /admin/scim/connections/{id} (own) for the admin plugin's principals.
package scim
