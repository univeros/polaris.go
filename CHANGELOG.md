# Changelog

What changes for an application (a "host") or a plugin author in each release of Polaris for Go.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html), with the pre-1.0 rule that a minor
release may break what [API.md](API.md) does not mark stable, and breaks a stable name only with a
decision in [docs/decisions.md](docs/decisions.md) ("decision N" below). Breaking changes are
marked **Breaking**.

## [Unreleased]

### Added

- Host API for what the examples had to work around (decision 66):
  `polaris.SignIn.OrganizationID` opens a session in an organization (membership checked; as a
  sign-in plus `POST /auth/switch-org`); `p.Orgs().Invite` returns the `polaris.Invitation` and its
  token for the host to deliver; `polaris.ErrEmailNotVerified` (also `ErrForbidden`) names the
  refusal of `Sessions().Issue` for an unverified email; `p.Wrap(h)` applies `Config.Middleware` to
  a host route outside `Protect`; `polaris.DevEnv` generates throwaway secrets for local
  development and refuses to run without `POLARIS_DEV=1`; `polaristest.Hasher()` is the cheap test
  Argon2id for a host's own `polaris.Config` in tests; `sqlstore.Store.Conn(ctx)` (plain
  `database/sql` in the transaction ctx carries, for hooks), `Store.AfterCommit` and `Store.Close`;
  `Config.TxListeners` and, for plugin authors, `wiring.Graph.Deferred`.
  Package `event` (`Event`, `Listener`, the event types) joins the host surface in API.md §1.
- SECURITY.md states the policy from v1.0.0: the latest minor gets every security fix, the previous
  minor gets Critical and High fixes for 3 months after a new minor, and each fix is a GitHub
  security advisory with a CVE. [docs/stored-formats.md](docs/stored-formats.md) lists the stored
  data and tokens every 1.x release keeps reading (decision 71).
- `token.Thumbprint(alg, publicKey)`, the RFC 7638 JWK thumbprint; `token.Config.LegacyKeyID` and
  `PreviousLegacyKeyID`, a second kid `VerifyJWT` accepts for each key; `config.Secrets.LegacyKeyID`
  and `PreviousLegacyKeyID` (decision 73).
- `APP_KEY` is fixed for the life of a deployment in 1.x: `config.Secrets`, SECURITY.md
  ("Operating Polaris") and docs/stored-formats.md say what depends on it and what changing it
  invalidates (decision 73).

### Changed

- **Client-visible:** without `AUTH_JWT_KID` the `kid` of new tokens and of the JWKS is the RFC 7638
  thumbprint of the public key (base64url, 43 characters), not the SHA-256 hex of the PEM text, so
  re-encoding the same key no longer changes it. Nothing issued before stops verifying: the server
  still accepts tokens naming the old `kid`, and `/auth/.well-known/jwks.json` publishes each key a
  second time under its old `kid` (same key material), after the keys under their new kids, for
  verifiers holding old tokens or a cached key set. An explicit `AUTH_JWT_KID` or
  `AUTH_JWT_PREVIOUS_KID` is unchanged and gets no alias (decision 73).

- **Client-visible:** every timestamp a plugin route answers is RFC 3339 in UTC with `Z`
  (`2026-11-22T10:00:00Z`, was `+00:00`): admin, api-keys, agents, audit (and its file and webhook
  sinks), multi-session, oauth, passkey, scim, sentinel, social, sso. admin echoed a key's or
  grant's `expires_at` in the offset it was sent with; it now answers UTC. Agent receipts keep
  `+00:00` in `created_at`, which their hash covers. Inputs accept both (decision 65).
- **Client-visible:** `plugins/audit`: the file and webhook sinks write standard JSON (UTF-8, `/`
  unescaped, `{}` for an empty object); the signature header still covers the bytes sent. The
  stored trail and its hash chain are unchanged (decision 65).
- **Client-visible:** `limit` on the admin, audit, sentinel, sso and scim listings, SCIM
  `startIndex`/`count` and the agents receipts' `after`/`limit` must be integers (decimal digits
  in a query, a JSON integer in a body); `1.5`, `1e1`, padded values are refused (422, SCIM 400
  `invalidValue`) instead of truncated (decision 65).
- **Client-visible:** `plugins/scim`: `active` must be a JSON boolean or the string
  `"true"`/`"false"` in any case (what Microsoft Entra ID sends), in POST, PUT and PATCH; `"on"`,
  `"yes"`, `"1"`, `1` answer 400 `invalidValue`, and a POST or PUT with `"false"` no longer
  activates the account. `members` must be a list of
  `{"value": id}`; a PATCH operation without `path` must carry an object; a filter value is a JSON
  string (an unknown escape such as `\0`, a raw control character or a NUL is `invalidFilter`;
  `\uXXXX` now decodes) (decision 65).
- **Client-visible:** request bodies are read as their JSON types. agents: `arguments`/`input`
  must be an object, constraints, operators and `budget` objects (a `[]` was read as `{}`; a list
  of operators is now 422 `invalid_input`, was 400 `unknown_constraint_operator`), capability
  lists lists, an agent's or host's name has no control character (a NUL was a 500 on
  PostgreSQL, now 422 `invalid_input`); `max`/`min` need a JSON number argument and `in`/`not_in` compare numbers by value
  (`1` equals `1.0`). api-keys: `name` a string, `permissions` a list, `metadata` an object. sso:
  `config`, `attributes`, `jit` objects, `jit.enabled` a boolean, `jit.roles` and
  `redirect_uris` lists; `sso_url`, `slo_url`, `slo_response_url` must be http(s) URLs
  (decision 65).
- **Client-visible:** `plugins/oauth`: a client's `jwks` must hold `keys` as an array (RFC 7517;
  422 `invalid_client_metadata`, a `jwks_uri` document `invalid_client`); a fetched metadata or
  JWKS document must be a JSON object. A key is chosen by `kid` only (a key without `kid` is no
  longer named `"0"`, `"1"`…); a client assertion without `kid` verifies when the client has one
  key. A client whose registered keys have no `kid` and that sent `kid: "0"` must drop the `kid`
  (one key) or register keys with a `kid`. Clients registered with `keys` as an object keep
  working (decision 65).
- **Client-visible:** error texts. JWT failures in oauth, agents, sso and social read "the
  signature does not verify", "the token has expired", "the token is not valid before …", … (were
  "Signature verification failed", "Expired token", "Cannot handle token with nbf prior to …");
  agents' argument-schema errors read `missing required properties: x`, `/p: must be string, not
  integer`, …; problem titles in oauth, mcp and agents are sentences ("Invalid DPoP proof",
  "Capability not granted", were "Invalid Dpop Proof", "Capability Not Granted"). Error codes and
  problem types are unchanged (decision 65).
- **Client-visible:** encodings. oauth authorization redirects leave `~` unescaped; social's
  authorization URL is form-encoded (`scope=openid+email+profile`, was `%20`); mcp sends a boolean
  tool argument as `true`/`false` (was `1`/empty) and refuses an object, list or null path
  argument (`-32602`); messaging renders booleans `true`/`false` and escapes HTML with
  `html.EscapeString` (`'` is `&#39;`, was `&#039;`) (decision 65).
- `plugins/sso` and `plugins/social`: a provider's JWK without `alg` verifies the algorithm its
  type implies (RSA RS256, EC P-256 ES256, Ed25519 EdDSA) and any other key without `alg` is
  refused; it used to be taken as RS256. An expired IdP certificate in SAML still verifies, by
  design (decision 65).
- **Client-visible:** core routes write timestamps as RFC 3339 in UTC with `Z`
  (`2026-06-10T09:00:00Z`, was `2026-06-10T09:00:00+00:00`): `GET /auth/sessions`, `POST`/`GET
  /orgs/{id}/invites`, `GET`/`PATCH /users/{id}`. Same instant; any RFC 3339 parser reads both. A
  client comparing timestamp strings byte for byte must compare parsed times (decision 64).
- **Client-visible:** a core route answers 422 when a field holds another JSON type than its spec
  declares, e.g. `{"errors": ["code must be a string."]}`. Send strings as strings (`"code":
  "123456"`, not `123456`) and booleans as `true`/`false` (`"default": true`, not `"1"` or `1`).
  Before, numbers and booleans were turned into text and `default` read `"0"`, `0` and `""` as
  false (decision 64).
- **Client-visible:** the `e164` and `regex` input rules no longer accept a value with a trailing
  newline (`"+15551234567\n"`), and neither does a new organization slug (decision 64).
- **Client-visible, Breaking for OpenAPI code generators:** each OpenAPI `operationId` is the
  route's name (`polaris.auth.login`, was `post_LoginEndpoint`), unique across core and the
  plugins; the JSON manifest (`polaris manifest`) carries `"name"` where it carried `"class"`.
  Regenerate generated clients; their method names change (decision 64).
- **Client-visible:** the exported manifest, the OpenAPI document and MCP tool schemas write an
  empty object as `{}` (was `[]`): an untyped schema is `{}`, `"properties": {}`, and examples
  documented as `{}` are typed as objects. Token claims encode an empty object as `{}` and large or
  tiny floats as `encoding/json` does; tokens issued before keep verifying (decision 64).
- **Client-visible:** new TOTP factors get a 20-byte secret (32 base32 characters, was 103), which
  every authenticator app accepts. Factors enrolled before keep their secrets and keep working
  (decision 64).
- **Breaking:** `manifest.Route.Class` and the `domain.class` key of route specs are gone; a spec
  that still has the key loads and the key is ignored. A `max:` rule argument must be a whole
  number (`max:10abc` no longer loads) (decision 64).
- Tokens whose `iat`, `nbf` or `exp` is a string or negative, or whose `aud` is not a string or a
  list of strings, are refused. Polaris never issued such a token (decision 64).
- `notify.Text` renders booleans as `true`/`false` (was `1` and empty); the built-in templates
  carry none. `store.Row.Bool` reads text as `strconv.ParseBool` does (`y`/`yes` are no longer
  true; no value Polaris or the drivers write changes). New `auth_audit_log.metadata` rows are
  standard JSON (`{}` for no fields, `/` and non-ASCII unescaped, `Z` timestamps); earlier rows are
  untouched and decode to the same values (decision 64).
- Event delivery has two phases. Listeners that write to the store (core's audit, every plugin's
  listeners: audit, erasure, revocations) run inside the transaction that raised the event, as
  before. The mail listener, metrics and `Config.Listeners` now run after a `sqlstore.Store.Tx`
  commits and never after it rolls back (a rolled-back savepoint drops its own). A host's `db.Tx`
  around `p.Users().Create` no longer mails for a signup it then rolls back. A host listener that
  writes to the database and must stay atomic moves to the new `Config.TxListeners`; plugins wrap a
  listener with effects outside the database in `Graph.Deferred`. Under `sqlstore.WithTx` the
  deferred listeners still run before the host commits: Polaris cannot see that commit
  (decision 66).
- The examples run with `POLARIS_DEV=1 go run ./examples/<name>` (`polaris.DevEnv` replaces each
  example's copy of a key generator), and their tests use `polaristest.Hasher()`: a `-race` run of
  each takes seconds instead of 45–90 s.

### Fixed

- `plugins/audit` with `HashChain`: two requests could hang each other when a host transaction
  recorded two events while another request recorded one, and the first chained writes on a new
  database could fail or deadlock. `Migrate` now creates the chain's lock row (run it after
  upgrading, as always) and writers no longer share a process-wide lock (decision 72). New for
  plugin authors: the optional `wiring.Seeder`, called by `Migrate`.
- `plugins/mcp`: a path argument with a reserved character was escaped twice (a space went out as
  `%2520`); each path segment is now escaped once (decision 65).

## [0.5.1] - 2026-11-22

Security fixes from the pre-1.0 security review (decisions 68 and 69). Upgrade now and **run
`Migrate`** (one new table, `polaris_sso_account`). Some fixes change what clients see; read every
entry if you use `plugins/sso`, `plugins/social`, `plugins/oauth` (with `verify` or `mcp.Protect`
downstream), `plugins/admin` or `plugins/ui`. In particular: accounts an SSO provider created
before this release sign in through SSO again once the organization verifies its email domain or
you call `sso.Of(g).MarkProvisioned`; SSO sessions stay in their organization; OAuth tokens carry
only the permission scopes their subject holds.

### Added

- For plugin authors: `wiring.Identity.ProveEmail`, the optional `wiring.AccessEraser` (a plugin
  that stores a way to act as a user removes it on the mailbox's first proof),
  `token.Token.OrganizationBound`, `token.AMRSSO`, `authz.Caller.OrganizationBound`,
  `pipeline.DeniesBound`, `session.ErrOrganizationBound`. For hosts:
  `Principal.OrganizationBound`, `sso.Plugin.MarkProvisioned`.
- `oauth.ClientAuthority`: a plugin whose OAuth clients act as themselves says which permissions
  such a client holds (`plugins/agents` implements it with `Plugin.ClientPermissions`).

### Security

- sso: a provider signs in an existing account only when its organization owns the account: one of
  its providers created it just in time, one of its SCIM directories created it, or the account's
  email domain is verified for the organization. Being a member of the organization is no longer
  enough. **Breaking, client-visible:** other accounts answer 403 `sso/user_unknown`, including
  accounts a provider created before this release: verify the organization's email domain, or
  record them with `sso.Of(g).MarkProvisioned(ctx, organizationID, userID)`. An IdP LogoutRequest
  ends sessions under the same rule. A platform superadmin no longer signs in through an
  organization's provider.
- sso: the session a provider opens is bound to the provider's organization (`amr` holds `sso`;
  sessions opened before the upgrade included). **Client-visible:** `POST /auth/switch-org` to
  another organization answers 403, and so does every route reserved to the account holder: the
  password, MFA factors and step-up, passkeys, API keys, provider links, phone numbers, agents,
  OAuth consent, creating or joining an organization, the profile, account deletion and
  logout-everywhere. Reading, logging out, refreshing and the organization's permissioned routes
  work as before. A user who needs the others signs in to the account itself. Hosts read
  `Principal.OrganizationBound` and should refuse it on routes that act on the user's account or
  on data outside the organization.
- The first proof of an account's mailbox is one operation on every path (`Identity.ProveEmail`):
  a password reset, a passwordless email code or magic link, a trusted social link and an SSO
  sign-in on a verified domain, for an account whose email was never verified, mark it verified
  and remove what could act as it before: the password, MFA factors and recovery codes, passkeys,
  provider links, API keys, OAuth grants, agents, the confirmed phone and every session. Before,
  each path removed a different part, and a provider account linked to an unverified account kept
  signing in after the mailbox's owner took the account over. **Client-visible:** a password reset
  (core's and the passwordless code) now verifies an unverified account (`email_verified` true,
  `user.email_verified` dispatched); a verification link or code on an account that has no
  password removes the same things; with a password it confirms the registration and removes
  nothing, as before.
- social: a sign-up whose provider does not vouch for the email creates no account and no link
  when unverified accounts cannot sign in (`RequireVerifiedEmail`, the default). It answered 403
  `social/email_unverified` before too, but left both behind in the address's name.
  **Client-visible:** the address stays free to register; the person signs up another way and
  links the provider from their account.
- ui: opening the email verification link no longer verifies (mail scanners follow links).
  **Client-visible:** `GET /auth/ui/verify?token=…` answers a page with one button, and its
  CSRF-guarded POST verifies. New message key `verify_confirm`; a host template replacing
  `verify.html` keeps working and may use `.TokenGiven`.
- `plugins/oauth`: a scope that is a permission name (`org.read`, one of your
  `Config.Permissions`) is put in an access token only if the token's subject holds that
  permission when the token is minted: at issue, on every refresh and on a token exchange. A user
  holds what their roles grant in the token's organization. A client acting as itself
  (`client_credentials`) holds none, unless an operator registered it `trusted` with the
  permission in its `scopes`, or it is an agent of `plugins/agents` (its live grants that its
  owner holds). Before, any permission scope a client asked for was granted; the host's own routes
  were not affected (they intersect with the user's permissions on every request), but a service
  checking tokens with `verify.Require` or `mcp.Protect` read a permission the subject did not
  hold. **Client-visible:** a token response's `scope` may list fewer scopes than requested
  (RFC 6749 §3.3); clients should read it. `PATCH /orgs/{id}/oauth/clients/{clientId}` answers 400
  `invalid_client_metadata` when it changes the `scopes` of a trusted client (an operator sets
  them). If you run `verify` or `mcp.Protect` in other services, upgrade the Polaris host; their
  documentation now says what a scope proves: only a permission scope is an authorization check,
  a `Config.Scopes` scope says what the client asked for (decision 69).
- `plugins/admin`: an operator below `owner` can no longer ban, unban, set the password of, remove
  or reset the MFA of, or delete the account of a superadmin or of an operator whose grant is of
  its own role or above. **Client-visible:** those requests answer 403 `admin/forbidden`; an
  `owner` manages every account as before (decision 69).
- MFA: second-factor attempts are limited per user, not only per IP. After
  `auth.lockout.max_attempts` (5) codes that did not clear at the MFA login step or step-up,
  recovery codes included, every code of that user is answered as a wrong one until
  `auth.lockout.lock_duration` (15 minutes) has passed since the first; a code that clears resets
  the count. **Client-visible:** during that window a right code answers the wrong-code 422
  (decision 69).
- MFA: an email or SMS code attempt is counted before the code is compared, so requests sent
  together cannot get more compares than `auth.otp.max_attempts` (decision 69).
- `plugins/ui`: `GET /auth/ui/refresh` renews the session only for a navigation the browser marks
  `Sec-Fetch-Site: same-origin` or `none` (or without the header). **Client-visible:** arriving
  from a link on another site with an expired access cookie shows a page with one "Continue" link
  (messages `refresh_title`, `refresh_intro`) that renews the session, instead of renewing at
  once (decision 69).
- `plugins/agents`: on the plugin's routes a request JWT's `aud` is checked against
  `Config.BaseURL`'s origin (default: the oauth plugin's base URL) instead of the request's `Host`
  header; a TLS-terminating proxy no longer has to set `r.TLS` for them. **Client-visible:** an
  agent calling Polaris under another host name gets `aud_mismatch`. An autonomous agent's own
  token carries only the grant permissions its owner still holds (decision 69).
- `verify`, `mcp.Protect`: a failed fetch of the issuer's JWK Set is remembered for 5 seconds, so
  requests answer 503 at once while the issuer is down instead of waiting for one another's
  timeout (decision 69).

## [0.5.0] - 2026-11-22

Security fixes for replicas, account lifecycle and MFA; your own permissions grantable to roles;
`Migrate` that evolves an existing database. **Run `Migrate` after upgrading**: it adds two
tables (`polaris_audit_chain`, `polaris_scim_user_name`) and swaps an admin index, and it stops with
a remedy if your data needs a manual step (see the admin entry under Security). Read the
**Client-visible** entries under Changed if you have front ends or API clients: the magic-link page,
429 bodies, `budget_exhausted` and whole-second token timestamps.

### Added

- `Migrate` (and `polaris migrate`) keeps an existing database current: besides creating missing
  tables, it adds the columns and indexes a release declares on an existing table and drops the
  indexes it retires. It never drops a table or a column, never changes a column's type, and is
  safe on replicas booting together. New: `sqlstore.Store.Migrate`, `schema.Model.DropIndex`
  (decision 63).
- Runnable examples for `Protect`, `PrincipalFrom`, `Can`, `Orgs`, `Sessions` and `polaristest.New`.
- For plugin authors: `endpoint.WithMFATicketFactors` and `endpoint.MFATicketAllows`,
  `pipeline.MFATicketFactors`, `session.MFATickets.IssueFor` / `AuthenticateFactors`,
  `passwordless.RouteMagicLinkConfirm`, `passwordless.KindMFASameChannel` /
  `ErrMFASameChannel`. `mfa.Tickets` (not in the stable API) has `IssueFor` instead of `Issue`, and
  `mfa_factors` joined the reserved claim names (`session.ReservedClaim`).
- `Config.RolePermissions`: say which system roles (`owner`, `admin`, `member`) hold your own
  permissions, e.g. `{"owner": {"invoices.read"}}`. Every organization's copy of the role holds
  them (existing organizations on the next `Migrate`), so an owner can put them into custom roles,
  invitations, API keys and agent grants. Before, nobody but a superadmin could grant a host
  permission; drop any workaround that wrote role grants through `Graph().Repos()` (decision 62).
- `endpoint.TooManyRequests` for plugin authors: the 429 in the route's error style (decision 62).

### Changed

- `Polaris.Migrate` returns every change it made: the tables it created, as before, then one
  `"<table>: added column <c>"`, `"created index <i>"` or `"dropped index <i>"` line per change to
  an existing table. `polaris migrate` prints "Applied N change(s)"; its JSON `created` list holds
  the same lines (decision 63).
- **Client-visible:** `GET /magic-link/verify` answers an HTML page (no JavaScript) with one "Sign
  in" button instead of the 302; the button posts to the new `POST /magic-link/verify`, which
  spends the link and answers the 302 with the hand-off code as before. The emailed link,
  `/magic-link/exchange` and the codes are unchanged. A front end that fetched the link itself
  and expected the redirect must now POST to it (decision 61).
- `anonymous.Config.OnConvert` runs inside the conversion's transaction (like
  `Hooks.OnUserCreated`): write through `ctx` and the move commits or rolls back with the
  conversion. A hook that writes elsewhere may run again on a retry; keep it idempotent.
- `plugins/mcp`: `tools/list` is paginated. A result carries at most `mcp.ToolsPageSize` (100)
  tools and a `nextCursor` when more follow; send it back as `params.cursor`. An invalid cursor is
  `-32602`. Lists of 100 tools or fewer are unchanged; MCP clients that follow `nextCursor` (the
  specification requires it) see every tool (decision 60).
- **Client-visible:** access tokens and OAuth access / ID tokens carry `iat`, `nbf` and `exp` as
  whole seconds, with `exp` = `iat` + the lifetime exactly; they used to carry microsecond
  fractions that many JWT libraries refuse. Tokens issued before still verify (decision 62).
- **Client-visible:** a 429 now has a JSON body: `{"error":"too_many_requests","message":…}` on
  core routes and your `Protect` routes, an `application/problem+json` document on plugin routes.
  `Retry-After` and `X-RateLimit-*` are unchanged (decision 62).
- **Client-visible:** `plugins/agents`: once a grant's budget is spent, further calls answer 403
  `budget_exhausted` (`agent.ErrBudgetExhausted`) instead of `capability_not_granted`
  (decision 62).
- `plugins/scim` adds a table, `polaris_scim_user_name`; run `Migrate` after upgrading
  (decision 62).

### Fixed

- Erasing a user (`Users().Delete`, the self-service and admin erase, SCIM delete, guest pruning)
  now deletes every plugin row keyed to it: usernames, verified phones and pending passwordless
  codes and links, multi-session and sentinel device records, operator grants, OAuth authorization
  codes, device codes and CIBA requests, SCIM provenance and user mappings, the guest row and the
  audit activity row. Client-visible: `GET /admin/users/{id}` of an erased user answers
  `last_active_at: null` (decision 61).
- The anonymous README said conversion ends the guest's sessions without saying that, with
  `AUTH_ACCESS_TOKEN_DENYLIST` off, the guest's access token answers until it expires (as every
  revoked session's does). It now says so; `config.AccessToken.Denylist` documents the window.
- `plugins/audit`: audit rows of core events (`org.*`, `session.*`, `mfa.*`, `user.*`) record the
  request's `ip` and `user_agent`, as plugin events already did (decision 62).
- `plugins/scim`: a User answers back `name.givenName` and `name.familyName` as the directory sent
  them, so a directory comparing resources sees no difference. A PATCH of one part keeps the other
  (decision 62).

### Security

- **Critical:** an organization's owner could create a role slugged `superadmin` and be treated as
  the platform superadmin (other organizations' members, roles, OAuth clients, SSO providers and
  audit; platform-only permissions). Only the system superadmin role counts now, and the slug is
  reserved (decision 67). After upgrading, check for organization roles with that slug:
  `SELECT * FROM auth_roles WHERE slug = 'superadmin' AND organization_id IS NOT NULL`.

- MFA: a passwordless sign-in and a second factor on the same channel no longer count as two
  factors. After an email code or magic link to an address (or an SMS code to a phone), the
  `mfa_required` envelope lists only factors that do not deliver there, and the `mfa_token` is
  bound to the factors it lists: `/auth/mfa/challenge` and `/auth/mfa/verify` answer 404 for
  another factor (recovery codes still work). A user whose only factor delivers there gets 403
  `passwordless/mfa_same_channel` and signs in with the password, or adds a factor. The passkey
  sign-in, which already left its own passkey out of the list, now has the same enforcement
  (decision 61).
- `plugins/passwordless`: email security scanners can no longer spend magic links; opening the
  link spends nothing (see Changed) (decision 61).
- `plugins/social`: two concurrent unlinks can no longer remove an account's last way to sign in;
  the check and the delete are one transaction with the user's row locked (decision 61).
- `plugins/anonymous`: a guest conversion is one transaction. Before, if ending the guest failed
  after `OnConvert` ran, the conversion stayed recorded, the guest's sessions stayed live and a
  retry answered `not_a_guest`; now any failure leaves the guest as it was and a retry converts it
  (decision 61).
- `plugins/audit`: with `HashChain` on, replicas writing at the same time no longer fork the hash
  chain (two rows linked to one predecessor, or ids out of chain order), which made `Verify`
  report breaks in an untampered table. Each chained write now first takes the lock row of a new
  table, `polaris_audit_chain`, so writers in every process append one at a time. **Run
  `Migrate` after upgrading**: it creates the table; until then chained writes fail (logged) with
  an error naming it. Existing chains keep verifying. On SQLite, set a busy timeout
  (`_pragma=busy_timeout(5000)`) so concurrent writers wait (decision 60).
- `plugins/admin`: two concurrent first grants for one user could both insert, leaving the user
  with two operator grants of which either one applied. `polaris_admin_grant.user_id` is now unique
  and the losing grant is applied as an update, as if it had come second (decision 60).
  **Upgrade:** `Migrate` adds the unique index (`polaris_admin_grant_user_unique`) and drops the old
  `polaris_admin_grant_user_index`. If your database already holds two grants for one user,
  `Migrate` stops with an error naming `polaris_admin_grant` and `user_id`. Find them with
  `SELECT user_id FROM polaris_admin_grant GROUP BY user_id HAVING COUNT(*) > 1`, revoke the ones
  you do not want (`DELETE /admin/grants/{id}` or `Grants().Revoke`), and run `Migrate` again.

## [0.4.1] - 2026-11-22

Security fixes. Upgrade: `go get github.com/univeros/polaris.go@v0.4.1`. Check the `mcp.Protect`
entry if your MCP server accepts tokens from an issuer other than Polaris.

### Security

- `plugins/social`: a provider's `email_verified` / `verified` is true only when the provider
  sends true, "true" or 1. The string "false", other strings and container values were read as
  verified, which could let a trusted provider link to an existing account (decision 59).
- `mcp.Protect` refuses OpenID ID tokens, even when their `aud` equals the resource. **Changed:**
  a typ JWT token (or one without typ) is accepted only with a Polaris session token's `roles`
  list; tokens from another issuer must be `at+jwt` (decision 59).

## [0.4.0] - 2026-11-22

Drop-in sign-in pages, users brought over with their existing passwords, middleware for every Go
router, and token verification in your other services. No breaking change: the stable API
([API.md](API.md)), the routes, the database schema and every stored format are unchanged, so an
upgrade is `go get github.com/univeros/polaris.go@v0.4.0`.

### Added

- `plugins/ui`: server-rendered sign-in, MFA, sign-up, email verification, forgot / reset password,
  sign-out and OAuth consent / device pages under `/auth/ui`, without JavaScript;
  `RequireSignIn(p.Protect(h))` for your own pages; `examples/webapp` (decision 57). The pages
  serve one configured origin (`ui.Config.BaseURL`, default `AUTH_ISSUER`), so they work behind a
  TLS-terminating proxy. Passkey, social and magic-link buttons are not in the pages yet.
- `wiring.HandlerProvider`: a plugin serves HTML pages under its own path prefix.
- `oauth.PageProvider`: a plugin (`ui`) fills the `ConsentURL` and `DeviceURL` you left empty.
- `p.Users().Import(ctx, polaris.ImportedUser{…})`: create an account with the password hash your
  previous system stored. The user signs in with the password they already have, and that first
  sign-in rehashes it to Argon2id. Verified (never created): bcrypt, Argon2id/Argon2i, Django and
  passlib PBKDF2-SHA256/512 and scrypt, Firebase's scrypt. Cost parameters are bounded; imports go
  through `Hooks.OnUserCreated` and join `sqlstore.WithTx` (decision 56).
- `security.HashChecker` and `security.ErrUnsupportedHash`: an optional method on a custom
  `Hasher` that `Import` uses to refuse a hash it could not verify.
- `p.Require(permissions...)`, `Protect` as `func(http.Handler) http.Handler` middleware, and
  `p.Authenticate` for routes open to anonymous callers (a token that does not verify is still
  401). `polaris.RequireKind` and `polaris.RequireOrganization` (decision 55).
- Package `verify`: checks Polaris access tokens in another Go service against the issuer's JWK Set
  (RS256 and EdDSA only, typ, iss, aud, exp, scopes; ID tokens and DPoP-bound tokens refused). It
  cannot see revocations or permission changes until a token expires; see its package
  documentation (decision 55).
- Runnable examples: `examples/agents`, `mcp`, `b2b`, `signin-methods`, `hooks` and `webapp`, each
  with a curl walkthrough and a test that keeps it working.
- `SECURITY.md`, `CONTRIBUTING.md`, this changelog, and `docs/v1.md` (what 1.0 requires). Each
  GitHub Release now carries its version's section as release notes.

### Changed

- The code reads as a Go library: comments, internal names and test names no longer refer to the
  PHP project (decision 58). No behaviour changed.
- The `cache.ErrInvalidKey` message says "contains a reserved character" (was "reserved by
  PSR-16"). Match the error with `errors.Is`, not its text.

### Fixed

- Nested guards (`Authenticate` then `Require`, or `Protect` inside `Protect`) resolve the
  credential and run plugin middleware once per request; an API key's rate limit was counted
  twice.

## [0.3.1] - 2026-11-22

Documentation only; no code change. Upgrade freely.

### Changed

- Package documentation (pkg.go.dev) and the README describe Polaris for Go as its own product and
  say what each package does. The README's code snippets are compiled by the test suite.

## [0.3.0] - 2026-11-21

Polaris for Go is its own product (decision 53): it no longer tracks the PHP Polaris
(`polaris-core`), and the two may diverge. Routes, tables and stored formats are still the same in
this release; if you share a database or clients with the PHP version, read the release notes of
each upgrade from now on.

### Changed

- **Breaking (client-visible):** the server identifies as Polaris for Go (decision 54). MCP
  `serverInfo` carries the running Polaris release as its version and a "Polaris for Go: …"
  description. The OpenAPI document (`polaris manifest --format=openapi`, the MCP schema resource)
  is titled "Polaris for Go" and versioned with the running release.
  `/.well-known/agent-configuration` `agent_sdk_versions` names the Go agent SDK,
  `{"github.com/univeros/polaris.go/agent": "<release>"}`, instead of the PHP and TypeScript SDKs.
  Update clients that match on any of these strings. The release is read from the build
  information: the version of `github.com/univeros/polaris.go` your `go.mod` requires, or `devel`.

### Removed

- **Breaking:** `manifest.UpstreamVersion` (decision 54). There is no replacement constant; the
  version in the documents above comes from the build information.

### Fixed

- MCP tool output schemas let every inferred scalar be `null` (decision 52). An MCP client that
  validates a tool result against its `outputSchema` no longer rejects results such as
  `GET /auth/me` with `"display_name": null`.

## [0.2.1] - 2026-11-20

Documentation only; no code change.

### Added

- `plugins/sso/README.md`: configuring SAML and OIDC single sign-on for an organization.

## [0.2.0] - 2026-11-20

### Added

- [API.md](API.md) states what is stable in v0.x: the host surface (package `polaris`, plugin
  constructors and configs, `store/sqlstore`, `polaristest`, `agent`, `cli`, `config`,
  `telemetry/otel`), the plugin SDK (`wiring`, `endpoint`, `manifest`, `event`, `token`) and the
  interfaces a host implements (`security.PasswordHasher`, `notify.Mailer`, `notify.SMSSender`,
  `cache.Cache`, `ratelimit.Store`, `clock.Clock`, `metrics.Metrics`, ...). Pull requests are
  checked against it (`make apicheck`).

### Changed

- **Breaking (plugin SDK):** `wiring.Graph`'s `Identity`, `Sessions`, `MFA`, `Orgs`, `Denylist`,
  `Catalog`, `Resolver`, `Gate`, `Principals` and `Pepper` return narrow interfaces declared in
  `wiring` instead of the concrete services (decision 51). Code that only uses package `polaris`
  is not affected. If you called a method through `Graph()` that the interface no longer has, use
  the programmatic API (`p.Users()`, `p.Orgs()`, `p.Sessions()`, `p.Can()`) or open an issue
  asking for the method.

### Removed

- **Breaking (plugin SDK):** `Graph.Escalation` and `Graph.Tickets` (decision 51).

## [0.1.2] - 2026-11-20

### Fixed

- Social sign-in: the binding cookie's `__Host-` prefix, `Secure` and `SameSite=None` follow the
  scheme of `Config.BaseURL` instead of the incoming connection (decision 50). Behind a
  TLS-terminating proxy the cookie was set `SameSite=Lax`, Apple's cross-site `form_post` callback
  did not carry it, and Sign in with Apple failed with `state_invalid`. Set `Config.BaseURL` to
  your public `https://` URL.

### Changed

- The module is public: `GOPRIVATE` is no longer needed to fetch it.

## [0.1.1] - 2026-11-20

First release under the module path `github.com/univeros/polaris.go`.

### Added

- Package `polaris`: `New` / `FromEnv`, an `http.Handler` with the core auth routes (accounts,
  email verification, password reset, MFA, sessions with rotating refresh tokens, organizations,
  invitations, roles and permissions), `Protect` middleware, `PrincipalFrom`, host hooks, and a
  programmatic API (`Users`, `Orgs`, `Sessions`, `Can`) that applies the routes' checks, events and
  audit.
- Storage in your own PostgreSQL, MySQL or SQLite database (`store/sqlstore`), with `Migrate`
  creating the missing tables; `polaristest` for a test server in one line.
- Plugins: `audit`, `admin`, `apikeys`, `oauth` (OAuth 2.1 / OpenID Connect provider), `agents`,
  `mcp`, `passwordless`, `username`, `anonymous`, `multisession`, `social`, `passkey`, `messaging`
  (SMTP, Twilio, Vonage, HTTP), `sentinel` (risk scoring), `scim`, `sso` (SAML and OIDC).
- The Go agent SDK (`agent`), the `polaris` CLI (`cmd/polaris`, `cli.Run`), OpenTelemetry
  instrumentation (`telemetry/otel`), EdDSA signing keys published in the JWKS.

### Security

- Ships the fixes from the pre-release security review (decisions 38, 39, 42, 43): an
  organization's SCIM connection or identity provider could take over accounts outside that
  organization; social login and account linking were open to login CSRF; `mcp.Protect` accepted a
  login MFA ticket as an access token when the issuer was also a configured audience. No released
  version contains these vulnerabilities.

`v0.1.0` was tagged under the earlier module path `github.com/univeros/polaris-go`; it cannot be
fetched as `github.com/univeros/polaris.go`. `v0.1.1` is the same code under the new path.

[Unreleased]: https://github.com/univeros/polaris.go/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/univeros/polaris.go/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/univeros/polaris.go/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/univeros/polaris.go/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/univeros/polaris.go/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/univeros/polaris.go/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/univeros/polaris.go/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/univeros/polaris.go/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/univeros/polaris.go/compare/v0.1.2...v0.2.0
[0.1.2]: https://github.com/univeros/polaris.go/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/univeros/polaris.go/releases/tag/v0.1.1
