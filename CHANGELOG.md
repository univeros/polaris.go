# Changelog

What changes for an application (a "host") or a plugin author in each release of Polaris for Go.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html): from 1.0.0 nothing in the Go API
([API.md](API.md): every exported name outside `internal/`) breaks within a major version. Each
notable change has its decision in [docs/decisions.md](docs/decisions.md) ("decision N" below).
Breaking changes are marked **Breaking**.

## [Unreleased]

### Added

- `agents.Config.Discovery`: which document `/.well-known/agent-configuration` serves.
  `agents.DiscoveryPolaris`, the default, is v1.0.0's, byte for byte; `agents.DiscoveryAgentAuth` is the
  Agent Auth Protocol's, for its clients (`@auth/agent`)
  ([docs/agent-auth-compat.md](docs/agent-auth-compat.md), decisions 83 to 85). Those clients sign in through
  a host whose key its owner registered, or through a host the server does not know, which a signed-in
  person approves with the code the client shows: the host and the agent are theirs then.
  `agents.Config.DisableDynamicHosts` takes registered hosts only.
- `GET /agents/configuration`: Polaris's discovery document in every mode. `agent.New` and
  `agent.Discover` fall back to it when the well-known document names no `enroll` endpoint. A Go agent
  SDK of v1.0.0 does not: upgrade it before a server switches to `DiscoveryAgentAuth`.
- The Agent Auth Protocol's routes, in both modes: `GET /capability/list`, `GET /capability/describe`,
  `POST /agent/register`, `GET /agent/status`, `POST /agent/request-capability` and
  `POST /capability/execute`, with the protocol's codes (new `agents.Err*` names). Budgets, approval
  strengths, receipts and the kill switch apply to an agent registered this way as to any other. A
  third-party plugin that declares one of the new paths is refused by `polaris.New`.
- `POST /agents/hosts` takes a host's `public_key` (an Ed25519 JWK) or, with `DiscoveryAgentAuth`,
  `jwks_url`: the host signs with its key and has no enrolment token. Revoking such a host revokes its
  agents. `agents.Host` has `PublicJWK`, `JWKSURL` and `KeyThumbprint`; `agents.Config` has `HTTPClient`
  (for those key sets; the default reaches public addresses only) and `DisableJWKSURLs`.
- An agent's `status` may be `pending` or `rejected` (`agents.StatusPending`, `StatusRejected`): a protocol
  registration that waits for a person, or was denied. Neither acts anywhere.
- An agent's registration through a host is idempotent by the host's and the agent's key: pending answers
  the same agent, any other state 409 `agent_exists` (`agents.ErrAgentExists`).
- `agents.Plugin.Prune` deletes the registrations nobody decided; schedule it beside `Polaris.Prune`.
  New events `agents.EventRegistrationRequested` and `agents.EventRegistrationDenied`.
- Where unknown hosts are taken, `GET /agents/approvals/code` answers 429 after too many codes that stand for none of the caller's agents'
  approvals (the `MFAConfirm` budget, per person).
- `oauth.Plugin.CreateClientAs`: `CreateClient` under a `client_id` the caller chose.
- Run `Migrate`: `polaris_agent_host` gains three nullable columns and two unique indexes, `polaris_agent`
  one nullable column and a unique index, and `polaris_agent_registration` is new.

### Fixed

- An agent JWT whose `sub` holds a control character is 401, where PostgreSQL answered 500.

## [1.0.0] - 2026-11-23

Polaris for Go 1.0. The code of v0.7.3 plus the security fixes below, from a review of the plugins
(decision 81); **upgrade now from any v0.x**.

### What 1.0 promises

- **The Go API does not break.** Every exported name outside `internal/` is covered by semantic versioning
  for all of v1: things are added and deprecated, never removed or changed incompatibly ([API.md](API.md)).
  `make apicheck` refuses a break on every pull request.
- **The routes do not break.** Methods, paths, inputs, outputs and errors of the 1.0 specs
  (`polaris manifest --format=openapi`) stay; the recorded contract tests replay them. Fields, routes and
  error codes are added.
- **Stored data stays readable.** Password hashes, encrypted secrets, issued tokens, receipts and the audit
  chain keep verifying, and `Migrate` only adds ([docs/stored-formats.md](docs/stored-formats.md)).
  `APP_KEY` is fixed for the life of a deployment.
- **Security fixes have a policy.** The latest minor gets every fix, the one before it Critical and High
  ones for three months, each announced as a GitHub security advisory ([SECURITY.md](SECURITY.md)). A
  security fix may change behaviour when nothing else closes the hole; the Go API still compiles.
- **Go 1.26 or newer,** PostgreSQL 17, MySQL 8.4 and the bundled SQLite, each in CI. A minor release may
  raise the Go version, never past the older of the two releases the Go team supports.

### Upgrading

1. From v0.7.x: change the version and deploy; no schema change. From v0.6.x or earlier: run `Migrate` (it
   swaps the OAuth consent index, adds tables and indexes, and lists the platform permissions it removes
   from organization roles). `Migrate` upgrades the schema of every released version, in one step.
2. Read the breaks below; a host that uses package `polaris` and plugin constructors compiles unchanged.
3. Afterwards, review:
   - OAuth clients registered `trusted`, or with the CIBA grant, for one organization (decision 81);
   - organizations' SSO providers and domains that someone other than an owner configured (decision 78),
     and `jit.roles` naming `owner` or `admin` (decision 74);
   - SCIM directory tokens an administrator created before v0.7.0: rotate them (decision 74);
   - accounts a directory deprovisioned before v0.7.1 that are disabled and unverified (decision 78);
   - SAML identity providers that sign with SHA-1: they must sign with SHA-256.

### Every break since v0.6.0

- **Go API** (v0.7.0, decisions 70, 74, 76): the concrete services of `identity`, `session`, `mfa`, `orgs`,
  `authz` and `notify` moved under `internal/`; ten `wiring` interfaces are sealed;
  `sso.Plugin.CompleteOIDC` and `CompleteSAML` take the browser's binding; the `Listeners` method of seven
  plugins is gone. Every name is listed under [0.7.0]. Nothing since.
- **Clients** (v0.7.0): `/sso/sign-in` sets a cookie its callback requires; accounts a directory or a provider
  creates outside verified domains are unverified; a second registration of an unverified address needs a
  reset; impersonation tokens carry no `auth_time` and write nothing of the account's; OAuth tokens,
  exchanges, introspection, consents and DPoP proofs are bounded as listed under [0.7.0]; a new default
  `kid` (older ones keep verifying).
- **Clients** (v0.7.1): configuring single sign-on takes an owner's authority; a SCIM DELETE of an account
  nobody proved anonymises it.
- **Clients** (v0.7.2): an `mfa_token` ends with the user's sessions; a domain verification answers 409 when
  another organization verified it first.
- **Clients** (v0.7.3): a locked account is mailed its reset; a disabled account's OAuth grants answer
  `invalid_grant` and introspect as inactive.
- **Clients** (this release): the entries marked **Client-visible** or **Breaking** below.

### Security

- **agents: `Guard` guards a path whatever the Host says.** A request with a port, a trailing dot or
  another name in `Host` matched no capability and reached the handler unchecked. A location is now
  matched by its path when the Host is no location's; a path several hosts share answers 404
  `agents/capability_not_found` under any other name. **Client-visible** on a mux that serves such a path
  as something else under another host name: use `Protect` there.
- **agents: `Guard` reads a path as a router does.** A percent-encoded character (`%3A`, `%2F`) that a router
  decodes passed it unchecked. `Protect` was not affected by either.
- **agents: one body, one meaning.** `Protect` and `Guard` checked constraints on a decoded map while a
  Go handler decoding the same body into a struct matches names whatever their case and reads a first
  value whatever follows it. **Client-visible:** `agents/invalid_arguments` for a body in which two
  members of one object have the same name, upper and lower case alike, one that spells a declared
  argument in another case, and one that begins as an object and is not exactly one.
- **agents: a shorter window is more budget.** A request for a shorter window than the policy's refilled
  its budget each time it passed. **Client-visible:** a budget asked with any window but the policy's
  waits for a person.
- **oauth: a refresh in flight does not outlive a revocation.** On PostgreSQL, a client refreshing back to
  back kept its grant after the user took the consent back, after the reuse of a refresh token was seen
  and after an erasure. Issuing, rotating and ending the tokens of a user's grants now run one after the
  other, and taking a grant back also ends its unredeemed codes and pending requests.
- **oauth: trust takes an owner of the instance.** An operator of one organization could register a
  client `trusted`, or with CIBA, which count in every organization. **Client-visible:** 403
  `admin/forbidden` (400 `invalid_client_metadata` for CIBA).
- **oauth: an exchanged token does not renew itself.** Exchanging a token again never ended.
  **Client-visible:** a token exchanged from one of the provider's own expires no later than it.
- **oauth: a user can always take a client's tokens back.** `DELETE /oauth2/consents/{clientId}` answered
  404 and revoked nothing when the grant left no consent (device, CIBA, exchange, trusted client).
- oauth: a client assertion expires within an hour, and its `jti` is refused until then.
- **core: confirming a factor takes a step-up.** A stolen access token of a user with MFA enrolled its own
  factor and stepped up with it. **Client-visible:** `/auth/mfa/{totp,sms,email}/confirm` answer 401
  `step_up_required` without a recent authentication when the user has a factor. So do
  `/one-time-token/generate`, `POST /api-keys` and `POST /api-keys/{id}/rotate`, which turn a session into
  another credential (with an API key they now answer `api-keys/not_allowed`, not `forbidden`).
- **social: a link ends with the session that started it.** With `RequireVerifiedEmail` off, whoever
  registered an address could hold a link's callback over the owner's first proof of it and then sign in
  as them. **Client-visible:** `/social/{provider}/link` answers 401 when its session has ended, and the
  callback refuses the link.
- **passkey: an RSA key is at most 8192 bits, its exponent at most 65537.** A registered key of any size
  made an unauthenticated request verify with it for minutes. Decoding no longer reserves memory for
  what the input only claims to hold.
- **apikeys: a rotated key acts as who rotated it.** An administrator rotating a colleague's organization
  key received a secret that acted as them. **Client-visible:** the successor's `created_by` and subject
  are the caller. `POST /api-keys/verify` answers `valid: false` for a disabled user, and only the
  permissions the user still holds.
- **sentinel: the guard reads what the endpoint reads.** Fields in the query string, a JSON body with
  anything after it, a form with an unusual content type and an address with a trailing NUL were not
  judged, or not as the account's.
- **sentinel, messaging: security mail is not silenced.** Anyone could have an address challenged, in
  observe mode too, and so drop the mails that say its password or factors changed. Quiet mode follows
  enforced decisions only, and those mails are essential.
- **scim: a directory does not undo an operator's ban.** `active: true` re-enabled an account the directory
  owns; it now reactivates the membership only.
- **sso: a discovery document's endpoints are http(s) URLs.** A `javascript:` one reached the browser of a
  host that navigates to the `url` of `/sso/sign-in` or `/sso/logout`.
- **sso: SHA-1 SAML signatures are refused.** **Breaking** for identity providers that still use them.
- sso: `POST /sso/logout` is for the organization's active members (404 otherwise).
- passwordless: what one destination is sent is bounded (`Auth.OTP.SendMax` while one message lives), and
  what one account adding phones asks for (`SendMax` in `SendWindow`), whatever addresses the requests
  come from; over it nothing is sent and the answer is the same.
- core: recovery codes of an earlier MFA enrolment do not work after the next one. Two concurrent removals
  do not take the last factor of a user for whom MFA is enforced.
- admin: setting the password of an erased account is refused; a reset read before its account was
  disabled is refused where it is written.
- Outbound requests to `::/96`, `fec0::/10` and `64:ff9b:1::/48` are refused too.

### Fixed

- `Migrate` on PostgreSQL no longer fails (`cache lookup failed`) when another replica drops a retired index
  while it reads the table.
- audit: `Verify` accepts the gaps a per-name retention leaves anywhere in the chain (it reported them as
  breaks), also once their checkpoint is pruned, and still reports a row nobody pruned.

## [0.7.3] - 2026-11-23

Security fixes from a review of v0.7.2 (decision 80). **Upgrade now.** No schema change and no Go API
break.

### Security

- **core: a password change in flight does not undo a reset.** A change that verified the old password
  while the account's owner reset it wrote its own password over the new one and ended the owner's
  sessions. The change is now checked again where it is written: a reset, another change, an
  operator's password, a disabled or an erased account wins.
- **core, apikeys, oauth: a lockout is the password sign-in's alone.** Five wrong passwords, which anyone
  who knows an address can send, also stopped the reset mail, the account's API keys and its OAuth
  tokens, and went on doing so after the lock ended. **Client-visible:** `POST /auth/password/forgot`
  mails a locked account; its API keys and OAuth tokens work, and a CIBA request finds it.
- **oauth: a disabled account's grants issue nothing.** An access, ID or refresh token was still issued,
  and introspection still answered `active`, for a user an operator had disabled.
  **Client-visible:** `invalid_grant` and `{"active": false}`. Enabled again, a refresh token that was
  refused meanwhile is unspent.
- **core: an expired session mints nothing.** The holder of an access token of a session past its
  refresh lifetime could step it up, switch its organization, hand it over with a one-time token or
  convert a guest with it.
- core: enabling an account does not bring back one that is being erased, or that was erased meanwhile.

### Changed

- core: a refresh that rotates keeps an organization switch or a step-up made while it ran.
- core: a session is opened for an existing account only (`session: invalid grant`).
- The tests run on the newest Go as well as Go 1.26.

## [0.7.2] - 2026-11-23

Security fixes from a review of v0.7.1 (decision 79). **Upgrade now**, whichever plugins you use,
and first of all on PostgreSQL. No schema change and no Go API break.

### Security

- **core: revoking a user's sessions ends a refresh in flight.** On PostgreSQL, a refresh running
  while the sessions were revoked (password reset or change, logout, disabling, erasure, the first
  proof of the mailbox) could leave its new token live. Opening, rotating and revoking a user's
  sessions now run one after the other, on every database.
- **core: a login in flight does not survive a reset.** A login that verified the password while it
  was being reset or changed, or the account disabled, opened a session all the same, and one whose
  hash was due an upgrade wrote the old password back. Every sign-in (password, host, passkey, social,
  passwordless) is checked again where it opens its session.
- **core: an MFA login ends with the sessions.** **Client-visible:** a `mfa_token` issued before the
  user's sessions were revoked, or the password changed, answers 401 on `/auth/mfa/challenge` and
  `/auth/mfa/verify`.
- core: a step-up, an organization switch and a refresh without rotation mint nothing for a session
  that ended meanwhile, and keep their change when it was refreshed meanwhile. A disabled account
  opens no session.
- **sso: a domain verification is what it answers.** Another organization's claim during the lookup
  made `POST …/domains/{domainId}/verify` answer 200 for a domain that was not verified.
  **Client-visible:** the proof now stands (the domain answered may carry a new id), and the route
  answers 409 `sso_conflict` when another organization verified the domain first.
- scim: renaming, replacing and patching a user decide whether the directory owns the account in the
  transaction that writes it.

### Changed

- core: a refresh that loses to a logout or a revocation is an invalid grant and no longer raises
  `auth.refresh_reuse_detected`.
- sso: a display name a provider sends is trimmed and at most 120 characters.

## [0.7.1] - 2026-11-23

Security fixes from a third pre-1.0 review (decision 78). **Upgrade now if you use `plugins/sso` or
`plugins/scim`.** No schema change and no Go API break. After upgrading:

- Review every organization's SSO providers and domains that someone other than an owner configured:
  `created_by` names who created a provider, and the audit trail's `sso.provider_updated` and
  `sso.domain_*` events who changed one since. They keep working as configured.
- Accounts a directory deprovisioned before this release that are disabled and unverified still hold
  their address; an operator erases them (`DELETE /admin/users/{id}`) where its owner needs it.

### Security

- **sso: configuring single sign-on takes every permission the organization's roles grant.**
  Whoever runs an organization's identity provider signs in as any account the organization owns,
  with the roles it holds, so an administrator with `org.update` alone could add or repoint a
  provider and act as an owner. **Breaking, client-visible:** creating, changing (disabling included)
  or deleting a provider, and adding, verifying or deleting a domain, answers 403 `sso/forbidden`
  without that authority, as connecting a SCIM directory does since v0.7.0. Reading, listing and
  testing stay with `org.update`.
- **scim: deprovisioning an account nobody proved frees its address.** A directory could create an
  account for an address nobody had registered and deprovision it; the disabled account kept the
  address from its owner until an operator stepped in. **Breaking, client-visible:** a SCIM DELETE of
  an owned account whose mailbox nobody has proven anonymises it in either `deprovision` mode
  (recorded as `scim.user_deleted`; `Hooks.OnUserDeleted` runs). Verify the organization's domains if
  deprovisioned accounts should be kept: its accounts are then proven. `active: false` still only
  suspends the membership.
- sso: a provider creates accounts for email addresses only (`sso/assertion_invalid` otherwise, an
  address without a dot in its domain included); existing accounts keep signing in. A sign-in checks
  the account and the membership again in the transaction that opens its session.
- core: on MySQL, revoking every session of a user also ends the ones issued since the revoking
  transaction began.
- scim, sso: a confirmed registration ends a directory's or a provider's hold on the account, as
  every other first proof of its mailbox does.
- A signed payload is one JSON object: a provider's ID token, a client assertion or DPoP proof, a
  receipt, a request JWT and what `verify` and `mcp.Protect` verify are refused when anything follows
  it. An agent's body holding more than one JSON value has no arguments (a constrained one is then
  missing), and an MCP message with anything after it is a parse error.
- core: `POST /auth/email/verify/resend` sends nothing to a disabled account.
- scim, sso, agents: the READMEs say what a uniqueness conflict tells a directory, how long a domain
  stays verified and what the auto-approval policy remembers.

### Changed

- scim: **client-visible:** with `deprovision: delete`, a SCIM DELETE of the organization's last
  active owner answers 409, as it did with `deactivate`.

### Fixed

- core: an address can be erased again after it was registered again: the second erasure failed on
  the first one's tombstone.

## [0.7.0] - 2026-11-23

The 1.0 release candidate: security fixes from a second pre-1.0 review (decisions 74 to 77) and the
v1 Go API (decision 70). Upgrade now, and **run `Migrate`**: it swaps the OAuth consent index and
removes platform permissions that organization roles should never have held (it lists each one).

- **Security** first: read the Security section if you use SSO, SCIM, OAuth, the admin plugin or
  agents. Accounts a directory or an identity provider created on a domain the organization has not
  verified are now unverified until their owner proves the mailbox.
- **Breaking (Go API):** concrete services that only Polaris used moved under `internal/`, the
  `wiring` service interfaces are sealed, and some plugin `Listeners` methods are gone. A host that
  uses `polaris.*` and plugin constructors is unaffected; see Changed for every removed name.
- **Client-visible:** new tokens carry an RFC 7638 `kid` (older tokens keep verifying, and the JWKS
  still lists the old `kid`), and the entries marked client-visible below.

### Added

- `token.Thumbprint(alg, publicKey)`, the RFC 7638 JWK thumbprint; `token.Config.LegacyKeyID` and
  `PreviousLegacyKeyID`, a second kid `VerifyJWT` accepts for each key; `config.Secrets.LegacyKeyID`
  and `PreviousLegacyKeyID` (decision 73).
- `APP_KEY` is fixed for the life of a deployment in 1.x: `config.Secrets`, SECURITY.md
  ("Operating Polaris") and docs/stored-formats.md say what depends on it and what changing it
  invalidates (decision 73).

### Changed

- **Breaking** (Go API, decision 70): from v1.0.0 every exported name outside `internal/` is the
  API ([API.md](API.md)), so what only Polaris used left the public packages. Nothing API.md listed
  as the host surface or the plugin SDK is removed; this affects code that imported one of the
  "public but not stable" packages for a concrete service. Use `polaris.Users` / `Orgs` /
  `Sessions` from a host and `wiring.Graph`'s `Identity()`, `Sessions()`, `MFA()`, `Orgs()`,
  `Gate()`, `Resolver()`, `Principals()`, `Denylist()` from a plugin. Removed:
  - `identity`: `Service`, `New`, `Config`, `Sessions`, `MFAGate`, `MFATickets`,
    `AuthorityResolver`, `NewUser`, `ImportedUser`, `UserView`, `ErrInvalidConfig`.
  - `session`: `Service`, `New`, `Config`, `Issuer`, `PrincipalResolver`, `UserPrincipals`,
    `Denylist`, `NewDenylist`, `MFATickets`, `NewMFATickets`, `PurposeLoginMFA`, `ReservedClaim`,
    `ErrInvalidConfig`.
  - `mfa`: `Service`, `New`, `Config`, `Sessions`, `Tickets`, `PrincipalResolver`, `TOTP`,
    `NewTOTP`, `TOTPProvider`, `QRRenderer`, `SVGQRCode`, `TOTPEnrollResult`, `OTPEnrollResult`,
    `OTPChallengeResult`, `ManagedFactorView`, `ManagedViewOf`, `RecoveryCodeCount`,
    `ErrInvalidConfig`.
  - `orgs`: `Service`, `New`, `Config`, `Sessions`, `Invitation`, `InvitationTTL`, `Role`,
    `NewRole`, `RoleChanges`, `ErrInvalidConfig`, and the message constants `MsgAlreadyMember`,
    `MsgBadStatus`, `MsgInvalidInvitation`, `MsgInvitationEmail`, `MsgInvitationNotFound`,
    `MsgInvitationNotYetUsed`, `MsgLastActiveOwner`, `MsgLastOwner`, `MsgMemberNotFound`,
    `MsgMemberSuspended`, `MsgMembershipExists`, `MsgOrgName`, `MsgOrganizationNotFound`,
    `MsgOwnMembershipSuspend`, `MsgOwnerModify`, `MsgOwnerRemove`, `MsgOwnerRole`,
    `MsgOwnerStatus`, `MsgRoleName`, `MsgRoleNotFound`, `MsgRoleSlug`, `MsgRoleSlugReserved`,
    `MsgRolesRequired`, `MsgSlugTaken`, `MsgSlugUnderivable`, `MsgSystemRole`, `MsgUserNotFound`.
  - `authz`: `Resolver`, `NewResolver`, `Gate`, `NewGate`, `EscalationGuard`,
    `NewEscalationGuard`, `Principals`, `NewPrincipals`, `Seed`.
  - `notify`: `Listener`, `Users`.

  What stays in those packages is what a plugin sees: `identity.LoginResult`, `PasswordError`,
  `PasswordPolicy`, `NormalizeEmail` and the sentinels; `session.Info`; `mfa.FactorType`,
  `LoginChallenge`, `FactorView`, `ViewOf`, …; `orgs.Member`, `Error`; `authz.Authority`, `Caller`,
  `Catalog`, the permission keys and role slugs. The wire messages and behaviour are unchanged.
- **Breaking** (Go API, decision 70): `wiring.Identity`, `Sessions`, `MFA`, `Orgs`, `Denylist`,
  `Catalog`, `Resolver`, `Gate`, `Principals` and `Pepper` are sealed (an unexported method): only
  Polaris implements them, so a 1.x release can add a method without breaking a plugin. A test
  double that implemented one embeds it instead (`struct{ wiring.Identity }`). Every other exported
  interface is frozen for v1.
- `make apicheck` compares every public package with the base (was: the names in
  `scripts/api-stable.txt`, now removed), and refuses an incompatible change outright once the
  base is `v1.0.0` or later. [API.md](API.md) is the v1 promise, with the deprecation policy: added
  and deprecated in 1.x, removed only in v2.
- **Client-visible:** without `AUTH_JWT_KID` the `kid` of new tokens and of the JWKS is the RFC 7638
  thumbprint of the public key (base64url, 43 characters), not the SHA-256 hex of the PEM text, so
  re-encoding the same key no longer changes it. Nothing issued before stops verifying: the server
  still accepts tokens naming the old `kid`, and `/auth/.well-known/jwks.json` publishes each key a
  second time under its old `kid` (same key material), after the keys under their new kids, for
  verifiers holding old tokens or a cached key set. An explicit `AUTH_JWT_KID` or
  `AUTH_JWT_PREVIOUS_KID` is unchanged and gets no alias (decision 73).

### Security

Account provisioning and email proof (decision 74). Upgrade; no schema change.

- scim, sso: a directory or an identity provider vouches for a mailbox only on a domain its
  organization verified. **Client-visible:** an account created by SCIM `POST /Users` or by
  just-in-time provisioning outside those domains is unverified (`email_verified` false in the
  `/sso/exchange` envelope and in the session's tokens), and stays unverified when the provider
  signs it in again; when the mailbox's owner proves it (reset, email code, magic link) the
  organization's IdP answers `sso/user_unknown` for it and its directory changes the membership
  only. A SCIM `userName` change of a verified account to an address outside the verified domains
  answers 403 `mutability`; an unverified account moves and stays unverified. Accounts created
  before this release are not changed.
- core, passwordless: a reset or verification token, and a passwordless `verify-email` or
  `reset-password` code, is refused once the account has left the address it was sent to.
- core: `POST /auth/register` for an address whose account nobody verified sends a new
  verification message (the earlier tokens stop working). With the password the account already
  has, nothing else changes. With another password neither is kept: the stored password, display
  name, sessions, factors and keys are removed, the new password is not stored, and after
  verifying the owner sets a password with a reset. **Client-visible:** same 202; a second
  `user.registered` event for the same user; after a contested registration the verified account
  has no password until a reset; the verification token is longer (`<nonce>.<binding>`, 76
  characters, still opaque) and confirms only the password it was issued with: after a password
  change on an unverified account, request a new message. Tokens already sent keep working until
  they expire.
- sso: a sign-in completes only in the browser that started it. **Breaking, client-visible:**
  `POST /sso/sign-in` sets a `polaris_sso_<state>` cookie (`__Host-` prefixed, `SameSite=None;
  Secure` under https) that `/sso/callback/{providerId}` requires: call sign-in from the browser
  that follows `url` (with credentials when cross-origin), not from a server. A callback without
  it answers 403 `sso/assertion_invalid`. IdP-initiated SAML (`idp_initiated`) is unchanged.
  **Breaking (Go API):** `sso.Plugin.CompleteOIDC` and `CompleteSAML` take the browser's binding;
  `Start` returns it (`Started.State`, `Started.Binding`).
- sso, scim: the roles an IdP or a directory hands out stay within the authority of whoever
  configures it. **Client-visible:** `jit.roles` on `POST`/`PATCH /orgs/{id}/sso/providers` must be
  roles of the organization (422) carrying no permission the caller lacks (403 `sso/forbidden`);
  creating a SCIM connection or rotating its token takes every permission the organization's roles
  grant, in practice an owner (403 `scim/forbidden`). After upgrading, review providers whose
  `jit.roles` name `owner` or `admin` and rotate directory tokens an administrator created.
- sso: an ID token without `exp` is refused, and so is a discovery document whose `issuer` is not
  the configured one. **Client-visible:** an unverified domain claim no longer blocks the domain:
  another organization's `POST /orgs/{id}/sso/domains` replaces it (409 only for a verified domain
  or the caller's own claim), and an organization's verification token for a domain is the same on
  every claim. Existing claims keep their token.
- `polaris.SignIn.AMR`: documented that `"sso"` opens an organization-bound session.
- `wiring.Identity` gains `ChangeEmail` (the one place an account's address changes); `sso` and
  `scim` implement `wiring.AccessEraser`.

- `plugins/oauth` without the admin plugin: a session an organization's identity provider opened
  is no operator on the OAuth admin routes, even for a superadmin (decision 77).
- `plugins/agents`: a capability whose grant was revoked is not auto-approved again when the agent
  asks; a person decides (decision 77). **Client-visible:** such a request answers `pending`.

Operator reach and hardening before 1.0 (decision 76). **Client-visible** marks what a client or an
operator's tool sees change.

- admin: impersonation follows the reach rule of `Manage`: below `owner`, an operator cannot
  impersonate an operator of its own role or above. **Client-visible:** 403 `admin/forbidden`.
- admin, core: an impersonation token is not the account holder. It carries no `auth_time`, and
  every route that needs no permission and writes, destroys or is a step-up route refuses it
  (`pipeline.DeniesImpersonation`, `token.Token.ImpersonatedBy`); the MCP tool list hides those
  tools from it. Audit rows written while serving one carry `impersonated_by`. **Client-visible:**
  such a route answers 403 `forbidden`; the token has no `auth_time` claim.
- admin: an organization-scoped owner replaces a user's operator grant only when the grant already
  there is on its organization, and never grants to a superadmin. **Client-visible:**
  `POST /admin/grants` answers 403 `admin/forbidden` otherwise.
- admin: a session an organization's identity provider opened is no operator. **Client-visible:**
  `/admin/*` answers it 401 `admin/unauthorized`.
- agents: the auto-approval policy does not refill a budget. After an agent exhausts a grant of a
  capability, its next request for it waits for a person until the spent grant's window has passed
  (a budget without a window: always). **Client-visible:** `POST /agents/grants/request` answers
  that grant `pending`, with an approval to complete, where it answered `active`.
- audit, admin: drains are delivered to public addresses only (after DNS resolution), without
  following redirects, after the recording transaction commits and off the writer's goroutine
  (15 s per batch, 32 batches in flight). New `audit.Config.Drains`; `Config.HTTPClient` still turns
  delivery on and is then used as given, so a host that passes its own client bounds what it
  reaches (set `Drains: true` and leave `HTTPClient` nil for the guarded client). New
  `audit.Plugin.WaitDrains`. **Client-visible:** `POST /admin/organizations/{id}/drains` answers
  422 for an endpoint with credentials, a literal non-public address or `localhost`; a drain's
  `last_error` is a category (`refused`, `timeout`, `unreachable`, `HTTP <status>`) instead of the
  transport's error text; a drain endpoint that answered through a redirect now fails with
  `HTTP 3xx`.
- authz: no organization role grants a platform permission (`users.read`, `users.manage`), whatever
  its rows say (`authz.PlatformOnly`), and `Migrate` removes such grants from organization roles,
  returning one line and logging one warning per removal. Review the audit log of the members of a
  role it names. **Client-visible:** a member who held such a grant gets 403 on other users'
  `/users/{id}`.
- Erasing an account erases what the plugins hold about it inside the same transaction
  (`wiring.UserEraser`, new, and `wiring.AccessEraser`): a failure rolls the erasure back instead
  of being logged. A third-party plugin that erases in an `event.UserDeleted` listener keeps
  working, after the commit as before; implement `wiring.UserEraser` to join the transaction.
- multisession, sentinel: the device cookies are `Secure` when the configured issuer is https, not
  only when the request itself came over TLS (a proxy that ends TLS). **Client-visible:** the
  `Secure` attribute on `polaris_ms_device` and `polaris_device`.
- messaging: with no channel configured, the log carries a message's recipient and template only,
  never its subject, body or variables (codes, reset links), and startup logs a warning.
  `messaging.Log` logs bodies only with the new `Bodies: true`.
- Per-IP rate limits key an IPv6 client by its /64 and an IPv4-mapped address by its IPv4 address.
  **Client-visible:** IPv6 clients in one /64 share the per-IP budgets (429 sooner).
- `polaris.New` logs a warning when `Config.Hasher` is an Argon2id below the default cost
  (`polaristest.Hasher()` in a production `Config`); silent under `go test`.
- **Breaking** (Go API, decision 76; nothing a host or a plugin calls): the `Listeners` method of
  the admin, multisession, anonymous, username, sso, scim and passwordless plugins is removed;
  they erase through `EraseUser` / `EraseAccess` now.

Found by a security review with running tests; each is fixed with the regression test that failed
before (decision 75). Run `Migrate` (one index of `polaris_oauth_consent` is replaced).

- **oauth: an organization cannot repoint a trusted client.** On a client an operator registered
  `trusted`, or listed in `oauth.Config.TrustedClients`, the organization's route changes only
  `name`, `logo_uri`, `policy_uri`, `tos_uri` and `disabled`. **Client-visible:** `PATCH
  /orgs/{id}/oauth/clients/{clientId}` answers 400 `invalid_client_metadata` for a different
  `type`, `redirect_uris`, `grant_types`, `token_endpoint_auth_method`, `jwks`, `jwks_uri`,
  `client_uri` or `dpop_bound_access_tokens` on such a client (`scopes` already did, decision 69).
  `oauth.Plugin.UpdateClient` without `mayTrust` does the same.
- **oauth: a token exchange stays within the subject's client and audience.** **Client-visible**
  at `POST /oauth2/token` with the token-exchange grant: an access token issued to another client
  is refused as `subject_token` or `actor_token` (400 `invalid_grant`) unless the exchanging client
  is trusted; without `resource` the new token keeps the subject token's audience (it was the
  issuer); a `resource` other than the subject's audience answers 400 `invalid_target` unless the
  subject was for this server or the client is trusted. A session is a subject only while it is
  the user's own live session: a logged-out session, an operator's impersonation token and a
  session an organization's identity provider opened answer 400 `invalid_grant`.
  `oauth.Plugin.Exchange` does the same.
- **oauth: a DPoP proof is for this server's URL.** The `htu` of a proof is compared with the
  origin of `oauth.Config.BaseURL` and the path requested, not with the request's `Host` header.
  **Client-visible:** a deployment reached under a host name other than its `BaseURL` (default
  `Auth.Issuer`) must set `BaseURL` to the URL clients call, as the discovery documents already
  assume; proofs naming any other origin answer `invalid_dpop_proof` (401 on a resource route).
- **oauth: introspection answers the token's own client.** **Client-visible:** `POST
  /oauth2/introspect` answers `{"active": false}` for a token issued to another client, unless the
  token's `aud` is the caller's client id or the caller is trusted. A resource server that
  introspects other clients' tokens is registered `trusted`.
- **oauth: a consent counts in the organization it was given in.** **Client-visible:** the same
  client asking the same user in another organization (or outside any) gets 409
  `consent_required` again; `GET /oauth2/consents` lists one consent per client and organization.
  Existing consents keep counting for the organization they name.
- **oauth, agents: a token ends with the grant behind its permission scopes.** A token of an
  agent, its own or one a user delegated to it, carries a permission scope only while a live grant
  covers it and expires no later than that grant. **Client-visible:** such a token response's
  `expires_in` (and the token's `exp`) can be shorter than the access-token lifetime, and after a
  windowed grant expired the scope is no longer issued. New for plugins:
  `oauth.ClientGrantWindows`, implemented by `agents.Plugin.ClientPermissionsUntil`.

## [0.6.0] - 2026-11-22

The last v0.x feature release before 1.0: the wire speaks plain Go (decisions 64 and 65), the host
API gains what everyday programs needed (decision 66), and an audit-chain hang is fixed (decision
72). **Run `Migrate` after upgrading** (it now also seeds the audit chain's lock row). Many entries
are **Client-visible**: timestamps end in `Z`, empty objects are `{}`, request bodies are typed
strictly (422 on a wrong JSON type), OpenAPI `operationId`s are the route names, JWT and schema
error texts are new, and SCIM, agents and OAuth inputs follow their RFCs. Read Changed before
upgrading a client. New for hosts: `SignIn.OrganizationID`, `Orgs().Invite`,
`sqlstore.Store.Conn`/`Tx`/`AfterCommit`/`Close`, two-phase event delivery
(`Config.TxListeners`), `polaris.DevEnv`, `polaristest.Hasher`, `Polaris.Wrap`.

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

### Changed

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

[Unreleased]: https://github.com/univeros/polaris.go/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/univeros/polaris.go/compare/v0.7.3...v1.0.0
[0.7.3]: https://github.com/univeros/polaris.go/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/univeros/polaris.go/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/univeros/polaris.go/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/univeros/polaris.go/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/univeros/polaris.go/compare/v0.5.1...v0.6.0
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
