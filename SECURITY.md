# Security policy

Polaris for Go is an authentication and authorization library. A vulnerability in it is a
vulnerability in every service that uses it, so reports are taken seriously and handled privately.

## Supported versions

| Version | Security fixes |
|---|---|
| The latest minor release of the current major version (`v1.N.x`) | Every fix, as a patch release `v1.N.x+1`. |
| The minor release before it (`v1.N-1.x`) | Fixes whose advisory rates them Critical or High (CVSS 7.0 or more), as a patch release, for 3 months after `v1.N.0` ships. |
| Older minor releases | None: upgrade to the latest minor release. Within a major version an upgrade breaks no stable Go API, route or stored data ([API.md](API.md), [docs/stored-formats.md](docs/stored-formats.md)). |

A new major version will state how long the previous one gets fixes.

The v0.x versions get no fixes: upgrade to v1 ([CHANGELOG.md](CHANGELOG.md) says how, and what each
release fixed).

## Reporting a vulnerability

Do not open a public issue, pull request or discussion.

Report it privately through GitHub: on the repository's **Security** tab choose **Report a
vulnerability** ([direct link](https://github.com/univeros/polaris.go/security/advisories/new)).
The report and the conversation that follows stay private until the fix is released.

Include what you can of:

- the affected version (tag or commit) and the packages or plugins involved;
- the configuration needed (`polaris.Config` fields, plugins enabled, database);
- the steps or a proof of concept, ideally a Go test against `polaristest`;
- what an attacker gains, and what they need beforehand (an account, an organization, a client).

## What happens next

- You get an acknowledgement within a few days, and updates as the fix progresses.
- The fix is made and released first, and announced after, with credit to the reporter unless they
  prefer otherwise. Nothing that would let someone exploit an unpatched release is made public
  before its fix ships.
- Every fix is announced, when its release ships, in:
  - a [GitHub security advisory](https://github.com/univeros/polaris.go/security/advisories)
    naming the affected and fixed versions, with a CVE identifier requested through GitHub;
  - the release notes: the version's **Security** section in [CHANGELOG.md](CHANGELOG.md) and its
    GitHub Release;
  - the [Go vulnerability database](https://pkg.go.dev/vuln/), to which the advisory is reported,
    so that `govulncheck` flags builds that use an affected version.

## Scope

In scope: anything in this module that lets someone do what Polaris should prevent, for example

- authentication bypass: signing in, or acting, as another account or agent without its credentials;
- token forgery or confusion: minting, altering or replaying access tokens, refresh tokens, API keys,
  OAuth codes, ID tokens, DPoP proofs, agent grants or receipts, or using one kind where another is
  required;
- privilege escalation: gaining a role or permission, or reaching another organization's members,
  data or identity-provider configuration (SSO, SCIM) without being granted it;
- secret disclosure: password hashes, encrypted secrets, signing keys, one-time codes or tokens
  leaking through responses, logs, telemetry or errors;
- bypassing MFA, rate limits, account lockout, email verification or the agent approval flow;
- request forgery (CSRF, SSRF through client- or tenant-supplied URLs), open redirects in sign-in
  flows, and injection.

Out of scope: vulnerabilities in a host application's own code or configuration (for example
`Config.BaseURL` pointing at the wrong scheme, or secrets committed to its repository), in
dependencies that do not affect Polaris (report those upstream), and denial of service that needs
traffic volumes a rate limiter in front of the service is expected to absorb. If in doubt, report
it.

## Operating Polaris

What a deployment must keep, and what it may rotate:

- **`APP_KEY` is fixed for the life of a deployment in 1.x.** Keep it in your secret manager,
  back it up with the database, and never change it. Polaris derives two keys from it: the pepper
  behind every stored lookup digest (refresh tokens, API keys, operator keys, SCIM tokens, OAuth
  client secrets, codes and refresh tokens, recovery codes, email verification, password reset,
  invitation and passwordless tokens) and the encryption key of every stored secret (TOTP secrets,
  SSO client secrets, social provider tokens, audit drain secrets). A new `APP_KEY` makes all of
  them unmatchable or unreadable: every user is signed out, every API key, OAuth client secret and
  SCIM token stops working, and every TOTP factor must be enrolled again. If `APP_KEY` leaks,
  replacing it is that reset; there is no other remedy in 1.x. A key ring (`APP_KEY_PREVIOUS`) can
  be added in a later 1.x release without a format change: encrypted values carry a version byte
  and a lookup can try both keys ([docs/stored-formats.md](docs/stored-formats.md), decision 73).
- **The JWT signing key rotates.** Generate a new pair, set it as `AUTH_JWT_PRIVATE_KEY` and
  `AUTH_JWT_PUBLIC_KEY`, and keep the old public key in `AUTH_JWT_PREVIOUS_PUBLIC_KEY` for at least
  one access-token lifetime, so tokens it signed keep verifying and the JWKS publishes both. Without
  `AUTH_JWT_KID` the `kid` is the RFC 7638 thumbprint of the public key; tokens and key sets from
  releases before decision 73, which named the key by the SHA-256 of its PEM text, keep verifying.
