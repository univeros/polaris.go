# Security policy

Polaris for Go is an authentication and authorization library. A vulnerability in it is a
vulnerability in every service that uses it, so reports are taken seriously and handled privately.

## Supported versions

Polaris for Go is pre-1.0. Security fixes go to `main` and ship in a new release of the latest
minor version (today `v0.3.x`). Older minor versions are not patched: upgrade to the latest one
([CHANGELOG.md](CHANGELOG.md) says what changes). After `v1.0.0` this policy will name the
supported major and minor versions.

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
- Before 1.0, a fix ships as a patch release whose notes ([CHANGELOG.md](CHANGELOG.md), the GitHub
  Release) describe it under **Security**. From v1.0.0, each fix is also published as a
  [security advisory](https://github.com/univeros/polaris.go/security/advisories).

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
