# examples/b2b

A multi-tenant SaaS on Polaris. Each customer is an organization with its own members, roles and API
keys. The host declares its own permissions and gates its own routes with them:

| Route | Needs |
| --- | --- |
| `GET /api/projects` | `projects.read` |
| `POST /api/projects` | `projects.write` |

It shows:

- `cfg.Permissions` (`projects.read`, `projects.write`) and `p.Protect` on host routes; users, API
  keys and SCIM-provisioned accounts all pass through the same check.
- Organizations, custom roles, invitations (`/orgs/*`, `/auth/invites/accept`).
- `apikeys`: an organization's key carrying a subset of permissions.
- `audit` (the organization's log) and `admin` (the operator API, with a `pak_` key).
- `sso` (an OIDC identity provider and a verified domain per organization) and `scim` (a directory
  connection that provisions users and maps groups onto roles).

Everything runs in one process with zero setup: SQLite in a temporary directory, generated keys,
emails written to the log.

## Run it

```sh
go run ./examples/b2b
```

It prints an operator key (`operator key (viewer, this run only): pak_…`) and serves on
`http://localhost:8080` (`ADDR` changes it). Verification and invitation tokens appear in its log as
`Polaris dev email (not delivered) … context=map[token:…]`.

One thing the program does that Polaris has no host call for yet: a new organization's `owner` and
`admin` roles get the host's own permissions (`grantToRole`, run from an `org.created` listener).
Without it the owner could not put `projects.*` into a role, an invitation or an API key: Polaris
refuses to grant permissions the caller does not hold.

## Walkthrough

The commands use `jq`, and `B=http://localhost:8080`, `J='Content-Type: application/json'`.
Output is from a real run, trimmed.

### 1. Ada signs up and creates her organization

```sh
curl -s -X POST $B/auth/register -H "$J" -d '{"email":"ada@acme.test","password":"correct horse battery staple"}'
# {"message":"If the address can be registered, a verification message has been sent."}
# the server log: ... template=verify_email context=map[token:2VniHe0dN4TyrA1Zoa4vjbdhvs8yojKInM5AvdywO4g]
curl -s -X POST $B/auth/email/verify -H "$J" -d '{"token":"<token from the log>"}'
# {"message":"Email verified."}
ADA=$(curl -s -X POST $B/auth/login -H "$J" -d '{"email":"ada@acme.test","password":"correct horse battery staple"}' | jq -r .data.access_token)

ORG=$(curl -s -X POST $B/orgs -H "Authorization: Bearer $ADA" -H "$J" -d '{"name":"Acme"}' | jq -r .data.id)
# {"data":{"id":"01a2022d-12de-…","name":"Acme","role":"owner","slug":"acme"}}

# scope the session to the organization: the token now carries its roles
ADA=$(curl -s -X POST $B/auth/switch-org -H "Authorization: Bearer $ADA" -H "$J" -d "{\"organization_id\":\"$ORG\"}" | jq -r .data.access_token)
H="Authorization: Bearer $ADA"
```

### 2. Custom roles with the host's permissions

```sh
curl -s -X POST $B/orgs/$ORG/roles -H "$H" -H "$J" -d '{"name":"Editor","slug":"editor","permission_keys":["org.read","projects.read","projects.write"]}'
# {"data":{"description":null,"id":"01a2022d-134a-…","is_system":false,"name":"Editor","permission_keys":["org.read","projects.read","projects.write"],"slug":"editor"}}
curl -s -X POST $B/orgs/$ORG/roles -H "$H" -H "$J" -d '{"name":"Viewer","slug":"viewer","permission_keys":["org.read","projects.read"]}'
# {"data":{… "name":"Viewer","permission_keys":["org.read","projects.read"],"slug":"viewer"}}

curl -s -X POST $B/api/projects -H "$H" -H "$J" -d '{"name":"Website relaunch"}'
# {"id":1,"name":"Website relaunch","created_by":"01a2022d-0908-…"}
curl -s $B/api/projects -H "$H"
# {"caller":"user","organization":"01a2022d-12de-…","projects":[{"id":1,"name":"Website relaunch",…}]}
```

### 3. Invite Bob as a viewer

```sh
curl -s -X POST $B/orgs/$ORG/invites -H "$H" -H "$J" -d '{"email":"bob@acme.test","role_slugs":["viewer"]}'
# {"data":{"email":"bob@acme.test","expires_at":"2026-11-29T07:33:58+00:00","id":"01a2022d-13e6-…","role_slugs":["viewer"]}}
# the server log: ... to=bob@acme.test template=org_invite context="map[organization_id:… token:28C7uRRe…]"
```

Bob signs up, verifies and signs in as Ada did (`BOB=<his access token>`), then accepts:

```sh
curl -s -X POST $B/auth/invites/accept -H "Authorization: Bearer $BOB" -H "$J" -d '{"token":"<invitation token from the log>"}'
# {"data":{"organization_id":"01a2022d-12de-…"}}
BOB=$(curl -s -X POST $B/auth/switch-org -H "Authorization: Bearer $BOB" -H "$J" -d "{\"organization_id\":\"$ORG\"}" | jq -r .data.access_token)

curl -s $B/api/projects -H "Authorization: Bearer $BOB"
# {"caller":"user","organization":"01a2022d-12de-…","projects":[{"id":1,"name":"Website relaunch",…}]}
curl -s -w ' %{http_code}\n' -X POST $B/api/projects -H "Authorization: Bearer $BOB" -H "$J" -d '{"name":"Nope"}'
# {"error":"forbidden","message":"You do not have permission to perform this action."} 403
```

### 4. An organization API key

The key belongs to the organization (it outlives Ada's membership) and carries only `projects.read`.

```sh
KEY=$(curl -s -X POST $B/api-keys -H "$H" -H "$J" -d "{\"name\":\"CI reporter\",\"organization_id\":\"$ORG\",\"permissions\":[\"projects.read\"]}" | jq -r .data.key)
# {"data":{… "key":"pk_live_MUNRT-…","name":"CI reporter","owner_type":"organization","permissions":["projects.read"],"status":"active",…}}

curl -s $B/api/projects -H "x-api-key: $KEY"
# {"caller":"api_key","organization":"01a2022d-12de-…","projects":[…]}
curl -s -w ' %{http_code}\n' -X POST $B/api/projects -H "Authorization: Bearer $KEY" -H "$J" -d '{"name":"Nope"}'
# {"error":"forbidden","message":"You do not have permission to perform this action."} 403
```

### 5. The audit log and the operator API

```sh
curl -s $B/audit/organization/$ORG -H "$H" | jq -r '.data[] | "\(.occurred_at) \(.name) by \(.actor_type)"'
# 2026-11-22T07:34:08+00:00 api_keys.created by user
# 2026-11-22T07:34:07+00:00 session.organization_switched by user
# 2026-11-22T07:34:07+00:00 org.member_joined by user
# 2026-11-22T07:33:58+00:00 org.member_invited by user
# 2026-11-22T07:33:58+00:00 org.role_created by user
# 2026-11-22T07:33:58+00:00 org.role_created by user
# 2026-11-22T07:33:58+00:00 session.organization_switched by user
# 2026-11-22T07:33:58+00:00 org.created by user

OP=pak_…   # the operator key the program printed
curl -s $B/admin/organizations -H "Authorization: Bearer $OP" | jq -c '.data[] | {id, name, slug}'
# {"id":"01a2022d-12de-…","name":"Acme","slug":"acme"}
curl -s $B/admin/stats -H "Authorization: Bearer $OP"
# {"data":{"active_users":{"24h":2,…},"sign_ins":{"24h":2,…},"sign_ups":{"24h":2,…},"totals":{"active_sessions":2,"organizations":1,"users":2}}}
```

### 6. Single sign-on: an OIDC identity provider

An organization admin (`org.update`) registers the company's IdP. The client id and secret come from
the IdP's app registration; the redirect URI to register there is the provider's `sp.acs_url`. `jit`
creates unknown users on first sign-in, here as viewers.

```sh
PROV=$(curl -s -X POST $B/orgs/$ORG/sso/providers -H "$H" -H "$J" -d '{
  "type": "oidc", "name": "Acme Okta", "issuer": "https://acme.okta.com",
  "config": {"client_id": "0oa1b2c3d4", "client_secret": "from-the-idp", "scopes": "openid email profile"},
  "attributes": {"email": "email", "name": "name"},
  "jit": {"enabled": true, "roles": ["viewer"]},
  "redirect_uris": ["http://localhost:8080/sso/done"]}' | jq -r .data.id)
# {"data":{… "config":{"client_id":"0oa1b2c3d4","client_secret_set":true,"scopes":"openid email profile"},"jit":{"enabled":true,"roles":["viewer"]},"type":"oidc",…}}
# (the secret is encrypted at rest and never returned)

curl -s $B/orgs/$ORG/sso/providers/$PROV -H "$H" | jq -c .data.sp
# {"acs_url":"http://localhost:8080/sso/callback/01a2022d-3de0-…","entity_id":"http://localhost:8080/sso/metadata/01a2022d-3de0-…",…}
```

A verified domain routes `POST /sso/sign-in {"email": "…@acme.test"}` to this provider. Polaris
answers the DNS TXT record and the HTTPS file that prove the organization owns the domain:

```sh
DOM=$(curl -s -X POST $B/orgs/$ORG/sso/domains -H "$H" -H "$J" -d "{\"domain\":\"acme.test\",\"provider_id\":\"$PROV\"}" | jq -r .data.id)
# {"data":{"domain":"acme.test","verification":{"dns":{"record":"_polaris.acme.test","type":"TXT","value":"polaris-sso-79a7…"},
#          "https":{"url":"https://acme.test/.well-known/polaris-sso.txt","body":"polaris-sso-79a7…"},…},"verified":false,…}}
curl -s -X POST $B/orgs/$ORG/sso/domains/$DOM/verify -H "$H"
# {"error":"sso_domain_unverified","detail":"Neither the DNS record nor the well-known file carries the token yet.","status":422,…}
```

`acme.test` cannot be verified (nobody publishes that record), so this step stops here; with a domain
you own, publish either value and call `verify` again. Starting a sign-in by provider works without a
domain:

```sh
curl -s -X POST $B/sso/sign-in -H "$J" -d "{\"provider_id\":\"$PROV\"}"
# {"data":{"url":"https://acme.okta.com/oauth2/v1/authorize?response_type=code&client_id=0oa1b2c3d4&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsso%2Fcallback%2F…&scope=openid+email+profile&state=…&nonce=…&code_challenge=…&code_challenge_method=S256","provider_id":"01a2022d-3de0-…","type":"oidc"}}
```

This call fetches the issuer's discovery document, so it needs the network and an issuer that serves
one (`https://acme.okta.com` did in this run; offline, the sign-in cannot start). The browser goes to
`url`; the IdP sends it back to `/sso/callback/{providerId}`, which redirects to
`http://localhost:8080/sso/done?sso_code=…`; the application trades the code for the session with
`POST /sso/exchange {"code": "…"}`. A SAML provider is the same call with `"type": "saml"` and
`"config": {"sso_url": "…", "certificate": "MIIC…"}`; its SP metadata is at `sp.metadata_url`.

### 7. Provisioning: a SCIM connection

The organization admin creates a connection and pastes `scim_base_url` and `token` into the
directory (Okta, Entra ID, Google, JumpCloud…). The token is shown once.

```sh
curl -s -X POST $B/orgs/$ORG/scim/connections -H "$H" -H "$J" -d '{"name":"Okta directory"}'
# {"data":{"deprovision":"deactivate","id":"01a2022d-4398-…","name":"Okta directory","scim_base_url":"http://localhost:8080/scim/v2/01a2022d-4398-…","status":"active","token":"pst_SefHJT_…",…}}
CID=<id>; S="Authorization: Bearer <token>"; SJ='Content-Type: application/scim+json'
```

What the directory then sends: a user (a Polaris account and a membership), and a group membership
(a Polaris role):

```sh
curl -s -X POST $B/scim/v2/$CID/Users -H "$S" -H "$SJ" -d '{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "carol@acme.test", "externalId": "00u1carol",
  "name": {"givenName": "Carol", "familyName": "Diaz"},
  "emails": [{"value": "carol@acme.test", "primary": true}], "active": true}'
# {"active":true,"displayName":"Carol Diaz","externalId":"00u1carol","groups":[{"display":"Member",…}],"id":"01a2022d-43db-…","userName":"carol@acme.test",…}

curl -s $B/scim/v2/$CID/Groups -H "$S" | jq -c '[.Resources[] | .displayName]'
# ["Owner","Administrator","Member","Editor","Viewer"]
curl -s -X PATCH $B/scim/v2/$CID/Groups/<Editor's id> -H "$S" -H "$SJ" -d '{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "add", "path": "members", "value": [{"value": "<Carol'"'"'s id>"}]}]}'
# {"displayName":"Editor","members":[{"display":"carol@acme.test",…}],…}

curl -s $B/orgs/$ORG/members -H "$H" | jq -c '.data[] | {email, roles}'
# {"email":"ada@acme.test","roles":["owner"]}
# {"email":"bob@acme.test","roles":["viewer"]}
# {"email":"carol@acme.test","roles":["member","editor"]}
```

Carol signs in through the organization's IdP (SSO) and can write projects. Deprovisioning
(`DELETE /scim/v2/$CID/Users/<id>`, or `"active": false`) bans her account and ends her sessions.

## Test

`main_test.go` boots `newServer` with `httptest` and drives the same flow: `go test ./examples/b2b`.
