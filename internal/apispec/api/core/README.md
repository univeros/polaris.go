# `api/core`: endpoint specs

One YAML spec per core route. The specs are the router (package `manifest` loads them) and the
source of the exported manifest and OpenAPI document (`polaris manifest`). Change a spec together
with its endpoint in `internal/httpapi`; the recorded contract fixtures in
`internal/apispec/fixtures` keep both honest.

## Layout

| Directory          | Endpoints                                                        |
| ------------------ | ---------------------------------------------------------------- |
| `auth/`            | register, login, email verification, tokens, sessions, switch-org, me, jwks, invite acceptance |
| `auth/password/`   | forgot / reset / change                                          |
| `auth/mfa/`        | TOTP/SMS/email enrollment + confirmation, the login gate, step-up, recovery codes, factor management |
| `orgs/`            | organization lifecycle, members, invitations, roles              |
| `permissions/`     | the permission catalog                                           |
| `users/`           | user admin (read, update, disable, enable, delete)               |

## Spec schema

`schema.json` lists the required keys and accepted values; `manifest.Load` enforces them.

```yaml
# <METHOD> <path>: one-line summary.
endpoint:
  method: POST
  path: /auth/login
  summary: Password login
  tags: [auth]
  auth: public            # public | bearer | mfa_token; step-up-gated routes add `step_up: true`
  requires_permissions: [] # permissions the caller must hold, where declared
  rate_limit: login        # per-IP budget group; omitted when only the global per-user budget applies
  effect: write            # read | write | destructive
  receipt: true            # defaults to true for write/destructive, false for read
  session: issue           # issue | refresh | end: what the route does to the caller's session; in cookie
                           # token delivery the refresh cookie follows it. Omitted otherwise.

input:
  source: body             # body | path | query | none
  fields:                  # field: {type, rules} as the endpoint validates them
    email: { type: string, rules: [required, email, "max:320"] }

domain:
  class: Polaris\Http\Auth\LoginEndpoint         # endpoint identifier published in the exported manifest and as the
                                                 # OpenAPI operationId; existing values stay as released
  description: >
    What the endpoint does, as implemented.

output:
  status: 200
  example: { data: { ... } }   # the implemented envelope; types the response in OpenAPI
  # example_<variant>: { ... }  # a second shape the same endpoint answers (login's example_mfa_required)

errors:                        # every non-2xx the endpoint returns
  - { status: 401, code: invalid_credentials }

events: [user.logged_in]       # events dispatched (package event)
```

## Response typing

`polaris manifest --format=openapi` types each success response from the spec's `example` (JSON Schema
by example, `manifest`'s schema inference): every key shown is required, scalars take their JSON type,
array items are merged (a key missing from some items is optional, one null in some is nullable), a
value null everywhere is a nullable string, an empty array has untyped items, and `example_<variant>`
keys become a `oneOf`. Clients generated from the OpenAPI document are typed from that, so keep the
examples the shape the endpoint really answers.
