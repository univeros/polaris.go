# examples/hooks

Your app's own data next to Polaris, in the same database and the same transactions:

- `Hooks.OnUserCreated` / `OnUserDeleted` insert and delete a row in the app's `profiles` table
  **inside the transaction that creates or erases the account**, whatever the path (`/auth/register`,
  `p.Users().Create`, admin, SCIM, …), with plain `database/sql` through `db.Conn(ctx)`. If the
  hook fails, the account is not created.
- `Hooks.Claims` puts the profile's plan into every access token as `app_plan`.
- `Listeners` log every domain event. `Middleware` gives every request an `X-Request-Id`, and the
  event log lines carry it; `p.Wrap` puts the same middleware around the host's public signup route.
- `POST /api/signup` is the host's own onboarding. It creates the account, its organization and the
  profile's plan in **one host transaction** (`db.Tx`). A plan the `profiles` table refuses (a
  `CHECK` constraint) rolls everything back, and the events and the verification mail of a
  rolled-back signup never go out: they wait for the commit.
- `GET /api/profile` is a host route behind `p.Protect`. It reads the profile row and the claim.
- `p.Prune` runs at start and every hour.

## Run it

```sh
POLARIS_DEV=1 go run ./examples/hooks
```

No setup beyond `POLARIS_DEV=1`: SQLite in a temporary directory, and throwaway keys from
`polaris.DevEnv` when `APP_KEY`, `AUTH_JWT_*` and `AUTH_ISSUER` are not set (without
`POLARIS_DEV=1` it refuses to start). `ADDR` (default `localhost:8080`) is where it listens. Mail
goes to the log. At start it prunes once:

```
2026/11/22 08:28:41 listening on http://localhost:8080
2026/11/22 08:28:41 pruned map[auth_email_verifications:0 auth_otp_challenges:0 auth_password_resets:0 auth_refresh_tokens:0]
```

## Walk through it

### 1. Sign up through the host: one transaction

```sh
curl -s -X POST localhost:8080/api/signup -H 'Content-Type: application/json' -H 'X-Request-Id: demo-signup' \
  -d '{"email":"ada@example.com","password":"correct horse battery staple","company":"Acme","plan":"pro"}'
```

```json
{"can_delete_org":true,"organization_id":"01a20228-875f-…","user_id":"01a20228-8624-…"}
```

The account, Ada's profile (plan `pro`) and the Acme organization were committed together.
`can_delete_org` is `p.Can`: the owner of the new organization holds `org.delete`. The log shows the
events with the request id the client sent:

```
event user.registered request_id=demo-signup
event org.created request_id=demo-signup
```

### 2. The rollback

`enterprise` is not a plan the `profiles` table accepts. The host's `UPDATE` fails after Polaris has
created the account and the organization, so the host rolls back:

```sh
curl -s -X POST localhost:8080/api/signup -H 'Content-Type: application/json' -H 'X-Request-Id: demo-rollback' \
  -d '{"email":"carol@example.com","password":"correct horse battery staple","company":"Carolco","plan":"enterprise"}'
```

```json
{"error":"plan is free or pro; nothing was created"}
```

```
signup rolled back: constraint failed: CHECK constraint failed: plan IN ('free', 'pro') (275)
```

No event line and no verification mail: inside `db.Tx` the events wait for the commit, and a
rollback drops them. Nothing is left behind: the same signup with a valid plan succeeds.

```sh
curl -s -X POST localhost:8080/api/signup -H 'Content-Type: application/json' \
  -d '{"email":"carol@example.com","password":"correct horse battery staple","company":"Carolco","plan":"free"}'
```

```json
{"can_delete_org":true,"organization_id":"01a20228-899f-…","user_id":"01a20228-88bd-…"}
```

A host that runs its own `*sql.Tx` (an ORM's, sqlc's) passes it with `sqlstore.WithTx(ctx, tx)`
instead. Polaris cannot see that commit, so there the events and the mail go out when Polaris's
part is done, before the host commits; prefer `db.Tx` when a rolled-back signup must send nothing.

### 3. Register through Polaris: the hook still runs

```sh
curl -s -X POST localhost:8080/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"bob@example.com","password":"correct horse battery staple"}'
# {"message":"If the address can be registered, a verification message has been sent."}
```

The verification token is in the log (`Polaris dev email (not delivered) to=bob@example.com
template=verify_email context=map[token:…]`):

```sh
curl -s -X POST localhost:8080/auth/email/verify -H 'Content-Type: application/json' -d '{"token":"<token>"}'
# {"message":"Email verified."}
TOKEN=$(curl -s -X POST localhost:8080/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"bob@example.com","password":"correct horse battery staple"}' | jq -r .data.access_token)
```

### 4. The profile and the claim

```sh
curl -s localhost:8080/api/profile -H "Authorization: Bearer $TOKEN"
```

```json
{"organization_id":null,"plan":"free","token_app_plan":"free","user_id":"01a20228-5a80-…"}
```

`plan` is the row `OnUserCreated` inserted. `token_app_plan` is the claim `Hooks.Claims` minted into
the access token (decode it: `…"auth_time":1795332488,"app_plan":"free"}`).

### 5. Erase the account: the profile goes with it

```sh
curl -s -X DELETE localhost:8080/users/<user_id> -H "Authorization: Bearer $TOKEN"
# {"data":{"deleted":true}}
curl -s localhost:8080/api/profile -H "Authorization: Bearer $TOKEN"
# {"error":"no profile"}
```

`OnUserDeleted` deleted the row in the erasing transaction. The access token itself stays valid until
it expires (15 minutes); set `AUTH_ACCESS_TOKEN_DENYLIST=1` to refuse it at once.

## The code

- Hooks read and write with plain `database/sql` through `db.Conn(ctx)`, with the `ctx` Polaris
  passes in: it is the account's transaction, so the statement joins it. Placeholders are the
  driver's: `?` on SQLite and MySQL, `$1` on PostgreSQL.
- In the host's own transaction, `db.Tx(ctx, fn)`, every Polaris call made with fn's `ctx` joins it,
  and so do the host's statements through `db.Conn(ctx)`.

`main_test.go` boots the same server with `httptest` and checks every step above.
