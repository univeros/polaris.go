# examples/mcp

An MCP server of your own, protected by Polaris-issued tokens, and Polaris's own MCP endpoint
next to it, in one program ([`main.go`](main.go)).

| Endpoint | What it is | Who gets in |
|---|---|---|
| `POST /tools/mcp` | your MCP server, built with the official Go MCP SDK (one tool, `deploy`), wrapped in `mcp.Protect` | a token whose `aud` is `http://localhost:8080/tools/mcp` and whose scope holds `deploy.run` |
| `POST /mcp` | Polaris as an MCP server (`plugins/mcp`): every Polaris route the caller may call is a tool | a token whose `aud` is `http://localhost:8080/mcp` |
| `GET /.well-known/oauth-protected-resource/tools/mcp` | the RFC 9728 metadata a 401 points clients at | anyone |

Tokens come from Polaris's OAuth provider (`plugins/oauth`). An OAuth client exchanges the user's
session for a token bound to one resource (RFC 8693 token exchange with `resource`), with only the
scopes it asks for. A scope is a permission, and `deploy.run` is the host's own permission
(`cfg.Permissions`). `oauth.Config.Audiences` lists both resources, so Polaris may mint tokens for them.
In the tool, `mcp.Claims(ctx)` is the verified token: `sub`, `scope`, `client_id`, `act`.

The MCP server here is in the same process as Polaris, so `mcp.Protect` verifies with
`Graph: p.Graph()`. For an MCP server in another service, pass
`JWKSURL: "https://auth.example.com/auth/.well-known/jwks.json"` and `Issuer` instead. Nothing else
changes.

## Run it

```sh
POLARIS_DEV=1 go run ./examples/mcp
```

The example needs no setup:

- The database is SQLite in a temporary directory.
- With `POLARIS_DEV=1`, `polaris.DevEnv` generates `APP_KEY` and the JWT key pair at start when
  the environment lacks them (without it the example refuses to start). Set
  `APP_KEY`, `AUTH_JWT_PRIVATE_KEY`, `AUTH_JWT_PUBLIC_KEY` and `AUTH_ISSUER` (see
  [`examples/minimal`](../minimal/main.go)) to keep tokens across restarts.
- `ADDR` changes the listen address. The default is `localhost:8080`.

It creates one user, `ada@example.com` (password `correct horse battery staple`), the owner of the
organization "Acme". It also gives Acme's owner role the `deploy.run` permission (see "Friction"
below).

## Walk through it

The commands use `jq`. The output below is real, with ids shortened.

```sh
B=http://localhost:8080
J='Content-Type: application/json'
```

### 1. Ada signs in and picks her organization

```sh
SESSION=$(curl -s $B/auth/login -H "$J" \
  -d '{"email":"ada@example.com","password":"correct horse battery staple"}' | jq -r .data.access_token)
ORG=$(curl -s $B/orgs -H "Authorization: Bearer $SESSION" | jq -r '.data[0].id')
SESSION=$(curl -s $B/auth/switch-org -H "Authorization: Bearer $SESSION" -H "$J" \
  -d "{\"organization_id\":\"$ORG\"}" | jq -r .data.access_token)
```

`/auth/switch-org` answers `{"token_type":"Bearer","expires_in":900,"org":"01a2023d-…"}`. The
session token now carries Acme's roles and permissions.

### 2. Register an OAuth client that may exchange a session

```sh
CLIENT=$(curl -s $B/orgs/$ORG/oauth/clients -H "Authorization: Bearer $SESSION" -H "$J" \
  -d '{"name":"Deploy CLI","type":"confidential",
       "grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"],
       "token_endpoint_auth_method":"client_secret_post"}')
CID=$(echo "$CLIENT" | jq -r .data.client_id); CSEC=$(echo "$CLIENT" | jq -r .data.client_secret)
```

```json
{"client_id":"01a2023e-b7b3-…","client_secret":"pcs_bQXVCVQw…","grant_types":["urn:ietf:params:oauth:grant-type:token-exchange"],"organization_id":"01a2023d-…"}
```

The secret is shown once.

### 3. The MCP server refuses what is not a token for it

```sh
curl -si -X POST $B/tools/mcp | grep -i '^HTTP\|^www-auth'
```

```
HTTP/1.1 401 Unauthorized
Www-Authenticate: Bearer resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource/tools/mcp"
```

An MCP client follows `resource_metadata` to learn where to get a token, and with which scopes:

```sh
curl -s $B/.well-known/oauth-protected-resource/tools/mcp | jq -c .
```

```json
{"authorization_servers":["http://localhost:8080"],"bearer_methods_supported":["header"],"dpop_signing_alg_values_supported":["RS256","…","EdDSA"],"resource":"http://localhost:8080/tools/mcp","resource_name":"Deploy tools","scopes_supported":["deploy.run"]}
```

Ada's session token is valid, but it was not issued for this resource:

```sh
curl -si -X POST $B/tools/mcp -H "Authorization: Bearer $SESSION" | grep -i '^HTTP\|^www-auth'
```

```
HTTP/1.1 401 Unauthorized
Www-Authenticate: Bearer error="invalid_token", error_description="The token is meant for another resource.", resource_metadata="…"
```

### 4. Exchange the session for a token bound to the MCP server

```sh
exchange() { # resource scope
  curl -s $B/oauth2/token -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
    -d client_id=$CID -d client_secret=$CSEC \
    -d subject_token=$SESSION -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
    -d resource=$1 --data-urlencode "scope=$2"
}
TOKEN=$(exchange $B/tools/mcp deploy.run | jq -r .access_token)
```

```json
{"token_type":"Bearer","expires_in":3600,"scope":"deploy.run","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}
```

### 5. Call the tool

These are MCP 2026-07-28 stateless messages. Each request is complete in itself: the protocol
version goes in a header and in `_meta`, and there is no session.

```sh
curl -s $B/tools/mcp -H "Authorization: Bearer $TOKEN" -H "$J" -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: deploy' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"deploy","arguments":{"service":"billing"},
       "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}'
```

```json
{"jsonrpc":"2.0","id":1,"result":{"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"deploy-tools","version":"1.0.0"}},"content":[{"type":"text","text":"billing deployed by user 01a2023d-a4a9-… through client 01a2023e-b7b3-…"}],"resultType":"complete"}}
```

A token for the right resource but without the scope gets a 403. The `WWW-Authenticate` header
names the missing scope, so the client can ask for it:

```sh
NARROW=$(exchange $B/tools/mcp org.read | jq -r .access_token)
# the same curl with $NARROW:
```

```
HTTP/1.1 403 Forbidden
Www-Authenticate: Bearer error="insufficient_scope", scope="deploy.run", resource_metadata="…"
```

### 6. Polaris's own MCP server

The same client, with a token for the `/mcp` resource:

```sh
PM=$(exchange $B/mcp "org.read members.read" | jq -r .access_token)
curl -s $B/mcp -H "Authorization: Bearer $PM" -H "$J" -H 'Accept: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/list' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{
       "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}' \
  | jq -c '[.result.tools[].name]'
```

```json
["polaris.auth.email.verify.resend","polaris.auth.email.verify","polaris.auth.jwks","polaris.auth.login","polaris.auth.me","polaris.auth.mfa.factors.list", "…","polaris.orgs.list","polaris.orgs.members.list","polaris.orgs.read","polaris.permissions.list","polaris.users.read","polaris.oauth.authorization.server", "…"]
```

The list holds the public routes and the routes this token's scopes allow. A tool call runs the
route in process, with the same permissions, events and rate limits:

```sh
curl -s $B/mcp -H "Authorization: Bearer $PM" -H "$J" -H 'Accept: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: polaris.orgs.members.list' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"polaris.orgs.members.list\",
       \"arguments\":{\"id\":\"$ORG\"},
       \"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\",\"io.modelcontextprotocol/clientCapabilities\":{}}}}" \
  | jq -c .result.structuredContent
```

```json
{"body":{"data":[{"display_name":null,"email":"ada@example.com","roles":["owner"],"status":"active","user_id":"01a2023d-a4a9-…"}]},"status":200}
```

To serve Polaris's MCP to a local coding agent over stdio instead, use
`mcp.ServeStdio(ctx, p, mcp.StdioOptions{Credential: os.Getenv(mcp.StdioEnv)})` or
`polaris mcp --token=…`.

## The host's permission

`deploy.run` is the host's own permission (`cfg.Permissions`), and
`cfg.RolePermissions = map[string][]string{"owner": {"deploy.run"}}` puts it in every
organization's owner role. Without it in her authority, Ada could not delegate that scope to the
client, nor put it into a custom role: Polaris refuses to grant permissions the caller does not hold.

## Test

[`main_test.go`](main_test.go) boots the same server on a real listener and runs this walkthrough:

```sh
go test ./examples/mcp
```
