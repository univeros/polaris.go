# examples/signin-methods

One Polaris server with every way to sign in besides a password, and the plugins around them:

| Plugin | What it adds here |
| --- | --- |
| `passwordless` | magic links and 6-digit email codes; a link ends on the host's `/signed-in` page |
| `username` | case-insensitive usernames; sign in with the username or the email |
| `anonymous` | guest sessions, converted to the account the guest signs up as (`OnConvert` moves your data) |
| `multisession` | several accounts on one device (cookie `polaris_ms_device` or header `X-Polaris-Device`) |
| `social` | a generic OpenID Connect provider from `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`; off without them |
| `passkey` | WebAuthn on `localhost`; a passkey is also an MFA factor |
| `messaging` | core's mailer: SMTP from `SMTP_ADDR`, `SMTP_FROM`, `SMTP_USER`, `SMTP_PASSWORD`, else the log |
| `sentinel` | risk scoring of sign-ups, sign-ins, resets and code sends, observe mode (records, never blocks) |
| `audit`, `admin` | sentinel needs them: its decisions are read at `/admin/sentinel/decisions` |

Core's MFA gate applies to all of them: an account with a confirmed factor gets `mfa_required`
from a password, a magic link, an email code or a social sign-in alike.

## Run it

```sh
go run ./examples/signin-methods 2>&1 | tee polaris.log
```

No setup: SQLite in a temporary directory, keys generated at start (set `APP_KEY`,
`AUTH_JWT_PRIVATE_KEY`, `AUTH_JWT_PUBLIC_KEY`, `AUTH_ISSUER` to keep them; `ADDR` changes the
address, default `localhost:8080`). Without SMTP every mail, links and codes included, is written to
the log, which is why the walkthrough greps `polaris.log`. At start the log also shows a read-only
operator key (`pak_…`) for sentinel's decisions; a real deployment mints one with
`polaris admin:key` and never logs it.

The walkthrough below needs `curl` and `jq`. In a second terminal:

```sh
BASE=http://localhost:8080 LOG=polaris.log
json='Content-Type: application/json'
pw='correct horse battery staple'
JAR=$(mktemp)  # the device cookie, for multisession
code() { grep -o 'code is [0-9][0-9]*' "$LOG" | tail -1 | grep -o '[0-9]*$'; }  # the last emailed code
```

The output below is real, trimmed (tokens cut). The routes are rate limited per IP (five code or
link sends, ten code redemptions per window; `config.Auth.RateLimits`): a `429` with `Retry-After`
means wait, or restart the server.

### 1. Magic link

Send it; the link is in the log. Opening it redirects to `/signed-in?code=…` (the host's page; a
real front end trades the code itself); the code is exchanged for core's login envelope. The link
works once.

```sh
curl -s -X POST $BASE/magic-link/send -H "$json" -d '{"email":"ada@example.com"}'
# {"data":{"status":"sent"}}
LINK=$(grep -o "$BASE/magic-link/verify?token=[A-Za-z0-9_-]*" "$LOG" | tail -1)
CODE=$(curl -s -L "$LINK" | jq -r .code)        # {"code":"R1Xty4mPO3cI…","state":""}
curl -s -X POST $BASE/magic-link/exchange -H "$json" -d "{\"code\":\"$CODE\"}" | jq -c '.data | {user, token_type, expires_in}'
# {"user":{"email":"ada@example.com","email_verified":true,"id":"01a20237-9da3-…"},"token_type":"Bearer","expires_in":900}
curl -s "$LINK"
# {"detail":"The token is unknown, used or expired.","error":"passwordless_token_invalid",…,"status":422,…}
```

An unknown address is signed up (`DisableSignUp` turns that off); the send answers the same 202
for known and unknown addresses.

### 2. Email code

```sh
curl -s -X POST $BASE/email-otp/send -H "$json" -d '{"email":"bob@example.com"}'
# {"data":{"status":"sent"}}
curl -s -c $JAR -X POST $BASE/email-otp/verify -H "$json" -d "{\"email\":\"bob@example.com\",\"code\":\"$(code)\"}" | jq -c '.data | {user, token_type}'
# {"user":{"email":"bob@example.com","email_verified":true,"id":"01a20237-a60a-…"},"token_type":"Bearer"}
```

`-c $JAR` keeps the device cookie multisession set; step 5 uses it.

### 3. Guest, then sign-up

A guest has a session before having an account. It signs up (here with a password: register,
verify the address with the token from the log, sign in), then converts: `OnConvert` runs (the log
shows `guest … is now user …`), the guest's sessions end and the guest is disabled.

```sh
GUEST=$(curl -s -X POST $BASE/anonymous/sign-in | jq -r .data.access_token)
curl -s $BASE/auth/me -H "Authorization: Bearer $GUEST" | jq -c '.data | {id, email, status}'
# {"id":"01a20237-a62c-…","email":"01a20237-a62c-…@anonymous.invalid","status":"active"}

curl -s -X POST $BASE/auth/register -H "$json" -d "{\"email\":\"carol@example.com\",\"password\":\"$pw\"}"
# {"message":"If the address can be registered, a verification message has been sent."}
TOKEN=$(grep -o 'verify your email address: [A-Za-z0-9_-][A-Za-z0-9_-]*' "$LOG" | tail -1 | awk '{print $NF}')
curl -s -X POST $BASE/auth/email/verify -H "$json" -d "{\"token\":\"$TOKEN\"}"
# {"message":"Email verified."}
CAROL=$(curl -s -X POST $BASE/auth/login -H "$json" -d "{\"email\":\"carol@example.com\",\"password\":\"$pw\"}" | jq -r .data.access_token)

curl -s -X POST $BASE/anonymous/convert -H "Authorization: Bearer $GUEST" -H "$json" -d "{\"access_token\":\"$CAROL\"}"
# {"data":{"guest_id":"01a20237-a62c-…","status":"converted","user_id":"01a20237-a8bc-…"}}
```

Any sign-in method works for the account side: pass its access token as `access_token`.

### 4. Username

```sh
curl -s -X PATCH $BASE/username -H "Authorization: Bearer $CAROL" -H "$json" -d '{"username":"Carol_C"}'
# {"data":{"display_username":"Carol_C","username":"carol_c"}}
CAROL=$(curl -s -b $JAR -c $JAR -X POST $BASE/username/sign-in -H "$json" -d "{\"username\":\"carol_c\",\"password\":\"$pw\"}" | jq -r .data.access_token)
```

The sign-in is core's password path (lockout, email verification, MFA gate); the email works in
place of the username.

### 5. Two accounts on one device

Bob (step 2) and Carol (step 4) signed in with the same cookie jar: one device. List its accounts,
switch to Bob without his code, read the device's last method (a sign-in page pre-selects it).

```sh
curl -s -b $JAR $BASE/multi-session/list -H "Authorization: Bearer $CAROL" | jq -c '.data[] | {session_id, email: .user.email, last_method, current}'
# {"session_id":"01a20237-b322-…","email":"carol@example.com","last_method":"pwd","current":true}
# {"session_id":"01a20237-a60d-…","email":"bob@example.com","last_method":"email_otp","current":false}
SID=$(curl -s -b $JAR $BASE/multi-session/list -H "Authorization: Bearer $CAROL" | jq -r '.data[] | select(.current == false) | .session_id')
curl -s -b $JAR -c $JAR -X POST $BASE/multi-session/switch -H "Authorization: Bearer $CAROL" -H "$json" -d "{\"session_id\":\"$SID\"}" | jq -c '.data | {user}'
# {"user":{"email":"bob@example.com","email_verified":true,"id":"01a20237-a60a-…"}}
curl -s -b $JAR $BASE/multi-session/last-method
# {"data":{"last_method":"pwd"}}
```

Each new sign-in on a device rotates its id (no device fixation): a client without cookies sends
back the newest `X-Polaris-Device` it received.

### 6. MFA enrolment (email codes)

Email codes need nothing but the log. TOTP is the same two calls (`/auth/mfa/totp/enroll` answers a
`secret` and an `otpauth_uri`; `/auth/mfa/totp/confirm` takes a code from an authenticator app or
`oathtool --totp -b <secret>`).

```sh
FACTOR=$(curl -s -X POST $BASE/auth/mfa/email/enroll -H "Authorization: Bearer $CAROL" -H "$json" -d '{}' | jq -r .data.factor_id)
# {"data":{"destination":"c***@example.com","factor_id":"01a20237-b385-…"}}
curl -s -X POST $BASE/auth/mfa/email/confirm -H "Authorization: Bearer $CAROL" -H "$json" -d "{\"factor_id\":\"$FACTOR\",\"code\":\"$(code)\"}" | jq -c '.data | {status, recovery_codes: (.recovery_codes | length)}'
# {"status":"confirmed","recovery_codes":10}
```

Now a password sign-in stops at the gate with a short-lived `mfa_token`; ask for a code and verify it:

```sh
MFA=$(curl -s -X POST $BASE/auth/login -H "$json" -d "{\"email\":\"carol@example.com\",\"password\":\"$pw\"}" | jq -r .data.mfa_token)
# {"data":{"mfa_required":true,"mfa_token":"eyJ…","factors":[{"id":"01a20237-b385-…","type":"email","default":true,"destination":"c***@example.com"}]}}
curl -s -X POST $BASE/auth/mfa/challenge -H "Authorization: Bearer $MFA" -H "$json" -d "{\"factor_id\":\"$FACTOR\"}"
# {"data":{"channel":"email","destination":"c***@example.com"}}
curl -s -X POST $BASE/auth/mfa/verify -H "Authorization: Bearer $MFA" -H "$json" -d "{\"factor_id\":\"$FACTOR\",\"code\":\"$(code)\"}" | jq -c '.data | {token_type, expires_in}'
# {"token_type":"Bearer","expires_in":900}
```

A magic link for Carol now ends at the same gate:

```sh
curl -s -X POST $BASE/magic-link/send -H "$json" -d '{"email":"carol@example.com"}'
LINK=$(grep -o "$BASE/magic-link/verify?token=[A-Za-z0-9_-]*" "$LOG" | tail -1)
CODE=$(curl -s -L "$LINK" | jq -r .code)
curl -s -X POST $BASE/magic-link/exchange -H "$json" -d "{\"code\":\"$CODE\"}" | jq -c '.data | {mfa_required, factors: [.factors[].type]}'
# {"mfa_required":true,"factors":["email"]}
```

### 7. Sentinel

Sentinel records a decision whenever a signal speaks. A sign-up from a disposable domain scores 60,
the challenge band; in observe mode it is recorded and let through (`Mode: sentinel.Enforce`
answers it).

```sh
curl -s -X POST $BASE/auth/register -H "$json" -d "{\"email\":\"eve@mailinator.com\",\"password\":\"$pw\"}"
KEY=$(grep -o 'pak_[A-Za-z0-9_-]*' "$LOG" | head -1)
curl -s "$BASE/admin/sentinel/decisions?limit=1" -H "Authorization: Bearer $KEY" | jq -c '.data[] | {kind, email, action, enforced, score, reasons}'
# {"kind":"sign_up","email":"eve@mailinator.com","action":"challenge","enforced":false,"score":60,"reasons":["disposable domain mailinator.com"]}
```

### 8. Passkeys and social sign-in

Both need a browser. A page on `http://localhost:8080` calls `POST /passkey/authenticate/options`
on load and hands the answer to `navigator.credentials.get()`; a signed-in user registers one with
`/passkey/register/options` and `/passkey/register/verify`.

```sh
curl -s -X POST $BASE/passkey/authenticate/options -H "$json" -d '{}'
# {"data":{"allowCredentials":[],"challenge":"O7LMQZd61S0Y…","rpId":"localhost","timeout":60000,"userVerification":"preferred"}}
```

With `OIDC_ISSUER`, `OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET` set (and
`http://localhost:8080/social/oidc/callback` registered at the provider),
`POST /social/oidc/start` answers the provider's authorization `url` (discovered from the issuer,
with PKCE) and a `state`; after the provider, the browser lands on `/signed-in?code=…&state=…` and
`POST /social/exchange` trades the code as in step 1. With `OIDC_ISSUER=https://accounts.google.com`:

```sh
curl -s -X POST $BASE/social/oidc/start -H "$json" -d '{}'
# {"data":{"url":"https://accounts.google.com/o/oauth2/v2/auth?client_id=…&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fsocial%2Foidc%2Fcallback&response_type=code&scope=openid%20email%20profile&state=0c005fbf…&code_challenge=…",…}}
```

## Test

`main_test.go` boots `newServer` with a memory mail channel (`messaging.NewMemory`) and runs steps
1 to 4 and 6: `go test ./examples/signin-methods`.
