# plugins/ui

Server-rendered pages for browsers: sign in, two-step verification, sign up, "check your email"
and email verification, forgot and reset password, sign out and, with `plugins/oauth`, the OAuth
consent and device pages. Plain HTML forms (`html/template`, one embedded stylesheet, about 10 KB in
all), no JavaScript, accessible (labels, `autocomplete`, an error summary with `role="alert"`),
responsive, light and dark. Every form runs the matching JSON route in process, through the same
pipeline as `p.Handler()`: rate limits, `plugins/sentinel`, core's MFA gate, events and audit apply
exactly as on the route, and the answers that hide whether an email is registered stay hidden.
Plugin id `ui`; no tables, no routes in the manifest.

## Install

```go
import "github.com/univeros/polaris.go/plugins/ui"

web := ui.New(ui.Config{AppName: "Acme", AfterSignIn: "/dashboard"})
cfg, err := polaris.FromEnv(db, web)
cfg.Mailer = mailer // builds the email links with web.VerifyEmailURL(token) / web.ResetPasswordURL(token)
p, err := polaris.New(cfg)

mux.Handle("/", p.Handler())                                          // the pages under /auth/ui
mux.Handle("GET /dashboard", web.RequireSignIn(p.Protect(dashboard))) // signed-out browsers go to sign-in and back
```

A complete program is [`examples/webapp`](../../examples/webapp/main.go).

## Config

Every field is optional.

| Field | Default | Purpose |
| --- | --- | --- |
| `AppName` | `Account` | shown in the header and the titles |
| `LogoURL` | none | a path or an `https` URL (its origin joins `img-src`) |
| `PrimaryColor`, `PrimaryColorDark` | built-in shades | `#rrggbb` for buttons, links, focus rings; dark mode uses the second |
| `TermsURL`, `PrivacyURL` | none | footer links |
| `AfterSignIn` | `/` | where a sign-in without `return_to` ends |
| `AfterSignOut` | the sign-in page | where a sign-out ends |
| `RedirectOrigins` | none | origins besides `BaseURL`'s a `return_to` may point at (`https://other.example.com`) |
| `BaseURL` | issuer + `polaris.Config.PathPrefix` | the public URL browsers use; its origin is the pages' only origin (below); the email links and OAuth pages derive from it |
| `Templates` | built-in | an `fs.FS` overriding files by name (below) |
| `Messages` | English | texts per locale (`"pt": {"sign_in_title": "Entrar"}`), keys of `ui.English`; picked by `Accept-Language` |

A `BaseURL` (or issuer) that is not an absolute http(s) URL, a bad colour, a redirect target off the
allow-list, a logo or link that is not http(s), or a template that does not parse fails `polaris.New`
naming the field.

## One origin, behind a proxy too

The pages have exactly one origin: `BaseURL`'s (scheme, host, port). They never read the Host header
or `r.TLS`, and they do not trust `X-Forwarded-*`:

- A form post is accepted only when the browser's `Origin` header is that origin (or, without
  `Origin`, `Sec-Fetch-Site: same-origin`); the session cookie authenticates a non-GET request on the
  same terms. Behind a TLS-terminating proxy (nginx, Caddy, a cloud load balancer), where `r.TLS` is
  nil and the Host may be an internal address, nothing needs configuring: set `BaseURL` (or
  `AUTH_ISSUER`) to the https URL browsers use.
- Sessions are issued when that origin is https, or http on `localhost` / a loopback address in
  development. Any other http origin refuses every form (and logs a warning at startup).
- Served under another name (`www.` beside the bare domain, an internal URL opened in a browser), the
  pages render but refuse every post with "This form only works at <origin>" and a link there: the
  `__Host-` cookies belong to one host, so the pages are served on the configured origin only.
  Redirect the other names to it at the proxy.

## Pages

Under `polaris.Config.PathPrefix` + `/auth/ui` (`ui.Prefix`):

| Path | GET | POST (CSRF-checked) |
| --- | --- | --- |
| `/sign-in` | the form (`?return_to=`) | `POST /auth/login`; a session, or the MFA step |
| `/mfa` | the factors of the sign-in under way | `POST /auth/mfa/challenge` (send a code), `/auth/mfa/verify` (a code or a recovery code) |
| `/sign-up` | the form | `POST /auth/register`, then `/check-email` whatever the outcome |
| `/check-email` | paste the code, or ask again | `POST /auth/email/verify/resend` |
| `/verify` | `?token=` verifies at once; else the form | `POST /auth/email/verify` |
| `/forgot` | the form | `POST /auth/password/forgot`; the same answer for every address |
| `/reset` | `?token=` from the email, or paste the code | `POST /auth/password/reset`; every session ends |
| `/sign-out` | a confirmation | `POST /auth/logout`, the cookies cleared |
| `/refresh` | renews the session from its cookie, back to `?return_to=`; else to sign-in | |
| `/consent` | the OAuth request (`?request=`), or the code at once when already granted | `POST /oauth2/authorize/decision` |
| `/device` | the code entry, then the device's request (`?user_code=`) | `POST /oauth2/device/approve` |
| `/style.css` | the stylesheet, with the configured colours | |

With `plugins/oauth` installed and its `ConsentURL` / `DeviceURL` empty, the provider sends browsers
to `/consent` and `/device` (`oauth.PageProvider`); `DeviceURL` filled this way turns the device flow on.

## Theming

`Config.Templates` replaces any of `layout.html`, `sign-in.html`, `mfa.html`, `sign-up.html`,
`check-email.html`, `verify.html`, `forgot.html`, `reset.html`, `sign-out.html`, `consent.html`
(also the device decision), `device.html`, `message.html` and `style.css`; the rest stay built in. A page
defines `{{define "content"}}`, the layout renders it with the data `.T` (the messages), `.App`,
`.Base`, `.CSRF`, `.Errors`, `.Notice`, `.ReturnTo` and the page's fields (start from the built-in files
in `plugins/ui/templates`). Every form must keep its `csrf` field. A host template that
renders a captcha posts its token as `captcha_token`, which reaches sentinel.

## Sessions and cookies

A sign-in opens core's session (the same refresh-token family, rotation and reuse detection as
`/auth/login`) and keeps it in HttpOnly, Secure cookies:

- `__Host-polaris_session`: the access token, `SameSite=Lax`, for its lifetime. `p.Protect` and every
  bearer route accept it from a browser (the plugin's bearer resolver); an `Authorization` header or
  `X-Api-Key` wins. A request other than GET, HEAD or OPTIONS uses it only with an `Origin` (or
  `Sec-Fetch-Site`) of the pages' origin, so a cross-site form cannot ride it, on the host's routes too.
- `__Secure-polaris_ui_refresh`: the refresh token, `Path=/auth/ui`: only the pages see it.
- `__Secure-polaris_ui_mfa`: the login ticket between the password and the code.
- `__Host-polaris_csrf`: the CSRF nonce, `SameSite=Strict`.

`RequireSignIn` turns the 401 of a GET or HEAD into a redirect to `/refresh`, which renews the
session or asks for a sign-in, then returns to the same URL.

## Security notes

- CSRF: every POST carries a signed double-submit token (the HMAC of the `__Host-` cookie's nonce,
  keyed from `APP_KEY`, compared in constant time) and must come from the configured origin.
- Headers on every page: `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none';
  style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`
  (no script, no inline style), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `X-Content-Type-Options: nosniff`.
- Redirects: `return_to`, `AfterSignIn` and `AfterSignOut` are same-origin paths or URLs on
  `BaseURL`'s origin or `RedirectOrigins`; anything else ends on `AfterSignIn`. The OAuth pages redirect only to
  what the provider answers (a registered redirect URI).
- Error texts do not reveal whether an email is registered beyond what the JSON routes do.
- Not in v1: passkeys (they need a JavaScript ceremony), social and magic-link buttons, account
  settings and organization screens.

## Example

`Example` in [`example_test.go`](example_test.go) — `go doc github.com/univeros/polaris.go/plugins/ui`.
