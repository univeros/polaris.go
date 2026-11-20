# telemetry/otel — OpenTelemetry for Polaris

`github.com/univeros/polaris.go/telemetry/otel` traces and measures a Polaris instance with
OpenTelemetry. It is the only package of the module that imports OpenTelemetry: a host that does not
import it links none of it.

```go
import polarisotel "github.com/univeros/polaris.go/telemetry/otel"

outcomes, err := polarisotel.Listener()       // auth outcome counter
if err != nil { … }
p, err := polaris.New(polaris.Config{
	Secrets: secrets, Auth: auth,
	DB:        polarisotel.Store(db),          // a span per database call
	Listeners: []event.Listener{outcomes},
	Middleware: []func(http.Handler) http.Handler{ // outermost: sees every request
		func(h http.Handler) http.Handler { return polarisotel.Middleware(h) },
	},
})
```

Without options everything uses the global providers (`otel.SetTracerProvider`,
`otel.SetMeterProvider`, `otel.SetTextMapPropagator`) your OpenTelemetry setup installs;
`WithTracerProvider` / `WithMeterProvider` pass explicit ones.

## What is recorded

| Source | Telemetry |
|---|---|
| `Middleware(next)` | One server span per request (otelhttp; W3C trace context extracted), named after the matched Polaris route (`polaris.auth.login`), else the host `ServeMux` pattern (`GET /hello`), else the method. Attributes: `polaris.route`, `http.response.status_code`, `polaris.principal.kind` (`user`, `api_key`, `oauth_client`, `agent`), and with `WithUserIDHash(key)` `enduser.pseudo.id`. Histogram `http.server.request.duration` (plus otelhttp's body-size histograms) labelled with `polaris.route` and `polaris.principal.kind`. |
| `Store(adapter)` | One client span per call, `<op> <table>` (`find_one`, `find_many`, `count`, `insert`, `update`, `delete`; `tx` with the calls as children). Attributes: `db.system.name`, `db.collection.name`, `db.operation.name`, `db.response.returned_rows` (reads), `polaris.db.rows_affected` (writes); on failure `error.type` (`duplicate`, `canceled` or `_OTHER`) and status Error. |
| `Listener()` | Counter `polaris.auth.outcomes` with `polaris.auth.outcome`: `login_succeeded`, `login_failed`, `account_locked`, `refresh_reuse`, `mfa_failed`, `agent_executed`, `agent_denied`. |

`Store` keeps the wrapped adapter's `CreateMissing` (so `Polaris.Migrate` works) and exposes it with
`Unwrap()` (the CLI's schema commands unwrap it).

## Privacy

- Never recorded: tokens, passwords, secrets, email addresses, request or response bodies, query
  criteria, row values, error messages (a driver's message can quote the value that failed).
- The principal's user id is omitted unless `WithUserIDHash(key)` is set; then the span carries
  `enduser.pseudo.id` = first 16 bytes of HMAC-SHA256(key, user id), hex. Use a dedicated secret key
  of at least 32 bytes. Metrics never carry ids.
- otelhttp itself records the request's `url.path` (which holds resource ids such as
  `/admin/users/{id}`), `user_agent.original`, `network.peer.address` and `client.address` (taken
  from `X-Forwarded-For` when present, so client-controlled). Drop or redact them in your collector
  if your policy requires it; Polaris's own decisions use `RemoteAddr` only.

## Alerts worth having

- `polaris.auth.outcomes{polaris.auth.outcome="refresh_reuse"}` > 0: a stolen refresh token was
  replayed (the family is already revoked).
- A spike of `login_failed` or `account_locked`: credential stuffing.
- `agent_denied` rising for one deployment: an agent probing outside its grants.
