package endpoint

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/univeros/polaris.go/manifest"
)

// ProblemTypes prefixes every RFC 9457 problem type URL.
const ProblemTypes = "https://polaris.univeros.io/problems/"

// JSON answers status with body.
func JSON(status int, body any) Result { return Result{Status: status, Body: body} }

// Data answers status with core's success envelope {"data": data}.
func Data(status int, data any) Result { return JSON(status, map[string]any{"data": data}) }

// NoContent answers 204 without a body.
func NoContent() Result { return Result{Status: http.StatusNoContent} }

// Error answers core's error envelope {"error": code, "message": message}.
func Error(status int, code, message string) Result {
	return JSON(status, map[string]any{"error": code, "message": message})
}

// Unprocessable answers core's 422 {"errors": [...]}.
func Unprocessable(errs []string) Result {
	if errs == nil {
		errs = []string{}
	}
	return JSON(http.StatusUnprocessableEntity, map[string]any{"errors": errs})
}

// Invalid answers the 422 for a validation error from manifest.Route.Validate.
func Invalid(err *manifest.ValidationError) Result { return Unprocessable(err.Errors) }

// Unauthorized answers 401 unauthorized.
func Unauthorized() Result {
	return Error(http.StatusUnauthorized, "unauthorized", "Authentication is required.")
}

// Forbidden answers 403 forbidden.
func Forbidden(message string) Result { return Error(http.StatusForbidden, "forbidden", message) }

// NotFound answers 404 not_found.
func NotFound(message string) Result { return Error(http.StatusNotFound, "not_found", message) }

// TooManyRequests answers 429 too_many_requests in rt's error style: core's envelope for a core
// route or no route (a host route behind Protect), a problem document for a plugin route. The
// caller sets Retry-After and the X-RateLimit-* headers.
func TooManyRequests(rt *manifest.Route) Result {
	const message = "Too many requests. Try again after the Retry-After delay."
	if rt == nil || rt.Plugin == "" {
		return Error(http.StatusTooManyRequests, "too_many_requests", message)
	}
	return Problem(http.StatusTooManyRequests, "too_many_requests", "Too many requests", message, nil)
}

// Problem answers an RFC 9457 problem document (plugin routes). typ is "<plugin>/<name>"; the body
// also carries "error" (typ with / and - as _) and "message" (= detail) so clients reading core's
// envelope read both. ext members are added last.
func Problem(status int, typ, title, detail string, ext map[string]any) Result {
	body := map[string]any{
		"type":    ProblemTypes + typ,
		"title":   title,
		"status":  status,
		"detail":  detail,
		"error":   strings.NewReplacer("/", "_", "-", "_").Replace(typ),
		"message": detail,
	}
	for k, v := range ext {
		body[k] = v
	}
	return Result{Status: status, Body: body, Problem: true}
}

// Write writes r to w: Content-Type (none on 204), extra headers, then the JSON body.
func Write(w http.ResponseWriter, r Result) {
	h := w.Header()
	if r.Status != http.StatusNoContent {
		if r.Problem {
			h.Set("Content-Type", "application/problem+json")
		} else {
			h.Set("Content-Type", "application/json")
		}
	}
	for name, values := range r.Header {
		h.Del(name)
		for _, v := range values {
			h.Add(name, v)
		}
	}
	var body []byte
	switch {
	case r.Raw != nil:
		body = r.Raw
	case r.Body != nil:
		body = encode(r.Body)
	}
	w.WriteHeader(r.Status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}

func encode(v any) []byte {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return []byte(`{"error":"server_error","message":"The response could not be encoded."}`)
	}
	return []byte(strings.TrimSuffix(b.String(), "\n"))
}
