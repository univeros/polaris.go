package agents

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
)

// Problem names: the agents/<name> problem type of a refusal. The protocol's own codes travel bare
// in the problem's error member; the others carry the plugin prefix (agents_not_found).
const (
	ErrUnauthorized              = "unauthorized"
	ErrInvalidJWT                = "invalid_jwt"
	ErrAudMismatch               = "aud_mismatch"
	ErrAgentInactive             = "agent_inactive"
	ErrCapabilityNotFound        = "capability_not_found"
	ErrCapabilityNotGranted      = "capability_not_granted"
	ErrConstraintViolated        = "constraint_violated"
	ErrBudgetExhausted           = "budget_exhausted"
	ErrUnknownConstraintOperator = "unknown_constraint_operator"
	ErrInvalidArguments          = "invalid_arguments"
	ErrInvalidInput              = "invalid_input"
	ErrNotFound                  = "not_found"
	ErrForbidden                 = "forbidden"
	ErrConflict                  = "conflict"
	ErrStepUpRequired            = "step_up_required"
	ErrPermissionNotHeld         = "permission_not_held"
	ErrSealed                    = "sealed"
	ErrPayloadTooLarge           = "payload_too_large"
)

var protocolCodes = []string{ErrInvalidJWT, ErrAudMismatch, ErrAgentInactive, ErrCapabilityNotFound,
	ErrCapabilityNotGranted, ErrConstraintViolated, ErrBudgetExhausted, ErrUnknownConstraintOperator}

var statuses = map[string]int{
	ErrUnauthorized: 401, ErrInvalidJWT: 401, ErrAudMismatch: 401, ErrAgentInactive: 401,
	ErrCapabilityNotFound: 404, ErrCapabilityNotGranted: 403, ErrConstraintViolated: 403, ErrBudgetExhausted: 403,
	ErrUnknownConstraintOperator: 400, ErrInvalidArguments: 422, ErrInvalidInput: 422, ErrNotFound: 404,
	ErrForbidden: 403, ErrConflict: 409, ErrStepUpRequired: 403, ErrPermissionNotHeld: 403, ErrSealed: 409,
	ErrPayloadTooLarge: 413,
}

// Error is a refused agent request, answered as the RFC 9457 problem agents/<Type>. Branch on it
// with errors.As; a capability handler may return one to refuse with that problem.
type Error struct {
	Type   string // one of the Err* names
	Detail string
	// Code overrides the problem's error member (agent_revoked, agent_suspended).
	Code string
	// Extra members of the problem (violations, errors, invalid_capabilities, strength).
	Extra map[string]any
}

// Error implements error.
func (e *Error) Error() string { return "agents: " + e.Type + ": " + e.Detail }

// Status is the HTTP status the problem answers.
func (e *Error) Status() int {
	if s, ok := statuses[e.Type]; ok {
		return s
	}
	return http.StatusBadRequest
}

func (e *Error) code() string {
	switch {
	case e.Code != "":
		return e.Code
	case slices.Contains(protocolCodes, e.Type):
		return e.Type
	}
	return "agents_" + e.Type
}

// acronyms are the words of a problem type a title writes in capitals.
var acronyms = map[string]string{"dpop": "DPoP", "id": "ID", "jwt": "JWT"}

// title is a snake_case problem type as a sentence: "invalid_jwt" is "Invalid JWT".
func title(typ string) string {
	words := strings.Split(typ, "_")
	for i, w := range words {
		if a, ok := acronyms[w]; ok {
			words[i] = a
		} else if i == 0 && w != "" {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

// problem is the RFC 9457 body.
func (e *Error) problem() map[string]any {
	body := map[string]any{
		"type": endpoint.ProblemTypes + "agents/" + e.Type, "title": title(e.Type),
		"status": e.Status(), "detail": e.Detail, "error": e.code(), "message": e.Detail,
	}
	for k, v := range e.Extra {
		body[k] = v
	}
	return body
}

// result is the endpoint answer: the problem, no-store, and RFC 6750's challenge on a 401 (no
// error without a credential, invalid_token for one that does not authenticate).
func (e *Error) result() endpoint.Result {
	r := endpoint.Result{Status: e.Status(), Body: e.problem(), Problem: true, Header: http.Header{"Cache-Control": {"no-store"}}}
	if e.Status() == http.StatusUnauthorized {
		challenge := `Bearer error="invalid_token"`
		if e.Type == ErrUnauthorized {
			challenge = "Bearer"
		}
		r.Header.Set("WWW-Authenticate", challenge)
	}
	return r
}

func refuse(typ, detail string) *Error { return &Error{Type: typ, Detail: detail} }

// asError extracts an *Error from err.
func asError(err error) (*Error, bool) {
	var e *Error
	ok := errors.As(err, &e)
	return e, ok
}
