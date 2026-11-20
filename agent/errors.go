package agent

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Error is a call the server refused: the HTTP status, the problem's error code and, when the
// server sent an RFC 9457 problem document, the document. Match a code with errors.Is against the
// Err* values, or read Code.
type Error struct {
	Status int
	// Code is the problem's error (invalid_jwt, capability_not_granted, constraint_violated,
	// budget_exhausted, ...), request_failed when the answer had none.
	Code    string
	Problem *Problem
	msg     string
}

func (e *Error) Error() string { return e.msg }

// Is matches an Err* code value: errors.Is(err, agent.ErrBudgetExhausted).
func (e *Error) Is(target error) bool {
	var t *Error
	return errors.As(target, &t) && t.Status == 0 && t.Code == e.Code
}

// Problem is the RFC 9457 problem document of a refusal.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Code   string `json:"error"`
	// Message is the core envelope's message, when the server sent one.
	Message string `json:"message"`
	// Violations are the failed constraints of a constraint_violated refusal.
	Violations []Violation `json:"violations"`
}

// Violation is one argument a grant's constraint refused.
type Violation struct {
	Field      string `json:"field"`
	Constraint string `json:"constraint"`
	Actual     any    `json:"actual"`
}

func code(c string) *Error { return &Error{Code: c, msg: "agent: " + c} }

// The refusals an agent most often branches on; match with errors.Is.
var (
	ErrInvalidJWT           = code("invalid_jwt")
	ErrAudMismatch          = code("aud_mismatch")
	ErrCapabilityNotFound   = code("capability_not_found")
	ErrCapabilityNotGranted = code("capability_not_granted")
	ErrConstraintViolated   = code("constraint_violated")
	ErrBudgetExhausted      = code("budget_exhausted")
	ErrAgentRevoked         = code("agent_revoked")
	ErrAgentSuspended       = code("agent_suspended")
)

// The waits for an approval that end without the grants. A wait the context cancels returns the
// context's error.
var (
	ErrApprovalDenied  = errors.New("agent: the approval was denied")
	ErrApprovalExpired = errors.New("agent: the approval expired before it was decided")
)

// ErrNotConfiguration is a discovery URL that did not answer an agent configuration document.
var ErrNotConfiguration = errors.New("agent: not an agent configuration document (endpoints.execute and token_endpoint are required)")

// ErrNoCredential is a call that needs the agent to authenticate, made by an Agent without a key
// or an access token: give it one with WithKey or WithToken.
var ErrNoCredential = errors.New("agent: the agent has no key and no access token: use agent.WithKey or Agent.WithToken")

// ErrNotRegistered is a call that needs the agent's id, made before it was registered or
// enrolled: use the Agent Register or Enroll returns, or agent.WithID.
var ErrNotRegistered = errors.New("agent: the agent is not registered yet: use the Agent that Register or Enroll returns, or agent.WithID")

// refusal builds the Error for a non-2xx answer as the PHP and TypeScript SDKs do: the problem
// when the body has string type and error members, the detail (else message, else the first 200
// bytes) in the message.
func refusal(method, url string, status int, body []byte) *Error {
	var loose map[string]any
	_ = json.Unmarshal(body, &loose)
	e := &Error{Status: status, Code: "request_failed"}
	if c, ok := loose["error"].(string); ok {
		e.Code = c
	}
	detail := string(body[:min(len(body), 200)])
	_, isType := loose["type"].(string)
	if _, isCode := loose["error"].(string); isType && isCode {
		var p Problem
		if json.Unmarshal(body, &p) == nil {
			e.Problem = &p
		}
	}
	if d, ok := loose["detail"].(string); ok && e.Problem != nil {
		detail = d
	} else if m, ok := loose["message"].(string); ok {
		detail = m
	}
	e.msg = fmt.Sprintf("agent: %s %s answered %d: %s", method, url, status, detail)
	return e
}
