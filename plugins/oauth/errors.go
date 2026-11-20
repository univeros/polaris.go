package oauth

import (
	"errors"
	"net/http"
)

// The error codes a refused OAuth request carries (RFC 6749, 8628, 8693, 9449, 7591, OpenID CIBA);
// each is also the problem type oauth/<code>.
const (
	CodeInvalidRequest          = "invalid_request"
	CodeInvalidClient           = "invalid_client"
	CodeInvalidGrant            = "invalid_grant"
	CodeUnauthorizedClient      = "unauthorized_client"
	CodeUnsupportedGrantType    = "unsupported_grant_type"
	CodeUnsupportedResponseType = "unsupported_response_type"
	CodeInvalidScope            = "invalid_scope"
	CodeAccessDenied            = "access_denied"
	CodeInvalidTarget           = "invalid_target"
	CodeInvalidDPoPProof        = "invalid_dpop_proof"
	CodeInvalidToken            = "invalid_token"
	CodeAuthorizationPending    = "authorization_pending"
	CodeSlowDown                = "slow_down"
	CodeExpiredToken            = "expired_token"
	CodeUnknownUserID           = "unknown_user_id"
	CodeInvalidClientMetadata   = "invalid_client_metadata"
	CodeRegistrationDisabled    = "registration_disabled"
	CodeNotFound                = "not_found"
	CodeConsentRequired         = "consent_required"
)

// ErrClientNotFound is returned by Plugin.Client for a client id nobody registered.
var ErrClientNotFound = errors.New("oauth: client not found")

// Error is a refused OAuth request: Code is the wire error code, Description its
// error_description, Status the HTTP status. Match it with errors.As.
type Error struct {
	Code        string
	Description string
	Status      int
	// reused marks a spent refresh token presented again (its family was revoked).
	reused bool
}

// Error implements error.
func (e *Error) Error() string { return "oauth: " + e.Code + ": " + e.Description }

// refusal is a 400 Error.
func refusal(code, description string) *Error {
	return &Error{Code: code, Description: description, Status: http.StatusBadRequest}
}

// refusalWith is an Error with another status.
func refusalWith(code, description string, status int) *Error {
	return &Error{Code: code, Description: description, Status: status}
}

// unauthorizedClient is the 401 invalid_client of a failed client authentication.
func unauthorizedClient(description string) *Error {
	return refusalWith(CodeInvalidClient, description, http.StatusUnauthorized)
}
