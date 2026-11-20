package sso

import (
	"errors"
	"net/http"

	"github.com/univeros/polaris-go/endpoint"
)

// Why a sign-in could not proceed: an Error's Reason, also the problem name the caller reads.
const (
	ReasonProviderNotFound    = "provider_not_found"
	ReasonProviderDisabled    = "provider_disabled"
	ReasonInvalidInput        = "invalid_input"
	ReasonAssertionInvalid    = "assertion_invalid"
	ReasonUserUnknown         = "user_unknown"
	ReasonAccountDisabled     = "account_disabled"
	ReasonMembershipSuspended = "membership_suspended"
	ReasonCodeInvalid         = "code_invalid"
)

// Error is a refused step of the flow. Reason is one of the Reason constants; Detail is what the
// audit trail records (sso.assertion_rejected) and is never sent to the caller for a rejected
// assertion or token, which reads a generic problem. A host's OIDC or SAML implementation returns
// an *Error with ReasonAssertionInvalid (any other error is treated the same way).
type Error struct {
	Reason string
	Detail string
}

func (e *Error) Error() string { return "sso: " + e.Reason + ": " + e.Detail }

func refuse(reason, detail string) *Error { return &Error{Reason: reason, Detail: detail} }

// rejected is err as a refused assertion: an *Error keeps its reason, anything else (a library's
// error) becomes assertion_invalid with its text as the detail.
func rejected(err error) *Error {
	if e, ok := errors.AsType[*Error](err); ok {
		return e
	}
	return refuse(ReasonAssertionInvalid, err.Error())
}

// problem is the problem document a refusal answers.
func problem(e *Error) endpoint.Result {
	switch e.Reason {
	case ReasonProviderNotFound:
		return ssoProblem(http.StatusNotFound, e.Reason, "Provider not found", "No SSO provider answers this request.")
	case ReasonProviderDisabled:
		return ssoProblem(http.StatusForbidden, e.Reason, "Provider disabled", "The SSO provider is disabled.")
	case ReasonInvalidInput:
		return ssoProblem(http.StatusUnprocessableEntity, e.Reason, "Invalid input", e.Detail)
	case ReasonUserUnknown:
		return ssoProblem(http.StatusForbidden, e.Reason, "Unknown user", "No account matches this identity and the provider does not create accounts.")
	case ReasonAccountDisabled:
		return ssoProblem(http.StatusForbidden, e.Reason, "Account disabled", "This account is disabled.")
	case ReasonMembershipSuspended:
		return ssoProblem(http.StatusForbidden, e.Reason, "Membership suspended", "Your membership in this organization is suspended.")
	case ReasonCodeInvalid:
		return ssoProblem(http.StatusUnprocessableEntity, e.Reason, "Invalid code", "The code is unknown, already used or expired.")
	}
	return ssoProblem(http.StatusForbidden, ReasonAssertionInvalid, "Sign-in refused", "The sign-in could not be completed.")
}

func ssoProblem(status int, name, title, detail string) endpoint.Result {
	return endpoint.Problem(status, "sso/"+name, title, detail, nil)
}

func invalidInput(detail string, errs ...string) endpoint.Result {
	var ext map[string]any
	if len(errs) > 0 {
		ext = map[string]any{"errors": errs}
	}
	return endpoint.Problem(http.StatusUnprocessableEntity, "sso/invalid_input", "Invalid input", detail, ext)
}
