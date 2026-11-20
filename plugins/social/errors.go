package social

import (
	"errors"
	"net/http"
)

// kind names why a social step could not proceed; it is the problem type social/<kind>.
type kind string

const (
	kindInvalidInput       kind = "invalid_input"
	kindProviderNotFound   kind = "provider_not_found"
	kindRedirectNotAllowed kind = "redirect_not_allowed"
	kindStateInvalid       kind = "state_invalid"
	kindProviderError      kind = "provider_error"
	kindTokenInvalid       kind = "token_invalid"
	kindEmailRequired      kind = "email_required"
	kindEmailMismatch      kind = "email_mismatch"
	kindAccountExists      kind = "account_exists"
	kindAccountLinked      kind = "account_linked"
	kindAccountDisabled    kind = "account_disabled"
	kindEmailUnverified    kind = "email_unverified"
	kindNotLinked          kind = "not_linked"
	kindLastCredential     kind = "last_credential"
	kindCodeInvalid        kind = "code_invalid"
	kindNoRefresh          kind = "no_refresh"
)

// refusal is a refused step; detail is what the caller may read (or, for a provider error, what
// the audit trail records).
type refusal struct {
	kind   kind
	detail string
}

func (r *refusal) Error() string { return "social: " + string(r.kind) + ": " + r.detail }

func refuse(k kind, detail string) error { return &refusal{kind: k, detail: detail} }

func asRefusal(err error) (*refusal, bool) {
	var r *refusal
	return r, errors.As(err, &r)
}

// problem is the wire form of each kind: status, title and, where upstream fixes it, the detail.
var problems = map[kind]struct {
	status int
	title  string
	detail string // "" means the refusal's own detail
}{
	kindProviderNotFound:   {http.StatusNotFound, "Provider not found", "No such provider is configured."},
	kindRedirectNotAllowed: {http.StatusUnprocessableEntity, "Redirect not allowed", ""},
	kindStateInvalid:       {http.StatusUnprocessableEntity, "Invalid state", "The state is unknown, used, expired or not signed for this application."},
	kindProviderError:      {http.StatusForbidden, "Sign-in refused", "The sign-in could not be completed with the provider."},
	kindTokenInvalid:       {http.StatusUnprocessableEntity, "Invalid token", "The token could not be verified."},
	kindEmailRequired:      {http.StatusUnprocessableEntity, "Email required", ""},
	kindEmailMismatch:      {http.StatusConflict, "Email mismatch", ""},
	kindAccountExists:      {http.StatusConflict, "Account exists", "An account with this email exists; sign in and link the provider from your account."},
	kindAccountLinked:      {http.StatusConflict, "Account linked elsewhere", ""},
	kindAccountDisabled:    {http.StatusForbidden, "Account disabled", "This account is disabled."},
	kindEmailUnverified:    {http.StatusForbidden, "Email not verified", ""},
	kindNotLinked:          {http.StatusNotFound, "Not linked", ""},
	kindLastCredential:     {http.StatusConflict, "Last credential", ""},
	kindCodeInvalid:        {http.StatusUnprocessableEntity, "Invalid code", "The code is unknown, used or expired."},
	kindNoRefresh:          {http.StatusConflict, "Token expired", ""},
}
