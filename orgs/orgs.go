package orgs

import (
	"errors"
)

// Kinds of refusal, matched with errors.Is on a *Error.
var (
	ErrInvalid           = errors.New("orgs: invalid input")      // 422 unprocessable
	ErrNotFound          = errors.New("orgs: not found")          // 404 not_found
	ErrConflict          = errors.New("orgs: conflict")           // 409 conflict
	ErrInvalidInvitation = errors.New("orgs: invalid invitation") // 400, never says why
)

// Error is a refusal of the domain: Kind is one of ErrInvalid, ErrNotFound, ErrConflict or
// ErrInvalidInvitation (errors.Is matches it), Message the text the endpoint answers.
type Error struct {
	Kind    error
	Message string
}

func (e *Error) Error() string { return e.Message }

// Unwrap returns Kind.
func (e *Error) Unwrap() error { return e.Kind }
