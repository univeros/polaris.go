package scim

import (
	"errors"
	"net/http"
)

// SCIM error types (RFC 7644 §3.12 scimType).
const (
	TypeInvalidFilter = "invalidFilter"
	TypeInvalidValue  = "invalidValue"
	TypeInvalidPath   = "invalidPath"
	TypeInvalidSyntax = "invalidSyntax"
	TypeUniqueness    = "uniqueness"
	TypeMutability    = "mutability"
)

// Error is a refused SCIM request: its HTTP status, scimType ("" for none) and detail, answered as
// a SCIM error document.
type Error struct {
	Status int
	Type   string
	Detail string
}

func (e *Error) Error() string { return "scim: " + e.Detail }

func notFound(what string) error {
	return &Error{Status: http.StatusNotFound, Detail: what + " not found."}
}

func invalid(detail, typ string) error {
	return &Error{Status: http.StatusBadRequest, Type: typ, Detail: detail}
}

func conflict(detail string) error {
	return &Error{Status: http.StatusConflict, Type: TypeUniqueness, Detail: detail}
}

func immutable(detail string) error {
	return &Error{Status: http.StatusForbidden, Type: TypeMutability, Detail: detail}
}

func asError(err error) (*Error, bool) {
	var e *Error
	return e, errors.As(err, &e)
}
