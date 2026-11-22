package authz

import (
	"errors"
	"slices"
)

// Wire messages of the forbidden errors raised here (endpoints answer them in a 403 body).
const (
	MsgForbidden  = "You do not have permission to perform this action."
	MsgEscalation = "You cannot grant permissions you do not hold."
)

// ErrForbidden is matched (errors.Is) by every authorization refusal.
var ErrForbidden = errors.New("authz: forbidden")

// ForbiddenError is an authorization refusal. Message is
// meant for the client: endpoints answer it as `403 forbidden` with this message. It matches
// ErrForbidden; domain services return their own with Forbidden.
type ForbiddenError struct{ Message string }

func (e *ForbiddenError) Error() string { return e.Message }

// Is reports whether target is ErrForbidden.
func (e *ForbiddenError) Is(target error) bool { return target == ErrForbidden }

// Forbidden returns a *ForbiddenError carrying the client-facing message.
func Forbidden(message string) error { return &ForbiddenError{Message: message} }

// Authority is a user's effective authority in one active organization: the role slugs held and
// the flattened permission keys they grant (RoleSuperadmin with every permission for the global
// override). Both lists are non-nil and free of duplicates.
type Authority struct {
	Roles []string
	Scope []string
}

// Allows reports whether the authority holds every one of permissions (true for none).
func (a Authority) Allows(permissions ...string) bool {
	for _, p := range permissions {
		if !slices.Contains(a.Scope, p) {
			return false
		}
	}
	return true
}

// IsSuperadmin reports whether the authority carries the global superadmin override.
func (a Authority) IsSuperadmin() bool { return slices.Contains(a.Roles, RoleSuperadmin) }
