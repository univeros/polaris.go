package session

import (
	"errors"
	"fmt"
)

var (
	// ErrInvalidGrant reports a refresh token that cannot be exchanged (unknown, expired, or
	// ended by logout, an admin or a password change), or a session that is no longer live for
	// StepUp and SwitchOrganization. The refresh endpoint answers 401 invalid_grant.
	ErrInvalidGrant = errors.New("session: invalid grant")
	// ErrRefreshReuse reports an already-rotated refresh token presented again, the stolen-token
	// signature: the whole family has been revoked and event.RefreshReuseDetected dispatched by
	// the time it is returned. It matches ErrInvalidGrant too.
	ErrRefreshReuse = fmt.Errorf("%w: refresh token already used", ErrInvalidGrant)
	// ErrOrganizationBound reports a SwitchOrganization out of a session an organization's
	// identity provider opened (amr "sso"): it stays in that organization.
	ErrOrganizationBound = errors.New("session: bound to its organization")
)
