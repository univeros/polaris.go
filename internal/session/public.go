package session

import pub "github.com/univeros/polaris.go/session"

// The names of the public package session (the v1 API), repeated here so this package's
// code and its callers inside the module read as one package.
type (
	Info = pub.Info
)

// The public errors.
var (
	ErrInvalidGrant      = pub.ErrInvalidGrant
	ErrOrganizationBound = pub.ErrOrganizationBound
	ErrRefreshReuse      = pub.ErrRefreshReuse
	ErrReservedClaim     = pub.ErrReservedClaim
)
