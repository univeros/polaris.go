package orgs

import pub "github.com/univeros/polaris.go/orgs"

// The names of the public package orgs (the v1 API), repeated here so this package's
// code and its callers inside the module read as one package.
type (
	Error  = pub.Error
	Member = pub.Member
)

// The public errors.
var (
	ErrConflict          = pub.ErrConflict
	ErrInvalid           = pub.ErrInvalid
	ErrInvalidInvitation = pub.ErrInvalidInvitation
	ErrNotFound          = pub.ErrNotFound
)
