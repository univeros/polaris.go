package session

import (
	"errors"
)

// ErrReservedClaim reports a host claim (Config.Claims) whose name Polaris or a standard reserves,
// or that the token already carries.
var ErrReservedClaim = errors.New("session: reserved claim name")
