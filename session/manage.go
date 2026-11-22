package session

import (
	"time"
)

// Info is one active session (device) of a user, as GET /auth/sessions lists it.
type Info struct {
	ID         string // the session id (refresh family)
	Current    bool   // the calling session
	IP         *string
	UserAgent  *string
	CreatedAt  time.Time // when the session was opened (its first token)
	LastUsedAt time.Time // last refresh, or creation of the live token
}
