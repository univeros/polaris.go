package session

import (
	"errors"
	"testing"
)

// A reused refresh token is answered as any other invalid grant.
func TestRefreshReuseIsAnInvalidGrant(t *testing.T) {
	if !errors.Is(ErrRefreshReuse, ErrInvalidGrant) || errors.Is(ErrInvalidGrant, ErrRefreshReuse) {
		t.Fatal("ErrRefreshReuse must match ErrInvalidGrant, and not the reverse")
	}
}
