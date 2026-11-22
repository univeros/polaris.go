package orgs

import (
	"errors"
	"testing"
)

func TestErrorCarriesItsMessageAndMatchesItsKind(t *testing.T) {
	var err error = &Error{Kind: ErrConflict, Message: "The organization must keep at least one owner."}
	if !errors.Is(err, ErrConflict) || errors.Is(err, ErrNotFound) || err.Error() != "The organization must keep at least one owner." {
		t.Fatalf("err = %#v", err)
	}
}
