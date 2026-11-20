package endpoint

import (
	"context"
	"testing"

	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/token"
)

func TestObservedRecordsRouteAndToken(t *testing.T) {
	o := &Observed{}
	ctx := WithObserved(context.Background(), o)
	r := &manifest.Route{Name: "polaris.auth.login"}
	tok := token.NewPrincipal(map[string]any{"sub": "u1"})
	inner := WithToken(WithRoute(ctx, r), tok)
	if Route(inner) != r || Token(inner) != tok {
		t.Fatal("context values lost")
	}
	if o.Route != r || o.Token != tok {
		t.Fatalf("Observed = %+v, want route and token recorded", o)
	}
	// Without an Observed nothing is recorded and nothing panics.
	if Route(WithRoute(context.Background(), r)) != r {
		t.Fatal("WithRoute without Observed")
	}
}
