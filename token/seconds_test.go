package token

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/univeros/polaris.go/clock"
)

// Date claims are minted as whole seconds (many verifiers decode NumericDate into an integer),
// and exp is iat plus the lifetime exactly; tokens minted earlier with fractional seconds still
// verify (the vectors keep them).
func TestDateClaimsAreMintedAsWholeSeconds(t *testing.T) {
	now := time.Unix(1_780_833_600, 123_456_789)
	codec := newCodec(t, testConfig(t, clock.NewFrozen(now)))
	ttl := int64(900)

	minted := map[string]string{"Issue": mustIssue(t, codec, Claims{}.With("sub", "u1"))}
	// The OAuth plugin computes expiresAt from its own reading of the clock, a moment earlier.
	at, err := codec.Mint("at+jwt", Claims{}.With("sub", "u1"), now.Add(-3*time.Microsecond).Add(300*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	minted["Mint"] = at
	for name, jwt := range minted {
		var c map[string]json.RawMessage
		if err := json.Unmarshal([]byte(segment(t, jwt, 1)), &c); err != nil {
			t.Fatal(err)
		}
		var iat, nbf, exp int64
		for claim, into := range map[string]*int64{"iat": &iat, "nbf": &nbf, "exp": &exp} {
			if err := json.Unmarshal(c[claim], into); err != nil {
				t.Fatalf("%s: %s is %s, not an integer", name, claim, c[claim])
			}
		}
		want := ttl
		if name == "Mint" {
			want = 300
		}
		if iat != now.Unix() || nbf != iat || exp-iat != want {
			t.Fatalf("%s: iat %d nbf %d exp %d", name, iat, nbf, exp)
		}
		if _, err := codec.VerifyJWT(jwt, 0); err != nil {
			t.Fatalf("%s does not verify: %v", name, err)
		}
	}
}
