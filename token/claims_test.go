package token

import (
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"testing"
)

// AccessTokenClaimsTest

func TestAccessClaimsRendersTheFullClaimMap(t *testing.T) {
	c := mustClaims(t, AccessClaims{
		Subject: "user-1", ID: "jti-1", SessionID: "sid-1", OrganizationID: "org-1",
		Roles: []string{"admin"}, Scope: []string{"members.invite"}, EmailVerified: true, MFA: true,
		AMR: []string{"pwd", "otp"}, AuthTime: int64p(1_780_000_000),
	})
	want := `{"sub":"user-1","jti":"jti-1","org":"org-1","roles":["admin"],"email_verified":true,` +
		`"mfa":true,"amr":["pwd","otp"],"sid":"sid-1","scope":["members.invite"],"auth_time":1780000000}`
	if got, _ := c.MarshalJSON(); string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
}

func TestAccessClaimsOmitsOptionalClaimsButKeepsNullableOrg(t *testing.T) {
	c := mustClaims(t, AccessClaims{Subject: "user-1", ID: "jti-1"})
	for _, name := range []string{"sid", "scope", "auth_time"} {
		if _, ok := c.Get(name); ok {
			t.Errorf("%s present", name)
		}
	}
	if org, ok := c.Get("org"); !ok || org != nil {
		t.Fatalf("org = %v, %v", org, ok)
	}
}

func TestAccessClaimsExtraClaimsRideAlongAndNeverOverrideAStandardOne(t *testing.T) {
	c := mustClaims(t, AccessClaims{Subject: "user-1", ID: "jti-1",
		Extra: Claims{}.With("impersonated_by", "op-1").With("sub", "someone-else")})
	if v, _ := c.Get("impersonated_by"); v != "op-1" {
		t.Fatalf("impersonated_by = %v", v)
	}
	if v, _ := c.Get("sub"); v != "user-1" {
		t.Fatal("a standard claim wins over an extra of the same name")
	}
	// PHP's [...$extra, 'sub' => …] keeps sub where extra put it.
	if names := c.Names(); names[0] != "impersonated_by" || names[1] != "sub" || names[2] != "jti" {
		t.Fatalf("order = %v", names)
	}
}

func TestAccessClaimsRejectsAnEmptySubjectOrID(t *testing.T) {
	for _, a := range []AccessClaims{{ID: "jti-1"}, {Subject: "user-1"}} {
		if _, err := a.Claims(); !errors.Is(err, ErrInvalidClaims) {
			t.Errorf("%+v: err = %v", a, err)
		}
	}
}

func TestClaimsWithIsCopyOnWrite(t *testing.T) {
	base := Claims{}.With("a", 1)
	x := base.With("b", 2)
	y := base.With("c", 3)
	if base.Len() != 1 || !reflect.DeepEqual(x.Names(), []string{"a", "b"}) || !reflect.DeepEqual(y.Names(), []string{"a", "c"}) {
		t.Fatalf("base %v x %v y %v", base.Names(), x.Names(), y.Names())
	}
	z := x.With("a", 9)
	if v, _ := x.Get("a"); v != 1 {
		t.Fatal("With mutated its receiver")
	}
	if !reflect.DeepEqual(z.Names(), []string{"a", "b"}) {
		t.Fatalf("re-set moved the claim: %v", z.Names())
	}
}

// Expectations probed from PHP 8.5's json_encode(…, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE).
func TestClaimsEncodeLikePHP(t *testing.T) {
	point1, point2 := 0.1, 0.2
	c := Claims{}.
		With("s", "a/b\u2028é<>&\x01\x1f\x7f\"\\\b\f").
		With("floats", []any{1.0, 1.5, 1e15, 1e16, 1e17, 123456789012345678.0, 1e20, 1.5e-7, 0.0001, 0.00001, math.Copysign(0, -1), point1 + point2}).
		With("ints", []any{int8(-1), uint16(2), uint(3), int64(-4)}).
		With("map", map[string]any{"b": 1, "a": Claims{}.With("z", true).With("y", nil)}).
		With("empty", map[string]any{}).
		With("raw", json.RawMessage(`{"k":[1]}`))
	want := `{"s":"a/b\u2028é<>&\u0001\u001f` + "\x7f" + `\"\\\b\f",` +
		`"floats":[1,1.5,1000000000000000,10000000000000000,1.0e+17,1.2345678901234568e+17,1.0e+20,1.5e-7,0.0001,1.0e-5,-0,0.30000000000000004],` +
		`"ints":[-1,2,3,-4],"map":{"a":{"z":true,"y":null},"b":1},"empty":[],"raw":{"k":[1]}}`
	got, err := c.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	for _, bad := range []any{math.Inf(1), math.NaN(), uint64(math.MaxUint64), json.RawMessage(`{`), []any{func() {}}} {
		if _, err := (Claims{}.With("x", bad)).MarshalJSON(); err == nil {
			t.Errorf("%T encoded", bad)
		}
	}
}
