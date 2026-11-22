package scim

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/univeros/polaris.go/endpoint"
)

// What a client reads: RFC 3339 timestamps in UTC, written with Z.
func TestTimestampsAreRFC3339InUTC(t *testing.T) {
	at := time.Date(2026, 9, 10, 14, 0, 0, 0, time.FixedZone("CEST", 2*3600))
	m := Connection{CreatedAt: at, LastSyncAt: &at}.Map()
	if m["created_at"] != "2026-09-10T12:00:00Z" || m["last_sync_at"] != "2026-09-10T12:00:00Z" || m["decommissioned_at"] != nil {
		t.Fatalf("connection timestamps %v %v %v", m["created_at"], m["last_sync_at"], m["decommissioned_at"])
	}
}

// startIndex, count and limit are integers (RFC 7644 §3.4.2.4): decimal digits in a query string
// (an optional sign for startIndex and count, which RFC 7644 clamps), a JSON integer in a body.
func TestQueryIntegersAreStrict(t *testing.T) {
	for v, want := range map[any]int{"12": 12, json.Number("7"): 7, "-4": -4, "99999999999999999999": 1e9, "-99999999999999999999": -1e9} {
		if got, ok := integer(v); !ok || got != want {
			t.Fatalf("integer(%v) = %d %v", v, got, ok)
		}
	}
	for _, v := range []any{" 3 ", "3 ", "1e2", "2.9", "0x1A", "inf", "", "abc", json.Number("1.0"), json.Number("1e2"), true, nil, 3.0} {
		if _, ok := integer(v); ok {
			t.Fatalf("integer(%#v) accepted", v)
		}
	}
	in := func(q string) *endpoint.Input {
		return endpoint.NewInput(httptest.NewRequest(http.MethodGet, "/?"+q, nil), nil)
	}
	for q, want := range map[string][2]int{"": {1, defaultCount}, "startIndex=-3&count=-1": {1, 0}, "startIndex=4&count=500": {4, MaxCount}} {
		start, n, err := paging(in(q))
		if err != nil || start != want[0] || n != want[1] {
			t.Fatalf("%q: %d %d %v", q, start, n, err)
		}
	}
	for _, q := range []string{"startIndex=x", "startIndex=1.5", "count=1e2", "count=%203", "startIndex="} {
		_, _, err := paging(in(q))
		var e *Error
		if !errors.As(err, &e) || e.Status != http.StatusBadRequest || e.Type != TypeInvalidValue {
			t.Fatalf("%q: %v", q, err)
		}
	}
	for v, want := range map[any]int{nil: DefaultLimit, "": DefaultLimit, "5": 5, json.Number("6"): 6, "100000": 100000} {
		if got, ok := positiveInt(v, DefaultLimit); !ok || got != want {
			t.Fatalf("positiveInt(%v) = %d %v", v, got, ok)
		}
	}
	for _, v := range []any{"0", "-1", " 5", "5 ", "2.5", "1e1", json.Number("2.0"), "x", 3.5} {
		if _, ok := positiveInt(v, DefaultLimit); ok {
			t.Fatalf("positiveInt(%#v) accepted", v)
		}
	}
}

// active is a JSON boolean (RFC 7643 §4.1.1); a string is refused, not read.
func TestActiveIsAJSONBoolean(t *testing.T) {
	for body, want := range map[string]bool{`{}`: true, `{"active": null}`: true, `{"active": true}`: true, `{"active": false}`: false,
		`{"active": "True"}`: true, `{"active": "false"}`: false, `{"active": "FALSE"}`: false} {
		var b map[string]any
		_ = json.Unmarshal([]byte(body), &b)
		if got, err := activeOf(b); err != nil || got != want {
			t.Fatalf("%s: %v %v", body, got, err)
		}
	}
	for _, v := range []any{"1", "on", "yes", "", " true", "t", json.Number("1"), json.Number("0"), []any{}} {
		_, err := activeOf(map[string]any{"active": v})
		var e *Error
		if !errors.As(err, &e) || e.Status != http.StatusBadRequest || e.Type != TypeInvalidValue {
			t.Fatalf("active %#v: %v", v, err)
		}
	}
}

// Microsoft Entra ID (without ?aadOptscim062020) sends active as "True"/"False" and capitalises
// op: its exact deactivation and reactivation PATCH bodies work.
func TestEntraIDsPatchOfActiveWorks(t *testing.T) {
	f := newFixture(t)
	orgID := f.organization()
	conn := f.connection(orgID, DeprovisionDeactivate)
	d := f.p.dir
	d.domains = func() any { return verifiedDomains{orgID: "acme.example"} }
	user := must(d.createUser(f.ctx, conn, map[string]any{"userName": "ada@acme.example", "active": "True"}))
	patchBody := func(body string) []operation {
		var b map[string]any
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			t.Fatal(err)
		}
		parsed, err := parsePatch(b)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	user = must(d.patchUser(f.ctx, conn, user, patchBody(
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)))
	if must(d.active(f.ctx, conn, user)) {
		t.Fatal("Entra's \"False\" deactivates")
	}
	user = must(d.patchUser(f.ctx, conn, user, patchBody(
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"True"}]}`)))
	if !must(d.active(f.ctx, conn, user)) {
		t.Fatal("Entra's \"True\" reactivates")
	}
	for _, v := range []any{"on", "1", json.Number("0")} {
		_, err := d.patchUser(f.ctx, conn, user, ops(t, map[string]any{"op": "replace", "path": "active", "value": v}))
		refused(t, err, 400, "active "+fmt.Sprint(v))
	}
}

// members is a multi-valued attribute: a JSON list of {"value": id} (RFC 7643 §4.2).
func TestMembersIsAListOfValueObjects(t *testing.T) {
	ids, err := memberIDs([]any{map[string]any{"value": "u1"}, map[string]any{"value": "u2", "display": "x"}})
	if err != nil || len(ids) != 2 || ids[0] != "u1" || ids[1] != "u2" {
		t.Fatalf("%v %v", ids, err)
	}
	if ids, err := memberIDs([]any{}); err != nil || len(ids) != 0 {
		t.Fatalf("empty list: %v %v", ids, err)
	}
	for _, bad := range []any{map[string]any{}, map[string]any{"0": map[string]any{"value": "u1"}}, []any{"u1"},
		[]any{map[string]any{}}, []any{map[string]any{"value": 7}}, "u1", nil} {
		var e *Error
		if _, err := memberIDs(bad); !errors.As(err, &e) || e.Type != TypeInvalidValue {
			t.Fatalf("%#v: %v", bad, err)
		}
	}
}

// An operation without a path carries an object (RFC 7644 §3.5.2): a list is not one.
func TestAPathlessOperationTakesAnObject(t *testing.T) {
	_, err := parsePatch(map[string]any{"schemas": []any{PatchSchema}, "Operations": []any{
		map[string]any{"op": "add", "value": []any{}},
	}})
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusBadRequest || e.Type != TypeInvalidValue {
		t.Fatalf("a list value: %v", err)
	}
}

// A filter's value is a JSON string (RFC 7644 §3.4.2.2): JSON escapes are decoded, anything else
// (an unknown escape, a raw control character, NUL) is an invalid filter.
func TestFilterValuesAreJSONStrings(t *testing.T) {
	for raw, want := range map[string]string{
		`displayName eq "a \"q\" b"`:   `a "q" b`,
		`displayName eq "back\\slash"`: `back\slash`,
		`displayName eq "café"`:        "café",
		`displayName eq "a\/b"`:        "a/b",
		`displayName eq "tab\there"`:   "tab\there",
		`displayName eq "😀"`:           "\U0001F600",
		"displayName eq \"plain\" \t":  "plain",
		" displayName eq \"x\" ":       "x",
	} {
		f, err := parseFilter(raw)
		if err != nil || len(f) != 1 || f[0].value != want {
			t.Fatalf("%s: %v %v", raw, f, err)
		}
	}
	for _, raw := range []string{`displayName eq "a\0b"`, `displayName eq "a\u0000b"`, `displayName eq "a\xb"`,
		`displayName eq "a\'b"`, "displayName eq \"a\tb\"", "displayName eq \"a\x00b\"", "\x00displayName eq \"x\""} {
		_, err := parseFilter(raw)
		var e *Error
		if !errors.As(err, &e) || e.Status != http.StatusBadRequest || e.Type != TypeInvalidFilter {
			t.Fatalf("%q: %v", raw, err)
		}
	}
}
