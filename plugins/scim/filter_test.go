package scim

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The filter subset and the PatchOp parsing (upstream FilterAndPatchTest).
func TestFilterAndPatch(t *testing.T) {
	t.Run("testFiltersParseAndMatch", func(t *testing.T) {
		f, err := parseFilter(`userName eq "Ada@Example.com" and displayName co "ada" and externalId sw "ext-"`)
		if err != nil || len(f) != 3 || f[0] != (clause{"username", "eq", "Ada@Example.com"}) {
			t.Fatalf("parsed %v, %v", f, err)
		}
		if !f.matches(map[string][]string{"username": {"ada@example.com"}, "displayname": {"Ada Lovelace"}, "externalid": {"ext-1"}}) {
			t.Fatal("a matching resource does not match")
		}
		if f.matches(map[string][]string{"username": {"ada@example.com"}, "displayname": {"Ada Lovelace"}, "externalid": {"other"}}) {
			t.Fatal("sw matched")
		}
		mustMatch := func(raw string, attrs map[string][]string) {
			t.Helper()
			f, err := parseFilter(raw)
			if err != nil || !f.matches(attrs) {
				t.Fatalf("%s: %v %v", raw, f, err)
			}
		}
		mustMatch(`emails[type eq "work"].value eq "ada@example.com"`, map[string][]string{"emails": {"ada@example.com"}})
		mustMatch(`active eq "true"`, map[string][]string{"active": {"true"}})
		mustMatch("", nil)
		mustMatch(" \t", nil)
		if f, _ := parseFilter(`displayName eq "a \"quoted\" one"`); f[0].value != `a "quoted" one` {
			t.Fatalf("unescaped %q", f[0].value)
		}
		if f, _ := parseFilter(`userName EQ "x" AND displayName Sw "y"`); len(f) != 2 || f[1].operator != "sw" {
			t.Fatalf("case-insensitive %v", f)
		}
		for _, bad := range []string{"userName pr", "userName eq ada", `userName gt "a"`, `userName eq "a" or displayName eq "b"`, "garbage",
			`userName eq "a" and`, `x userName eq "a"`, `userName eq "a" garbage`} {
			_, err := parseFilter(bad)
			var e *Error
			if !errors.As(err, &e) || e.Status != 400 || e.Type != TypeInvalidFilter {
				t.Fatalf("%s: %v", bad, err)
			}
		}
	})

	t.Run("testPatchOperationsParseAndExposeScalars", func(t *testing.T) {
		ops, err := parsePatch(map[string]any{"schemas": []any{PatchSchema}, "Operations": []any{
			map[string]any{"op": "Replace", "path": "active", "value": false},
			map[string]any{"op": "add", "value": map[string]any{"userName": "bob@example.com", "name": map[string]any{"givenName": "Bob"},
				"urn:ietf:params:scim:schemas:core:2.0:User:displayName": "Bobby"}},
			map[string]any{"op": "remove", "path": `members[value eq "u1"]`},
		}})
		if err != nil {
			t.Fatal(err)
		}
		if ops[0] != (operation{"replace", "active", false}) || ops[0].scalar("active") != false || ops[0].scalar("userName") != nil {
			t.Fatalf("op 0 %v", ops[0])
		}
		for attribute, want := range map[string]any{"userName": "bob@example.com", "name.givenName": "Bob", "displayName": "Bobby", "name.familyName": nil} {
			if got := ops[1].scalar(attribute); got != want {
				t.Fatalf("%s: %v, want %v", attribute, got, want)
			}
		}
		if !reflect.DeepEqual(ops[2], operation{"remove", `members[value eq "u1"]`, nil}) {
			t.Fatalf("op 2 %v", ops[2])
		}
		if stripURN("urn:ietf:params:scim:schemas:core:2.0:Group:displayName") != "displayName" {
			t.Fatal("stripURN")
		}
		for i, bad := range []map[string]any{
			{},
			{"schemas": []any{PatchSchema}},
			{"schemas": []any{PatchSchema}, "Operations": []any{map[string]any{"op": "merge"}}},
			{"schemas": []any{PatchSchema}, "Operations": []any{map[string]any{"op": "add", "value": "flat"}}},
			{"schemas": []any{PatchSchema}, "Operations": []any{map[string]any{"op": "add", "path": "???", "value": 1}}},
		} {
			var e *Error
			if _, err := parsePatch(bad); !errors.As(err, &e) || e.Status != 400 {
				t.Fatalf("bad %d parsed: %v", i, err)
			}
		}
	})
}

func TestStripSlashesAndBooleans(t *testing.T) {
	for in, want := range map[string]string{`a\"b`: `a"b`, `a\\b`: `a\b`, `a\0b`: "a\x00b", `ab\`: "ab", "plain": "plain"} {
		if got := stripSlashes(in); got != want {
			t.Fatalf("stripSlashes(%q) = %q, want %q", in, got, want)
		}
	}
	for v, want := range map[any]bool{true: true, false: false, "True": true, " yes ": true, "on": true, "0": false, "no": false, 3: false} {
		if phpBool(v) != want {
			t.Fatalf("phpBool(%v) != %v", v, want)
		}
	}
}

// FuzzFilter: the parser never panics, and what it accepts re-parses to the same clauses when
// written back in the canonical form.
func FuzzFilter(f *testing.F) {
	for _, seed := range []string{`userName eq "ada@example.com"`, `displayName co "a \"q\" b" and externalId sw "x"`,
		`emails[type eq "work"].value eq "a"`, "userName pr", "", `a eq "\`, "a eq \"b\"\vand\vc sw \"d\""} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		parsed, err := parseFilter(raw)
		if err != nil {
			if e, ok := asError(err); !ok || e.Type != TypeInvalidFilter {
				t.Fatalf("%q: %v", raw, err)
			}
			return
		}
		parts := make([]string, len(parsed))
		for i, c := range parsed {
			if c.operator != "eq" && c.operator != "co" && c.operator != "sw" {
				t.Fatalf("%q: operator %q", raw, c.operator)
			}
			if strings.ContainsRune(c.value, 0) {
				return // NUL has no escape in the canonical form
			}
			attr := c.attribute
			if attr == "" || attr != strings.ToLower(attr) {
				t.Fatalf("%q: attribute %q", raw, attr)
			}
			escaped := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(c.value)
			parts[i] = attr + " " + c.operator + ` "` + escaped + `"`
		}
		again, err := parseFilter(strings.Join(parts, " and "))
		if err != nil || !reflect.DeepEqual(again, parsed) {
			t.Fatalf("%q: canonical form re-parses to %v (%v), want %v", raw, again, err, parsed)
		}
		_ = parsed.matches(map[string][]string{"username": {raw}})
	})
}
