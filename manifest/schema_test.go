package manifest

import (
	"encoding/json"
	"testing"
)

// assertJSON compares v, encoded, with the JSON text want, structurally.
func assertJSON(t *testing.T, v any, want string) {
	t.Helper()
	got, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, got, []byte(want)) {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

// Object keeps the key order of the examples, which decides "required".

func TestExampleSchemaScalarsAndNestedObjects(t *testing.T) {
	value := Object{{"data", Object{{"id", "018f"}, {"expires_in", 900}, {"ratio", 0.5}, {"verified", true}, {"label", nil}}}}
	assertJSON(t, exampleSchema(value), `{
		"type": "object",
		"properties": {"data": {
			"type": "object",
			"properties": {
				"id": {"type": "string"},
				"expires_in": {"type": "integer"},
				"ratio": {"type": "number"},
				"verified": {"type": "boolean"},
				"label": {"type": ["string", "null"]}
			},
			"required": ["id", "expires_in", "ratio", "verified", "label"]
		}},
		"required": ["data"]
	}`)
}

func TestExampleSchemaArrayItemsAreMergedWithOptionalAndNullableKeys(t *testing.T) {
	value := []any{
		Object{{"id", "a"}, {"type", "totp"}, {"label", "Phone"}, {"email", "a@example.com"}, {"roles", []any{}}},
		Object{{"id", "b"}, {"type", "sms"}, {"destination", "+1"}, {"email", nil}, {"roles", []any{"owner"}}},
	}
	got := exampleSchema(value).object()
	assertJSON(t, got, `{
		"type": "array",
		"items": {
			"type": "object",
			"properties": {
				"id": {"type": "string"},
				"type": {"type": "string"},
				"label": {"type": "string"},
				"email": {"type": ["null", "string"]},
				"roles": {"type": "array", "items": {"type": "string"}},
				"destination": {"type": "string"}
			},
			"required": ["id", "type", "email", "roles"]
		}
	}`)
	items, _ := got.Get("items")
	keys := []string{}
	properties, _ := items.(Object).Get("properties")
	for _, m := range properties.(Object) {
		keys = append(keys, m.Key)
	}
	if want := []string{"id", "type", "label", "email", "roles", "destination"}; !equalStrings(keys, want) {
		t.Errorf("property order %v, want %v", keys, want)
	}
}

func TestExampleSchemaEmptyArraysAndDisagreeingShapesAreUntyped(t *testing.T) {
	assertJSON(t, exampleSchema([]any{}), `{"type": "array", "items": []}`)
	assertJSON(t, exampleSchema(Object{}), `{"type": "array", "items": []}`)
	assertJSON(t, exampleSchema([]any{Object{{"a", 1}}, "b"}), `{"type": "array", "items": []}`)
	assertJSON(t, exampleSchema([]any{1, "b"}), `{"type": "array", "items": {"type": ["integer", "string"]}}`)
	assertJSON(t, exampleSchema([]any{[]any{1}, []any{"b"}}), `{"type": "array", "items": {"type": "array", "items": {"type": ["integer", "string"]}}}`)
	assertJSON(t, exampleSchema([]any{[]any{1}, 2}), `{"type": "array", "items": []}`)
	assertJSON(t, exampleSchema([]any{1, 2.5, nil, 3}), `{"type": "array", "items": {"type": ["integer", "null", "number"]}}`)
	assertJSON(t, exampleSchema([]any{nil, nil}), `{"type": "array", "items": {"type": ["string", "null"]}}`)
	assertJSON(t, exampleSchema([]any{Object{}, Object{{"a", 1}}}), `{"type": "array", "items": []}`)
}

func TestExampleSchemaSeveralExamplesBecomeAOneOf(t *testing.T) {
	schema := examplesSchema([]Example{
		{"example", Object{{"data", Object{{"token", "x"}}}}},
		{"example_mfa", Object{{"data", Object{{"mfa_required", true}}}}},
	})
	oneOf, ok := schema.Get("oneOf")
	if !ok || len(oneOf.([]any)) != 2 {
		t.Fatalf("oneOf = %v", schema)
	}
	assertJSON(t, oneOf.([]any)[1], `{"type": "object", "properties": {"data": {"type": "object", "properties": {"mfa_required": {"type": "boolean"}}, "required": ["mfa_required"]}}, "required": ["data"]}`)

	single := examplesSchema([]Example{{"example", Object{{"ok", true}}}})
	if _, ok := single.Get("oneOf"); ok {
		t.Error("a single example is not a oneOf")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
