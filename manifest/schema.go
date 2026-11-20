package manifest

import (
	"encoding/json"
	"slices"
)

// jsonSchema is a schema inferred from an example response body: the documented approximation that
// types the success responses of the OpenAPI document. Every key of an object example is
// required; scalars take their JSON type; the items of an array are merged, so a key missing from
// some items is optional and a key null in some is nullable; a value null wherever it appears is a
// nullable string; an empty array has untyped items.
//
// The zero value is the untyped schema (encoded [], as upstream does).
type jsonSchema struct {
	types      []string // "object", "array" or the scalar types; empty when untyped
	properties []property
	required   []string
	items      *jsonSchema
}

type property struct {
	name   string
	schema jsonSchema
}

// examplesSchema is the schema of a route's examples: the one example's, or a oneOf of each.
func examplesSchema(examples []Example) Object {
	if len(examples) == 1 {
		return exampleSchema(examples[0].Value).object()
	}
	oneOf := make([]any, 0, len(examples))
	for _, e := range examples {
		oneOf = append(oneOf, exampleSchema(e.Value).object())
	}
	return Object{{"oneOf", oneOf}}
}

func exampleSchema(value any) jsonSchema {
	return infer(value).finish()
}

func infer(value any) jsonSchema {
	switch v := value.(type) {
	case Object:
		if len(v) == 0 { // upstream cannot tell {} from []
			return inferList(nil)
		}
		s := jsonSchema{types: []string{"object"}}
		for _, m := range v {
			s.properties = append(s.properties, property{m.Key, infer(m.Value)})
			s.required = append(s.required, m.Key)
		}
		return s
	case []any:
		return inferList(v)
	case bool:
		return scalar("boolean")
	case int, int64, uint64:
		return scalar("integer")
	case float64:
		return scalar("number")
	case string:
		return scalar("string")
	}
	return scalar("null")
}

func scalar(t string) jsonSchema {
	return jsonSchema{types: []string{t}}
}

func inferList(list []any) jsonSchema {
	var items jsonSchema
	for _, item := range list {
		items = merge(items, infer(item))
	}
	return jsonSchema{types: []string{"array"}, items: &items}
}

func (s jsonSchema) is(t string) bool {
	return len(s.types) == 1 && s.types[0] == t
}

// merge is the schema of two sibling items: object properties are unioned and required only
// where both require them, array items are merged, scalar types are unioned; an untyped side
// yields the other, and shapes that disagree (an object against a scalar) yield an untyped schema.
func merge(a, b jsonSchema) jsonSchema {
	switch {
	case len(a.types) == 0:
		return b
	case len(b.types) == 0:
		return a
	case a.is("object") && b.is("object"):
		out := jsonSchema{types: a.types, properties: slices.Clone(a.properties)}
		for _, p := range b.properties {
			i := slices.IndexFunc(out.properties, func(q property) bool { return q.name == p.name })
			if i < 0 {
				out.properties = append(out.properties, p)
			} else {
				out.properties[i].schema = merge(out.properties[i].schema, p.schema)
			}
		}
		for _, name := range a.required {
			if slices.Contains(b.required, name) {
				out.required = append(out.required, name)
			}
		}
		return out
	case a.is("array") && b.is("array"):
		items := merge(*a.items, *b.items)
		return jsonSchema{types: a.types, items: &items}
	}
	var types []string
	for _, t := range append(slices.Clone(a.types), b.types...) {
		if t == "object" || t == "array" {
			return jsonSchema{}
		}
		if !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	slices.Sort(types)
	return jsonSchema{types: types}
}

// finish types a value that was null wherever it appeared as a nullable string.
func (s jsonSchema) finish() jsonSchema {
	if s.is("null") {
		return jsonSchema{types: []string{"string", "null"}}
	}
	out := s
	out.properties = make([]property, len(s.properties))
	for i, p := range s.properties {
		out.properties[i] = property{p.name, p.schema.finish()}
	}
	if s.items != nil {
		items := s.items.finish()
		out.items = &items
	}
	return out
}

func (s jsonSchema) object() Object {
	if len(s.types) == 0 {
		return Object{}
	}
	var o Object
	if len(s.types) == 1 {
		o = Object{{"type", s.types[0]}}
	} else {
		o = Object{{"type", slices.Clone(s.types)}}
	}
	if s.is("object") {
		properties := make(Object, 0, len(s.properties))
		for _, p := range s.properties {
			properties = append(properties, Member{p.name, p.schema.object()})
		}
		o = append(o, Member{"properties", properties})
		if len(s.required) > 0 {
			o = append(o, Member{"required", slices.Clone(s.required)})
		}
	}
	if s.items != nil {
		o = append(o, Member{"items", s.items.object()})
	}
	return o
}

// MarshalJSON encodes the schema as upstream does.
func (s jsonSchema) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.object())
}
