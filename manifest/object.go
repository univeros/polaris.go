package manifest

import (
	"bytes"
	"encoding/json"
)

// Member is one key and value of an [Object].
type Member struct {
	Key   string
	Value any
}

// Object is a JSON object that keeps its key order: the YAML mappings of a spec's output examples
// and the documents [Manifest.OpenAPI] and [Manifest.Export] build. Order matters where the
// manifest derives lists from keys (an inferred schema's "required").
//
// An empty Object encodes as [], not {}: the exported documents have always written an empty map
// as an empty list, and clients of them keep reading that form (an untyped schema is "items": []).
type Object []Member

// Get returns the value under key.
func (o Object) Get(key string) (any, bool) {
	for _, m := range o {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}

// With returns a copy of o with key set to value, in place when the key exists, last otherwise.
func (o Object) With(key string, value any) Object {
	out := make(Object, len(o), len(o)+1)
	copy(out, o)
	for i := range out {
		if out[i].Key == key {
			out[i].Value = value
			return out
		}
	}
	return append(out, Member{key, value})
}

// MarshalJSON encodes o with its keys in order.
func (o Object) MarshalJSON() ([]byte, error) {
	if len(o) == 0 {
		return []byte("[]"), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, m := range o {
		if i > 0 {
			buf.WriteByte(',')
		}
		key, _ := json.Marshal(m.Key) // a string always encodes
		value, err := json.Marshal(m.Value)
		if err != nil {
			return nil, err
		}
		buf.Write(key)
		buf.WriteByte(':')
		buf.Write(value)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
