package observe

import (
	"encoding/json"

	"github.com/univeros/polaris.go/store"
)

// field is one key of an audit row's metadata. A metadata blob is a []field; the keys are written
// in slice order.
type field struct {
	key   string
	value any // string, *string, int, *int, []string or nil
}

// metadataJSON encodes fields as a JSON object with the keys in order, written as every JSON
// column is (store.JSONValue: "/", <, >, & and non-ASCII as they are), {} for no fields, a nil
// list as []. Rows written by releases before decision 64 hold "[]" for no fields and escape "/"
// and non-ASCII; nothing rewrites or re-hashes them, and every JSON reader decodes both forms.
func metadataJSON(fields []field) json.RawMessage {
	b := []byte{'{'}
	for i, f := range fields {
		if i > 0 {
			b = append(b, ',')
		}
		if list, ok := f.value.([]string); ok && list == nil {
			f.value = []string{}
		}
		key, _ := store.JSONValue(f.key)     // a string always encodes
		value, _ := store.JSONValue(f.value) // as does every type field holds
		b = append(append(append(b, key...), ':'), value...)
	}
	return append(b, '}')
}
