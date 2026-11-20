package store

import "reflect"

// Values flattens a slice criterion ([]any, []string, []int64, any slice but []byte) into its
// elements; ok is false when v is not such a slice. Adapters use it to read IN criteria.
func Values(v any) (values []any, ok bool) {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice || rv.Type().Elem().Kind() == reflect.Uint8 {
		return nil, false
	}
	values = make([]any, rv.Len())
	for i := range values {
		values[i] = rv.Index(i).Interface()
	}
	return values, true
}
