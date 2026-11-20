package store_test

import (
	"reflect"
	"testing"

	"github.com/univeros/polaris-go/store"
)

func TestValues(t *testing.T) {
	cases := []struct {
		in   any
		want []any
		ok   bool
	}{
		{[]string{"a", "b"}, []any{"a", "b"}, true},
		{[]int64{}, []any{}, true},
		{[]any{1, "x"}, []any{1, "x"}, true},
		{[]byte("raw"), nil, false},
		{"scalar", nil, false},
		{nil, nil, false},
	}
	for _, tc := range cases {
		got, ok := store.Values(tc.in)
		if ok != tc.ok || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Values(%#v) = %#v, %v; want %#v, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
