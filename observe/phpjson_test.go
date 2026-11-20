package observe

import "testing"

// The expectations are PHP 8's json_encode output with default flags.
func TestPHPJSONMatchesJSONEncode(t *testing.T) {
	for _, tc := range []struct {
		fields []field
		want   string
	}{
		{nil, `[]`},
		{[]field{{"a/b", "é😀\x01\x7f\"\\\n\b\f\r\t"}}, "{\"a\\/b\":\"\\u00e9\\ud83d\\ude00\\u0001\x7f\\\"\\\\\\n\\b\\f\\r\\t\"}"},
		{[]field{{"n", nil}, {"l", []string{}}, {"i", -3}}, `{"n":null,"l":[],"i":-3}`},
		{[]field{{"u", "\u2028<>&'\ufffd"}}, `{"u":"\u2028<>&'\ufffd"}`},
		{[]field{{"s", (*string)(nil)}, {"p", ptr("x")}, {"c", (*int)(nil)}, {"d", ptr(0)}}, `{"s":null,"p":"x","c":null,"d":0}`},
		{[]field{{"l", []string(nil)}, {"m", []string{"a", "b/c"}}}, `{"l":[],"m":["a","b\/c"]}`},
		// Invalid UTF-8 anywhere: PHP throws, upstream writes "{}".
		{[]field{{"x", "\xff"}}, `{}`},
		{[]field{{"\xed\xa0\x80", "lone surrogate"}}, `{}`},
		{[]field{{"l", []string{"ok", "\xc3"}}}, `{}`},
	} {
		if got := string(phpJSON(tc.fields)); got != tc.want {
			t.Errorf("phpJSON(%q) = %s; want %s", tc.fields, got, tc.want)
		}
	}
}
