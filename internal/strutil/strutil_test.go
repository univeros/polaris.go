package strutil

import "testing"

func TestTrimStripsOnlyItsSixEdgeBytes(t *testing.T) {
	for in, want := range map[string]string{
		" \t\n\r\x00\x0Bada\x0B\x00\r\n\t ": "ada",
		"\fada\f":                          "\fada\f", // form feed stays
		" ada ":                  " ada ",
		"a b":                              "a b",
		"":                                 "",
		"\xff ":                            "\xff",
	} {
		if got := Trim(in); got != want {
			t.Errorf("Trim(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPercentEncodeKeepsOnlyUnreservedCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"a b+c/~":          "a%20b%2Bc%2F~",
		"AZaz09-_.~":       "AZaz09-_.~",
		"Polaris:ada@x.io": "Polaris%3Aada%40x.io",
		"é":                "%C3%A9",
		"!*'();&=$,?#[]%":  "%21%2A%27%28%29%3B%26%3D%24%2C%3F%23%5B%5D%25",
	} {
		if got := PercentEncode(in); got != want {
			t.Errorf("PercentEncode(%q) = %q, want %q", in, got, want)
		}
	}
}
