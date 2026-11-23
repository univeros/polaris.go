package strictjson

import (
	"encoding/json"
	"testing"
)

func TestDecodeReadsOneValueAndNothingAfterIt(t *testing.T) {
	for data, ok := range map[string]bool{`{"a":1}`: true, " {\"a\":1}\r\n\t ": true, `{"a":1}0`: false, `{"a":1}{"a":2}`: false,
		`{"a":1}]`: false, `{"a":1}}`: false, `{"a":1}x`: false, `{"a":1}` + "\x00": false, `{`: false, ``: false} {
		var out map[string]any
		if err := Decode([]byte(data), &out); (err == nil) != ok {
			t.Errorf("%q: %v", data, err)
		} else if n, _ := out["a"].(json.Number); ok && n != "1" {
			t.Errorf("%q: %v", data, out)
		}
	}
}
