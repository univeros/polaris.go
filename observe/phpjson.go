package observe

import (
	"encoding/json"
	"strconv"
	"unicode/utf8"
)

// field is one key of an audit row's metadata. A metadata blob is a []field in the order of the
// upstream PHP array literal, which json_encode preserves.
type field struct {
	key   string
	value any // string, *string, int, *int, []string or nil
}

const hexDigits = "0123456789abcdef"

// phpJSON encodes fields exactly as PHP's json_encode with default flags: keys in order, "/"
// escaped as "\/", every non-ASCII character as a lowercase \uXXXX escape (surrogate pairs above
// the BMP), "[]" for no fields. Like PHP with JSON_THROW_ON_ERROR caught upstream, a string that is
// not valid UTF-8 makes the whole blob "{}".
func phpJSON(fields []field) json.RawMessage {
	if len(fields) == 0 {
		return json.RawMessage("[]")
	}
	b := []byte{'{'}
	for i, f := range fields {
		if i > 0 {
			b = append(b, ',')
		}
		var ok bool
		if b, ok = appendString(b, f.key); !ok {
			return json.RawMessage("{}")
		}
		b = append(b, ':')
		if b, ok = appendValue(b, f.value); !ok {
			return json.RawMessage("{}")
		}
	}
	return append(b, '}')
}

func appendValue(b []byte, v any) ([]byte, bool) {
	switch v := v.(type) {
	case string:
		return appendString(b, v)
	case *string:
		if v != nil {
			return appendString(b, *v)
		}
	case int:
		return strconv.AppendInt(b, int64(v), 10), true
	case *int:
		if v != nil {
			return strconv.AppendInt(b, int64(*v), 10), true
		}
	case []string:
		b = append(b, '[')
		for i, s := range v {
			if i > 0 {
				b = append(b, ',')
			}
			var ok bool
			if b, ok = appendString(b, s); !ok {
				return b, false
			}
		}
		return append(b, ']'), true
	}
	return append(b, "null"...), true
}

func appendString(b []byte, s string) ([]byte, bool) {
	b = append(b, '"')
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return b, false
		}
		i += size
		switch {
		case r == '"' || r == '\\' || r == '/':
			b = append(b, '\\', byte(r))
		case r == '\b':
			b = append(b, `\b`...)
		case r == '\f':
			b = append(b, `\f`...)
		case r == '\n':
			b = append(b, `\n`...)
		case r == '\r':
			b = append(b, `\r`...)
		case r == '\t':
			b = append(b, `\t`...)
		case r < 0x20 || r >= utf8.RuneSelf && r < 0x10000:
			b = appendU(b, r)
		case r >= 0x10000:
			r -= 0x10000
			b = appendU(appendU(b, 0xd800+(r>>10)), 0xdc00+(r&0x3ff))
		default:
			b = append(b, byte(r))
		}
	}
	return append(b, '"'), true
}

func appendU(b []byte, r rune) []byte {
	return append(b, '\\', 'u', hexDigits[r>>12&0xf], hexDigits[r>>8&0xf], hexDigits[r>>4&0xf], hexDigits[r&0xf])
}
