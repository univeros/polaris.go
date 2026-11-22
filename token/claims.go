package token

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"unicode/utf8"
)

// Claims is an ordered set of JWT claims. Names keep the position they were first set at, so
// a payload is byte-identical to one minted by an earlier release for the same claims.
// The zero value is empty and ready to use; With returns a new set and never changes the
// receiver.
//
// Values may be nil, string, bool, any integer type, float64, []string, []any,
// map[string]any (encoded with sorted keys), Claims (encoded in order) or json.RawMessage.
// Call MarshalJSON directly for the exact wire bytes: json.Marshal re-escapes <, > and &.
type Claims struct {
	names  []string
	values map[string]any
}

// With returns a copy of c with name set to value. Re-setting a name keeps its position.
func (c Claims) With(name string, value any) Claims {
	out := Claims{names: c.names, values: make(map[string]any, len(c.values)+1)}
	for k, v := range c.values {
		out.values[k] = v
	}
	if _, ok := c.values[name]; !ok {
		out.names = append(slices.Clip(c.names), name)
	}
	out.values[name] = value
	return out
}

// Get returns the value of name and whether it is set.
func (c Claims) Get(name string) (any, bool) {
	v, ok := c.values[name]
	return v, ok
}

// Names returns the claim names in order.
func (c Claims) Names() []string { return slices.Clone(c.names) }

// Len returns the number of claims.
func (c Claims) Len() int { return len(c.names) }

// MarshalJSON encodes c as a JSON object in claim order, with "/" and non-ASCII characters
// left unescaped (see encodeString) and floats in encoding/json's form; an empty set encodes as {}.
func (c Claims) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeOrderedObject(&buf, c.names, c.values); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var errUnencodable = errors.New("token: claim value cannot be encoded")

// encodeOrderedObject writes names (in order) and their values as a JSON object. Tokens issued
// before decision 64 wrote an empty object as []; they verify over their own bytes, so the
// encoding of new tokens is free to differ.
func encodeOrderedObject(buf *bytes.Buffer, names []string, values map[string]any) error {
	buf.WriteByte('{')
	for i, name := range names {
		if i > 0 {
			buf.WriteByte(',')
		}
		if err := encodeString(buf, name); err != nil {
			return err
		}
		buf.WriteByte(':')
		if err := encodeValue(buf, values[name]); err != nil {
			return fmt.Errorf("claim %q: %w", name, err)
		}
	}
	buf.WriteByte('}')
	return nil
}

// encodeValue writes one claim value; the Claims doc lists the types it takes.
func encodeValue(buf *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		return encodeString(buf, v)
	case bool:
		buf.WriteString(strconv.FormatBool(v))
	case int:
		buf.WriteString(strconv.FormatInt(int64(v), 10))
	case int8, int16, int32, int64, uint8, uint16, uint32:
		fmt.Fprintf(buf, "%d", v)
	case uint, uint64:
		n := toUint64(v)
		if n > math.MaxInt64 {
			return fmt.Errorf("%w: %d overflows int64", errUnencodable, n)
		}
		buf.WriteString(strconv.FormatUint(n, 10))
	case float64:
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return fmt.Errorf("%w: Inf and NaN cannot be JSON encoded", errUnencodable)
		}
		s, _ := json.Marshal(v) // finite floats always encode
		buf.Write(s)
	case []string:
		buf.WriteByte('[')
		for i, s := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeString(buf, s); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case []any:
		buf.WriteByte('[')
		for i, e := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeValue(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		names := make([]string, 0, len(v))
		for k := range v {
			names = append(names, k)
		}
		slices.Sort(names)
		return encodeOrderedObject(buf, names, v)
	case Claims:
		return encodeOrderedObject(buf, v.names, v.values)
	case json.RawMessage:
		if !json.Valid(v) {
			return fmt.Errorf("%w: invalid raw JSON", errUnencodable)
		}
		buf.Write(v)
	default:
		return fmt.Errorf("%w: unsupported type %T", errUnencodable, v)
	}
	return nil
}

func toUint64(v any) uint64 {
	if u, ok := v.(uint); ok {
		return uint64(u)
	}
	return v.(uint64)
}

// encodeString writes s as a JSON string with minimal escaping: only ", \, control characters
// and U+2028/U+2029 are escaped ("/" and other non-ASCII stay as they are); invalid UTF-8 is
// an error.
func encodeString(buf *bytes.Buffer, s string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: malformed UTF-8", errUnencodable)
	}
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return err
	}
	// encoding/json already escapes exactly that set the same way (\b \f \n \r \t, \u00XX
	// lower-case,    ); drop the trailing newline Encode adds.
	buf.Write(bytes.TrimSuffix(tmp.Bytes(), []byte("\n")))
	return nil
}
