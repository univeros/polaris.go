package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// dateClaims are the registered claims lcobucci/jwt turns into instants.
var dateClaims = [...]string{"iat", "nbf", "exp"}

// segments is a compact JWS split the way lcobucci/jwt's Parser does it.
type segments struct {
	header, claims map[string]any
	signingInput   string
	signature      []byte
}

// splitToken decodes the three segments: exactly two dots, no empty part, strict unpadded
// base64url (libsodium), JSON objects with no empty key, no "enc" header.
func splitToken(raw string) (*segments, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return nil, invalid("the token is not three non-empty dot-separated parts")
	}
	headerJSON, err1 := decodeSegment(parts[0])
	claimsJSON, err2 := decodeSegment(parts[1])
	signature, err3 := decodeSegment(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, invalid("a token part is not valid base64url")
	}
	header, err := decodeObject(headerJSON)
	if err != nil {
		return nil, invalid("the header is not a JSON object: %v", err)
	}
	if _, ok := header["enc"]; ok {
		return nil, invalid("encrypted tokens are not supported")
	}
	claims, err := decodeObject(claimsJSON)
	if err != nil {
		return nil, invalid("the claims are not a JSON object: %v", err)
	}
	if err := normalizeRegistered(claims); err != nil {
		return nil, err
	}
	return &segments{
		header: header, claims: claims, signature: signature,
		signingInput: parts[0] + "." + parts[1],
	}, nil
}

// decodeSegment is sodium_base642bin(URLSAFE_NO_PADDING): no padding, no whitespace, zero
// trailing bits.
func decodeSegment(s string) ([]byte, error) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, invalid("invalid base64url character")
		}
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// decodeObject is json_decode($json, true) for a top-level object: integers that fit int64
// become int64, other numbers float64, objects map[string]any, arrays []any. Malformed UTF-8
// and empty keys are rejected, as lcobucci/jwt does.
func decodeObject(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, fmt.Errorf("malformed UTF-8")
	}
	if err := phpJSONLimits(data); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("not an object")
	}
	if _, empty := obj[""]; empty {
		return nil, fmt.Errorf("empty key")
	}
	return phpValue(obj).(map[string]any), nil
}

// phpMaxDepth is json_decode's default depth: 512 nested containers already fail.
const phpMaxDepth = 512

// phpJSONLimits applies the two json_decode rules encoding/json lacks: the nesting depth
// limit and the refusal of unpaired UTF-16 surrogate escapes (Go would turn them into U+FFFD).
// Syntax errors are left to encoding/json.
func phpJSONLimits(data []byte) error {
	depth, inString := 0, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			switch c {
			case '"':
				inString = true
			case '{', '[':
				if depth++; depth >= phpMaxDepth {
					return fmt.Errorf("maximum stack depth exceeded")
				}
			case '}', ']':
				depth--
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 < len(data) && data[i+1] == 'u' {
				r, ok := hex4(data, i+2)
				if ok && r >= 0xD800 && r <= 0xDFFF {
					low, okLow := rune(0), false
					if r <= 0xDBFF && i+7 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
						low, okLow = hex4(data, i+8)
					}
					if !okLow || low < 0xDC00 || low > 0xDFFF {
						return fmt.Errorf("single unpaired UTF-16 surrogate in unicode escape")
					}
					i += 6 // the low half, checked here
				}
			}
			i++ // skip the escaped character
		}
	}
	return nil
}

func hex4(data []byte, at int) (rune, bool) {
	if at+4 > len(data) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(data[at:at+4]), 16, 16)
	return rune(n), err == nil
}

func phpValue(v any) any {
	switch v := v.(type) {
	case json.Number:
		return phpNumber(string(v))
	case map[string]any:
		for k, e := range v {
			v[k] = phpValue(e)
		}
	case []any:
		for i, e := range v {
			v[i] = phpValue(e)
		}
	}
	return v
}

func phpNumber(s string) any {
	if !strings.ContainsAny(s, ".eE") {
		if n, err := strconv.ParseInt(s, 10, 64); err == nil {
			return n
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil { // out of range: PHP yields ±INF
		if strings.HasPrefix(s, "-") {
			return math.Inf(-1)
		}
		return math.Inf(1)
	}
	return f
}

// normalizeRegistered applies lcobucci/jwt's claim conversions: aud becomes a list
// ((array) cast) and iat/nbf/exp become instants.
func normalizeRegistered(claims map[string]any) error {
	if aud, ok := claims["aud"]; ok {
		claims["aud"] = phpArrayCast(aud)
	}
	for _, name := range dateClaims {
		v, ok := claims[name]
		if !ok {
			continue
		}
		t, err := toInstant(v)
		if err != nil {
			return invalid("the %q claim is not a parseable date: %v", name, err)
		}
		claims[name] = t
	}
	return nil
}

// phpArrayCast is PHP's (array) cast as far as membership is concerned: null is empty, a
// scalar is a one-element list, an object contributes its values.
func phpArrayCast(v any) []any {
	switch v := v.(type) {
	case nil:
		return []any{}
	case []any:
		return v
	case map[string]any:
		out := make([]any, 0, len(v))
		for _, e := range v {
			out = append(out, e)
		}
		return out
	default:
		return []any{v}
	}
}

// phpNumeric is PHP 8's is_numeric for strings.
var phpNumeric = regexp.MustCompile(`^[ \t\n\r\v\f]*[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?[ \t\n\r\v\f]*$`)

// maxUnixSeconds bounds date claims well inside time.Time's range (year ~292 billion), so
// comparisons never wrap; a far-future iat or nbf is then refused as "in the future" would be
// upstream, and a far-future exp is refused rather than trusted.
const maxUnixSeconds = 1 << 62

// toInstant is lcobucci/jwt's Parser::convertDate: an int, float or numeric string,
// formatted with six decimals and read back as "U.u".
func toInstant(v any) (time.Time, error) {
	var f float64
	switch v := v.(type) {
	case int64:
		if v >= maxUnixSeconds || v <= -maxUnixSeconds {
			return time.Time{}, fmt.Errorf("out of range")
		}
		return time.Unix(v, 0).UTC(), nil
	case float64:
		f = v
	case string:
		if !phpNumeric.MatchString(v) {
			return time.Time{}, fmt.Errorf("not numeric")
		}
		parsed, err := strconv.ParseFloat(strings.Trim(v, " \t\n\r\v\f"), 64)
		if err != nil {
			return time.Time{}, err
		}
		f = parsed
	default:
		return time.Time{}, fmt.Errorf("unsupported type %T", v)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return time.Time{}, fmt.Errorf("not finite")
	}
	if f >= maxUnixSeconds || f <= -maxUnixSeconds {
		return time.Time{}, fmt.Errorf("out of range")
	}
	whole, frac, _ := strings.Cut(strconv.FormatFloat(f, 'f', 6, 64), ".")
	sec, err1 := strconv.ParseInt(whole, 10, 64)
	usec, err2 := strconv.ParseInt(frac, 10, 64)
	if err1 != nil || err2 != nil {
		return time.Time{}, fmt.Errorf("out of range")
	}
	// "U.u" adds the microseconds to the (signed) seconds, as PHP does.
	return time.Unix(sec, usec*int64(time.Microsecond)).UTC(), nil
}

// encodeInstant is lcobucci/jwt's MicrosecondBasedDateConversion: whole seconds as an
// integer, otherwise the float of "U.u".
func encodeInstant(t time.Time) any {
	sec, usec := t.Unix(), t.Nanosecond()/int(time.Microsecond)
	if usec == 0 {
		return sec
	}
	f, _ := strconv.ParseFloat(fmt.Sprintf("%d.%06d", sec, usec), 64)
	return f
}
