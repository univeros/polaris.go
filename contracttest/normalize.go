package contracttest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// The normalizer makes two responses comparable across runs: every value minted per run (ids,
// tokens, secrets, codes, timestamps, rate-limit clocks) collapses to a placeholder. It reproduces
// PHP's tests/Contract/Normalizer.php exactly, including the PHP array semantics the fixtures were
// recorded with (an empty object is an empty list, integer-like keys make a list, lists of records
// are compared as sets). Comments name the PHP rule each step mirrors.

// normalized is a response reduced to its contractual parts.
type normalized struct {
	Status  int                 `json:"status"`
	Headers map[string][]string `json:"headers"`
	Body    any                 `json:"body"`
}

// volatileHeaders are dropped from both sides: their values depend on the wall clock.
var volatileHeaders = []string{"date", "x-ratelimit-reset", "retry-after", "x-ratelimit-remaining"}

// Every pattern ending in `$` in PHP is written `\n?$` here: without the D modifier, PCRE's `$` also
// matches before a final newline.
var (
	queryCodeRe = regexp.MustCompile(`([?&])(sso_code|code|state|nonce|code_challenge|request|user_code)=[A-Za-z0-9_.~%-]+`)
	uuidRe      = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	wholeUUIDRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\n?$`)
	jwtRe       = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\n?$`)
	datetimeRe  = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`)
	opaqueRe    = regexp.MustCompile(`^[A-Za-z0-9_\-+/=]{32,}\n?$`)
	phpIntKeyRe = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
)

// timestampKeys hold epoch claims minted per run (an OAuth introspection, a userinfo document).
var timestampKeys = []string{"exp", "iat", "nbf", "auth_time", "updated_at"}

// maskedKeys are string values that are secrets or per-run identifiers wherever they appear.
var maskedKeys = []string{
	"refresh_token", "token", "secret", "code", "mfa_token", "access_token", "invite_token", "kid",
	"n", "e", "x", "y", "qr", "qr_code", "qr_svg", "otpauth_uri", "uri", "hint", "client_id",
	"client_secret", "user_code", "device_code", "request", "id_token", "auth_req_id",
}

// normalizeResponse is PHP's Normalizer::response: header names lower-cased, volatile headers
// dropped, the multi-session device id and URL hand-off codes masked; the body through value().
func normalizeResponse(status int, headers map[string][]string, body any) normalized {
	out := map[string][]string{}
	for name, values := range headers {
		lower := strings.ToLower(name)
		if slices.Contains(volatileHeaders, lower) {
			continue
		}
		if lower == "x-polaris-device" {
			out[lower] = []string{"<device>"}
			continue
		}
		masked := make([]string, len(values))
		for i, v := range values {
			masked[i] = maskQuery(v)
		}
		out[lower] = masked
	}
	return normalized{Status: status, Headers: out, Body: normalizeValue(body, "")}
}

// maskQuery collapses the per-run parameters of a URL (an OAuth state, nonce, PKCE challenge, a
// hand-off code) to placeholders; `sso_code` is written `<code>`.
func maskQuery(value string) string {
	return queryCodeRe.ReplaceAllStringFunc(value, func(match string) string {
		m := queryCodeRe.FindStringSubmatch(match)
		name := m[2]
		if name == "sso_code" {
			name = "code"
		}
		return m[1] + m[2] + "=<" + name + ">"
	})
}

// normalizeValue is PHP's Normalizer::value over a value decoded by decodeJSON. Objects come out
// as map[string]any, lists as []any.
func normalizeValue(value any, key string) any {
	switch v := value.(type) {
	case object:
		return normalizeArray(v, key)
	case []any:
		members := make(object, len(v))
		for i, item := range v {
			members[i] = member{key: strconv.Itoa(i), intKey: true, value: item}
		}
		return normalizeArray(members, key)
	case int64:
		if slices.Contains(timestampKeys, key) {
			return "<timestamp>"
		}
		return v
	case string:
		return normalizeString(v, key)
	default:
		return v
	}
}

// normalizeArray handles a PHP array: a JSON list or object.
func normalizeArray(members object, key string) any {
	if key == "recovery_codes" || key == "codes" {
		return []any{fmt.Sprintf("<%d codes>", len(members))}
	}
	isList := true
	for i, m := range members {
		if !m.intKey || m.key != strconv.Itoa(i) {
			isList = false
			break
		}
	}
	if !isList {
		out := make(map[string]any, len(members))
		for _, m := range members {
			childKey := m.key
			if m.intKey {
				childKey = key // PHP passes the parent key down for integer keys
			}
			out[m.key] = normalizeValue(m.value, childKey)
		}
		return out
	}
	out := make([]any, len(members))
	allArrays := len(members) > 0
	for i, m := range members {
		out[i] = normalizeValue(m.value, key)
		if !isArray(out[i]) {
			allArrays = false
		}
	}
	if allArrays {
		// 1.0 never ordered its record lists, so the contract holds the set of records, not
		// their order: sort by encoding, as PHP's usort over json_encode does.
		slices.SortStableFunc(out, func(a, b any) int { return strings.Compare(sortKey(a), sortKey(b)) })
	}
	return out
}

func isArray(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}

func sortKey(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v) // only non-finite floats fail to encode
	}
	return string(b)
}

// normalizeString applies PHP's string rules in their order; the first that matches wins.
func normalizeString(value, key string) any {
	// JSON embedded in a string (an MCP tool result's text) is compared decoded: key order is not
	// contractual (decision #4) and Go encodes maps in sorted order.
	if t := strings.TrimSpace(value); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		if decoded, ok := decodeJSON([]byte(t)); ok {
			return normalizeValue(decoded, key)
		}
	}
	if strings.Contains(value, "://") && strings.Contains(value, "=") {
		value = maskQuery(value)
	}
	if wholeUUIDRe.MatchString(value) {
		return "<uuid>"
	}
	// An id inside a longer string (a plugin's URL naming a record) is minted per run too.
	value = uuidRe.ReplaceAllString(value, "<uuid>")
	switch {
	case jwtRe.MatchString(value) && len(value) > 60:
		return "<jwt>"
	case datetimeRe.MatchString(value):
		return "<datetime>"
	case strings.HasPrefix(value, "otpauth://"):
		return "<otpauth>"
	case strings.HasPrefix(value, "data:image/") || strings.HasPrefix(value, "<svg"):
		return "<image>"
	case slices.Contains(maskedKeys, key):
		return "<" + key + ">"
	case opaqueRe.MatchString(value):
		return "<opaque>"
	}
	return value
}

// maskPath replaces the UUIDs of a request path, so a replay's minted ids match the recording's.
func maskPath(path string) string {
	return uuidRe.ReplaceAllString(path, "<uuid>")
}

// object is a decoded JSON object with its member order kept: PHP's json_decode turns integer-like
// keys into integers, and whether an array is a list depends on their order.
type object []member

type member struct {
	key    string
	intKey bool
	value  any
}

// decodeJSON decodes like PHP's json_decode($s, true): objects keep their order, integer literals
// become int64 and other numbers float64. ok is false when data is not exactly one JSON value.
func decodeJSON(data []byte) (v any, ok bool) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, false
	}
	return v, true
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '{' {
			return decodeObject(dec)
		}
		return decodeList(dec)
	case json.Number:
		return phpNumber(t), nil
	default:
		return t, nil // string, bool or nil
	}
}

func decodeObject(dec *json.Decoder) (object, error) {
	obj := object{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := tok.(string) // the decoder only yields a string in key position
		value, err := decodeValue(dec)
		if err != nil {
			return nil, err
		}
		obj = append(obj, member{key: key, intKey: isPHPIntKey(key), value: value})
	}
	_, err := dec.Token() // '}'
	return obj, err
}

func decodeList(dec *json.Decoder) ([]any, error) {
	list := []any{}
	for dec.More() {
		value, err := decodeValue(dec)
		if err != nil {
			return nil, err
		}
		list = append(list, value)
	}
	_, err := dec.Token() // ']'
	return list, err
}

// isPHPIntKey reports whether PHP stores the key as an integer: a canonical decimal in int64 range.
func isPHPIntKey(key string) bool {
	if !phpIntKeyRe.MatchString(key) {
		return false
	}
	_, err := strconv.ParseInt(key, 10, 64)
	return err == nil
}

func phpNumber(n json.Number) any {
	s := n.String()
	if !strings.ContainsAny(s, ".eE") {
		if i, err := strconv.ParseInt(s, 10, 64); err == nil {
			return i
		}
	}
	f, _ := strconv.ParseFloat(s, 64) // overflow gives ±Inf, as PHP's float does
	return f
}

// decodeBody is PHP's `json_decode($body, true) ?? $body`.
func decodeBody(body []byte) any {
	if v, ok := decodeJSON(body); ok && v != nil {
		return v
	}
	return string(body)
}

// headerValues reads a recorded header map: `[]` when PHP had none, else name => list or scalar.
func headerValues(v any) map[string][]string {
	out := map[string][]string{}
	obj, ok := v.(object)
	if !ok {
		return out
	}
	for _, m := range obj {
		list, isList := m.value.([]any)
		if !isList {
			list = []any{m.value}
		}
		values := make([]string, len(list))
		for i, item := range list {
			if s, isString := item.(string); isString {
				values[i] = s
			} else {
				values[i] = fmt.Sprint(item)
			}
		}
		out[m.key] = values
	}
	return out
}
