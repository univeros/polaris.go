package store

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// String reads a text column; "" when NULL or absent.
func (r Row) String(col string) string {
	s, _ := r.NullString(col)
	return s
}

// NullString reads a text column; ok is false when NULL or absent.
func (r Row) NullString(col string) (string, bool) {
	switch v := r[col].(type) {
	case nil:
		return "", false
	case string:
		return v, true
	case []byte:
		return string(v), true
	case time.Time:
		return v.UTC().Format(TimeLayout), true
	default:
		return fmt.Sprint(v), true
	}
}

// Int reads an integer column; 0 when NULL or absent.
func (r Row) Int(col string) int64 {
	switch v := r[col].(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case int32:
		return int64(v)
	case float64:
		return int64(v)
	case bool:
		if v {
			return 1
		}
		return 0
	case nil:
		return 0
	default:
		s, _ := r.NullString(col)
		n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		return n
	}
}

// Bool reads a boolean column: true, a non-zero number, or (case-insensitively) "1", "t", "true",
// "y", "yes"; anything else is false.
func (r Row) Bool(col string) bool {
	switch v := r[col].(type) {
	case bool:
		return v
	case nil:
		return false
	case int64, int, int32, float64:
		return r.Int(col) != 0
	default:
		s, _ := r.NullString(col)
		switch strings.ToLower(s) {
		case "1", "t", "true", "y", "yes":
			return true
		}
		return false
	}
}

// Time reads a datetime column as UTC; ok is false when NULL, absent or unparsable.
func (r Row) Time(col string) (time.Time, bool) {
	switch v := r[col].(type) {
	case nil:
		return time.Time{}, false
	case time.Time:
		return v.UTC(), true
	default:
		s, _ := r.NullString(col)
		return ParseTime(s)
	}
}

// TimePtr reads a nullable datetime column.
func (r Row) TimePtr(col string) *time.Time {
	t, ok := r.Time(col)
	if !ok {
		return nil
	}
	return &t
}

// StringPtr reads a nullable text column.
func (r Row) StringPtr(col string) *string {
	s, ok := r.NullString(col)
	if !ok {
		return nil
	}
	return &s
}

// JSON decodes a JSON text column into dst; a NULL column leaves dst untouched.
func (r Row) JSON(col string, dst any) error {
	s, ok := r.NullString(col)
	if !ok || s == "" {
		return nil
	}
	return json.Unmarshal([]byte(s), dst)
}

// ParseTime parses the stored datetime forms (TimeLayout, RFC 3339, with fractional seconds) as UTC.
func ParseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{TimeLayout, "2006-01-02 15:04:05.999999999", time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02 15:04:05-07", "2006-01-02 15:04:05.999999999-07"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// JSONValue encodes v for a JSON column: compact, map keys sorted, slashes, <, >, & and non-ASCII
// written as is, no trailing newline.
func JSONValue(v any) (string, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}

// Nullable returns nil for a nil pointer, else the pointed value; for optional columns in a Row.
func Nullable[T any](p *T) any {
	if p == nil {
		return nil
	}
	return *p
}
