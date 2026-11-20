package store_test

import (
	"testing"
	"time"

	"github.com/univeros/polaris-go/store"
)

// The driver value shapes rows arrive in: []byte (MySQL), int64, bool, time.Time (pgx, modernc),
// strings ("t" from text protocols), nil.
func TestRowAccessors(t *testing.T) {
	at := time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)
	r := store.Row{
		"bytes": []byte("ada"), "int64": int64(7), "int": 3, "int32": int32(4), "float": 2.0, "text_int": " 12 ",
		"true": true, "false": false, "t": "t", "yes": "YES", "one": []byte("1"), "no": "f", "nil": nil,
		"time": at.In(time.FixedZone("CEST", 7200)), "time_text": []byte("2026-06-07 10:00:00"),
		"time_rfc": "2026-06-07T12:00:00+02:00", "time_frac": "2026-06-07 10:00:00.123456", "bad_time": "soon",
		"json": `{"a":[1,2]}`,
	}
	strings := map[string]string{"bytes": "ada", "int64": "7", "time": "2026-06-07 10:00:00", "nil": "", "missing": ""}
	for col, want := range strings {
		if got := r.String(col); got != want {
			t.Errorf("String(%s) = %q, want %q", col, got, want)
		}
	}
	if _, ok := r.NullString("nil"); ok {
		t.Error("NullString(nil) ok")
	}
	if p := r.StringPtr("bytes"); p == nil || *p != "ada" {
		t.Errorf("StringPtr(bytes) = %v", p)
	}
	if r.StringPtr("nil") != nil {
		t.Error("StringPtr(nil) not nil")
	}
	ints := map[string]int64{"int64": 7, "int": 3, "int32": 4, "float": 2, "true": 1, "false": 0, "nil": 0, "one": 1, "text_int": 12, "bytes": 0}
	for col, want := range ints {
		if got := r.Int(col); got != want {
			t.Errorf("Int(%s) = %d, want %d", col, got, want)
		}
	}
	bools := map[string]bool{"true": true, "false": false, "t": true, "yes": true, "one": true, "no": false, "nil": false, "int64": true, "bytes": false}
	for col, want := range bools {
		if got := r.Bool(col); got != want {
			t.Errorf("Bool(%s) = %v, want %v", col, got, want)
		}
	}
	for _, col := range []string{"time", "time_text", "time_rfc"} {
		if got, ok := r.Time(col); !ok || !got.Equal(at) || got.Location() != time.UTC {
			t.Errorf("Time(%s) = %v, %v", col, got, ok)
		}
	}
	if got, ok := r.Time("time_frac"); !ok || got.Nanosecond() != 123456000 {
		t.Errorf("Time(time_frac) = %v, %v", got, ok)
	}
	for _, col := range []string{"nil", "bad_time"} {
		if _, ok := r.Time(col); ok {
			t.Errorf("Time(%s) ok", col)
		}
	}
	if r.TimePtr("nil") != nil || r.TimePtr("time") == nil {
		t.Error("TimePtr")
	}
	var dst struct{ A []int }
	if err := r.JSON("json", &dst); err != nil || len(dst.A) != 2 {
		t.Errorf("JSON = %v, %v", dst, err)
	}
	if err := r.JSON("nil", &dst); err != nil {
		t.Errorf("JSON(nil) = %v", err)
	}
	if err := r.JSON("bytes", &dst); err == nil {
		t.Error("JSON(bytes) accepted invalid JSON")
	}
}

func TestJSONValueAndNullable(t *testing.T) {
	got, err := store.JSONValue(map[string]any{"url": "https://x.io/a", "name": "José"})
	if err != nil || got != `{"name":"José","url":"https://x.io/a"}` {
		t.Errorf("JSONValue = %s, %v", got, err)
	}
	if _, err := store.JSONValue(func() {}); err == nil {
		t.Error("JSONValue accepted a func")
	}
	s := "x"
	if store.Nullable(&s) != "x" || store.Nullable[string](nil) != nil {
		t.Error("Nullable")
	}
}
