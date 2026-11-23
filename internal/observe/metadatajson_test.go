package observe

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/storetest"
)

// The metadata is standard JSON: keys in field order, "/" and non-ASCII written as they are,
// {} for no fields.
func TestMetadataJSONIsStandardJSONInFieldOrder(t *testing.T) {
	for _, tc := range []struct {
		fields []field
		want   string
	}{
		{nil, `{}`},
		{[]field{{"a/b", "é😀\x01\"\\\n"}}, "{\"a/b\":\"é😀\\u0001\\\"\\\\\\n\"}"},
		{[]field{{"n", nil}, {"l", []string{}}, {"i", -3}}, `{"n":null,"l":[],"i":-3}`},
		{[]field{{"u", "<>&'"}}, `{"u":"<>&'"}`},
		{[]field{{"s", (*string)(nil)}, {"p", ptr("x")}, {"c", (*int)(nil)}, {"d", ptr(0)}}, `{"s":null,"p":"x","c":null,"d":0}`},
		{[]field{{"l", []string(nil)}, {"m", []string{"a", "b/c"}}}, `{"l":[],"m":["a","b/c"]}`},
		{[]field{{"x", "\xff"}}, "{\"x\":\"\uFFFD\"}"}, // invalid UTF-8 is replaced
	} {
		// Go 1.26 writes the replacement character as an escape, Go 1.27 as it is.
		got := bytes.ReplaceAll(metadataJSON(tc.fields), []byte(`\ufffd`), []byte("\uFFFD"))
		if string(got) != tc.want {
			t.Errorf("metadataJSON(%q) = %s; want %s", tc.fields, got, tc.want)
		}
		if !json.Valid(got) {
			t.Errorf("metadataJSON(%q) is not valid JSON", tc.fields)
		}
	}
}

// Rows written by earlier releases ("[]" for no fields, "/" escaped, non-ASCII as \u escapes,
// "+00:00" offsets) read back unchanged and decode to the same values as the rows written now.
func TestAuditRowsOfEarlierReleasesStillRead(t *testing.T) {
	storetest.Each(t, func(t *testing.T, db store.Adapter) {
		r := repository.New(db)
		old := []string{`[]`, `{"slug":"a\/b","name":"é"}`, `{"until":"2026-06-10T12:15:00+00:00"}`}
		for i, meta := range old {
			must(t, r.AuditLog.Insert(ctx, model.AuditLogEntry{ID: repository.NewID(), Event: "org.created", Metadata: json.RawMessage(meta), CreatedAt: now.Add(time.Duration(i) * time.Second)}))
		}
		rows, err := r.AuditLog.Find(ctx, nil, store.Query{OrderBy: []store.Order{{Column: "created_at"}}})
		must(t, err)
		if len(rows) != len(old) {
			t.Fatalf("rows = %d", len(rows))
		}
		for i, meta := range old {
			var got, want any
			if json.Unmarshal(rows[i].Metadata, &got) != nil || json.Unmarshal([]byte(meta), &want) != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("row %d metadata = %s; want %s", i, rows[i].Metadata, meta)
			}
		}
		var a, b any
		must(t, json.Unmarshal(rows[1].Metadata, &a))
		must(t, json.Unmarshal(metadataJSON([]field{{"slug", "a/b"}, {"name", "é"}}), &b))
		if !reflect.DeepEqual(a, b) {
			t.Errorf("old row %v and new row %v differ", a, b)
		}
	})
}
