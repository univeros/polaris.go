package manifest

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// The goldens are the PHP CLI's output at the pinned ref (internal/upstream/REF), from ../polaris-core:
//
//	php bin/polaris manifest --format=json      > core.json
//	php bin/polaris manifest --format=openapi   > core.openapi.json
//	php bin/polaris manifest --format=json    --bootstrap=packages/client-ts/polaris.php > all.json
//	php bin/polaris manifest --format=openapi --bootstrap=packages/client-ts/polaris.php > all.openapi.json
func TestExportsMatchThePHPGoldens(t *testing.T) {
	core, all := loadCore(t), loadAll(t)
	cases := []struct {
		golden string
		doc    Object
	}{
		{"core.json", core.Export()},
		{"core.openapi.json", core.OpenAPI(UpstreamVersion)},
		{"all.json", all.Export()},
		{"all.openapi.json", all.OpenAPI(UpstreamVersion)},
	}
	for _, c := range cases {
		t.Run(c.golden, func(t *testing.T) {
			want, err := os.ReadFile("../testdata/manifest/" + c.golden)
			if err != nil {
				t.Fatal(err)
			}
			got, err := json.Marshal(c.doc)
			if err != nil {
				t.Fatal(err)
			}
			if !jsonEqual(t, got, want) {
				diff(t, "", decode(t, got), decode(t, want))
			}
		})
	}
}

func decode(t *testing.T, data []byte) any {
	t.Helper()
	var v any
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return normalizeNumbers(v)
}

// normalizeNumbers makes 1 and 1.0 equal, as they are in JSON.
func normalizeNumbers(v any) any {
	switch v := v.(type) {
	case json.Number:
		f, _ := v.Float64()
		return f
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			out[k] = normalizeNumbers(x)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, x := range v {
			out[i] = normalizeNumbers(x)
		}
		return out
	}
	return v
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	return reflect.DeepEqual(decode(t, a), decode(t, b))
}

// diff reports the first few differing paths.
func diff(t *testing.T, path string, got, want any) {
	t.Helper()
	gm, gok := got.(map[string]any)
	wm, wok := want.(map[string]any)
	if gok && wok {
		for k := range wm {
			if _, ok := gm[k]; !ok {
				t.Errorf("%s/%s: missing", path, k)
			}
		}
		for k, v := range gm {
			w, ok := wm[k]
			if !ok {
				t.Errorf("%s/%s: unexpected", path, k)
				continue
			}
			diff(t, path+"/"+k, v, w)
		}
		return
	}
	gl, gok := got.([]any)
	wl, wok := want.([]any)
	if gok && wok && len(gl) == len(wl) {
		for i := range gl {
			diff(t, path+"/"+string(rune('0'+i%10)), gl[i], wl[i])
		}
		return
	}
	if !reflect.DeepEqual(got, want) {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		t.Errorf("%s:\n got  %s\n want %s", path, g, w)
	}
}

func TestObjectEncoding(t *testing.T) {
	cases := map[string]Object{
		`[]`:               {},
		`{"a":1,"b":[]}`:   {{"a", 1}, {"b", Object{}}},
		`{"b":2,"a":null}`: {{"b", 2}, {"a", nil}},
	}
	for want, o := range cases {
		got, err := json.Marshal(o)
		if err != nil || string(got) != want {
			t.Errorf("%v: %s %v, want %s", o, got, err, want)
		}
	}
	if _, err := json.Marshal(Object{{"a", make(chan int)}}); err == nil {
		t.Error("an unencodable value must fail")
	}
	o := Object{{"a", 1}}
	if v, ok := o.Get("a"); !ok || v != 1 {
		t.Error("Get(a)")
	}
	if _, ok := o.Get("b"); ok {
		t.Error("Get(b)")
	}
	set := o.With("a", 2).With("b", 3)
	if v, _ := o.Get("a"); v != 1 || len(o) != 1 {
		t.Error("With mutated the receiver")
	}
	if !reflect.DeepEqual(set, Object{{"a", 2}, {"b", 3}}) {
		t.Errorf("With: %v", set)
	}
}
