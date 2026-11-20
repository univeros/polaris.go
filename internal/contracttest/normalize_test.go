package contracttest

import (
	"fmt"
	"math"
	"net/http"
	"reflect"
	"testing"
)

const testUUID = "0190a8b2-1234-7abc-8def-0123456789ab"

func normalizeJSON(t *testing.T, src string) any {
	t.Helper()
	v, ok := decodeJSON([]byte(src))
	if !ok {
		t.Fatalf("invalid JSON %q", src)
	}
	return normalizeValue(v, "")
}

func TestNormalizeValue(t *testing.T) {
	jwt := "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2F1dGgifQ.c2lnbmF0dXJlc2lnbmF0dXJl"
	cases := []struct {
		name string
		in   string
		want any
	}{
		{"uuid", `{"id":"` + testUUID + `"}`, map[string]any{"id": "<uuid>"}},
		{"uuid upper case", `"0190A8B2-1234-7ABC-8DEF-0123456789AB"`, "<uuid>"},
		{"uuid before a final newline (PCRE $)", `"` + testUUID + `\n"`, "<uuid>"},
		{"uuid inside a string", `"/orgs/` + testUUID + `/members"`, "/orgs/<uuid>/members"},
		{"jwt", `"` + jwt + `"`, "<jwt>"},
		{"short dotted string", `{"v":"a.b.c"}`, map[string]any{"v": "a.b.c"}},
		{"datetime", `["2026-09-10 12:00:00","2026-09-10T12:00:00+00:00"]`, []any{"<datetime>", "<datetime>"}},
		{"otpauth", `"otpauth://totp/Polaris:ada?secret=ABC&issuer=Polaris"`, "<otpauth>"},
		{"data image", `"data:image/png;base64,AAAA"`, "<image>"},
		{"svg", `"<svg xmlns=\"x\"/>"`, "<image>"},
		{"masked key", `{"token":"abc","n":"x","client_id":"c1","name":"ada"}`, map[string]any{"token": "<token>", "n": "<n>", "client_id": "<client_id>", "name": "ada"}},
		{"masked key in a list inherits the key", `{"token":["a","b"]}`, map[string]any{"token": []any{"<token>", "<token>"}}},
		{"opaque", `"` + "abcdefghijklmnopqrstuvwxyz012345" + `"`, "<opaque>"},
		{"not opaque under 32", `"` + "abcdefghijklmnopqrstuvwxyz01234" + `"`, "abcdefghijklmnopqrstuvwxyz01234"},
		{"masked phone kept", `"+1 *** *** 1234"`, "+1 *** *** 1234"},
		{"recovery codes counted", `{"recovery_codes":["a","b","c"]}`, map[string]any{"recovery_codes": []any{"<3 codes>"}}},
		{"empty codes object", `{"codes":{}}`, map[string]any{"codes": []any{"<0 codes>"}}},
		{"epoch claim", `{"exp":1789163153,"iat":1,"count":3}`, map[string]any{"exp": "<timestamp>", "iat": "<timestamp>", "count": int64(3)}},
		{"float epoch kept", `{"exp":1789.5}`, map[string]any{"exp": 1789.5}},
		{"float stays float", `{"v":5.0}`, map[string]any{"v": 5.0}},
		{"huge integer is a float", `99999999999999999999`, 1e20},
		{"query codes", `{"r":"https://x.test/cb?code=abc&state=xyz&other=1"}`, map[string]any{"r": "https://x.test/cb?code=<code>&state=<state>&other=1"}},
		{"sso code", `"https://app.example/done?sso_code=Abc-123"`, "https://app.example/done?sso_code=<code>"},
		{"code challenge", `"https://x.test/a?code_challenge=abc&nonce=n1&request=r&user_code=U"`, "https://x.test/a?code_challenge=<code_challenge>&nonce=<nonce>&request=<request>&user_code=<user_code>"},
		{"empty object is an empty list", `{"data":{}}`, map[string]any{"data": []any{}}},
		{"integer keys in order make a list", `{"0":"a","1":"b"}`, []any{"a", "b"}},
		{"integer keys out of order stay an object", `{"1":"a","0":"b"}`, map[string]any{"1": "a", "0": "b"}},
		{"integer key passes the parent key", `{"token":{"5":"abc","k":"v"}}`, map[string]any{"token": map[string]any{"5": "<token>", "k": "v"}}},
		{"non-canonical integer key is a string", `{"01":"a"}`, map[string]any{"01": "a"}},
		{"record list is a set", `[{"b":2},{"a":1}]`, []any{map[string]any{"a": int64(1)}, map[string]any{"b": int64(2)}}},
		{"mixed list keeps its order", `[{"b":2},1]`, []any{map[string]any{"b": int64(2)}, int64(1)}},
		{"scalars", `[true,null,"x"]`, []any{true, nil, "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeJSON(t, tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestRecordListsCompareAsSets(t *testing.T) {
	a := normalizeJSON(t, `{"data":[{"id":"x","roles":["owner"]},{"id":"y","roles":[]}]}`)
	b := normalizeJSON(t, `{"data":[{"roles":{},"id":"y"},{"roles":["owner"],"id":"x"}]}`)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("%#v != %#v", a, b)
	}
}

func TestDecodeJSON(t *testing.T) {
	for _, bad := range []string{"", "{", `{"a":1} {}`, "nope", `{"a":}`, `[1,]`} {
		if _, ok := decodeJSON([]byte(bad)); ok {
			t.Errorf("%q decoded", bad)
		}
	}
	if v, ok := decodeJSON([]byte(" 1e400 ")); !ok || !math.IsInf(v.(float64), 1) {
		t.Errorf("1e400: %v %v", v, ok)
	}
}

func TestDecodeBody(t *testing.T) {
	for in, want := range map[string]any{"": "", "null": "null", "<xml/>": "<xml/>", `"s"`: "s", "3": int64(3)} {
		if got := decodeBody([]byte(in)); !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %#v, want %#v", in, got, want)
		}
	}
}

func TestNormalizeResponseHeaders(t *testing.T) {
	h := http.Header{
		"Date":                  {"Tue, 10 Sep 2026 12:00:00 GMT"},
		"X-Ratelimit-Reset":     {"1788987600"},
		"X-Ratelimit-Remaining": {"4"},
		"Retry-After":           {"44"},
		"X-Ratelimit-Limit":     {"5"},
		"X-Polaris-Device":      {"030047f0", "second"},
		"Location":              {"https://app.polaris.test/signed-in?code=A-_X&state=fe91"},
		"Content-Type":          {"application/problem+json"},
	}
	got := normalizeResponse(201, h, nil)
	want := normalized{
		Status: 201,
		Headers: map[string][]string{
			"x-ratelimit-limit": {"5"},
			"x-polaris-device":  {"<device>"},
			"location":          {"https://app.polaris.test/signed-in?code=<code>&state=<state>"},
			"content-type":      {"application/problem+json"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v\nwant %#v", got, want)
	}
}

func TestHeaderValues(t *testing.T) {
	v, _ := decodeJSON([]byte(`{"A":["1","2"],"B":"x","C":[3]}`))
	want := map[string][]string{"A": {"1", "2"}, "B": {"x"}, "C": {"3"}}
	if got := headerValues(v); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
	empty, _ := decodeJSON([]byte(`[]`))
	if got := headerValues(empty); len(got) != 0 || got == nil {
		t.Fatalf("[] gave %#v", got)
	}
}

func TestMaskPath(t *testing.T) {
	if got := maskPath("/orgs/" + testUUID + "/members/" + testUUID); got != "/orgs/<uuid>/members/<uuid>" {
		t.Fatal(got)
	}
}

func TestEmbeddedJSONComparesDecoded(t *testing.T) {
	a := normalizeString("{\n    \"b\": 1,\n    \"a\": \"x\"\n}", "text")
	b := normalizeString(`{"a":"x","b":1}`, "text")
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatalf("%v != %v", a, b)
	}
	if got := normalizeString("{not json", "text"); got != "{not json" {
		t.Fatalf("non-JSON kept verbatim, got %v", got)
	}
}
