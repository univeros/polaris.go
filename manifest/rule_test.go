package manifest

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func mustRules(t *testing.T, texts ...string) []Rule {
	t.Helper()
	rules := make([]Rule, 0, len(texts))
	for _, text := range texts {
		rule, err := ParseRule(text)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", text, err)
		}
		rules = append(rules, rule)
	}
	return rules
}

func TestParseRuleEveryFormTheSpecsUse(t *testing.T) {
	for _, text := range []string{"required", "optional", "string", "email", "max:320", "in:recovery,totp", "regex:/^[a-z0-9-]+$/", "password_policy", "e164", "suspended"} {
		rule, err := ParseRule(text)
		if err != nil {
			t.Fatalf("ParseRule(%q): %v", text, err)
		}
		if rule.String() != text {
			t.Errorf("String() = %q, want %q", rule.String(), text)
		}
	}
	maxRule, _ := ParseRule("max:320")
	if maxRule.Name() != "max" || maxRule.Arg() != "320" {
		t.Errorf("max:320 = %q %q", maxRule.Name(), maxRule.Arg())
	}
	if _, err := ParseRule("between:1,2"); err == nil || err.Error() != `Unknown validation rule "between:1,2".` {
		t.Errorf("between: %v", err)
	}
	for _, text := range []string{"max", "in:", "regex"} {
		name, _, _ := strings.Cut(text, ":")
		if _, err := ParseRule(text); err == nil || err.Error() != `Rule "`+name+`" needs an argument.` {
			t.Errorf("%s: %v", text, err)
		}
	}
	if _, err := ParseRule("regex:/(/"); err == nil {
		t.Error("an invalid pattern must not parse")
	}
	required, _ := ParseRule("required:")
	if required.Name() != "required" || required.String() != "required:" {
		t.Errorf("required: = %q", required.String())
	}
}

func TestValidateEvaluatesRulesAgainstData(t *testing.T) {
	fields := []Field{
		{Name: "email", Type: "string", Rules: mustRules(t, "required", "email", "max:320")},
		{Name: "password", Type: "string", Rules: mustRules(t, "required", "password_policy"), Sensitive: true},
		{Name: "display_name", Type: "string", Rules: mustRules(t, "optional", "max:5")},
		{Name: "type", Type: "string", Rules: mustRules(t, "required", "in:totp,sms")},
		{Name: "phone", Type: "string", Rules: mustRules(t, "optional", "e164")},
		{Name: "slug", Type: "string", Rules: mustRules(t, "optional", "regex:/^[a-z0-9-]+$/")},
	}

	if err := Validate(fields, map[string]any{"email": "ada@example.com", "password": "x", "type": "totp", "phone": "+15551234567", "slug": "acme"}); err != nil {
		t.Fatalf("valid data: %v", err)
	}

	err := Validate(fields, map[string]any{"email": "nope", "display_name": "toolong", "type": "push", "phone": "555", "slug": "Not Ok"})
	var invalid *ValidationError
	if !errors.As(err, &invalid) {
		t.Fatalf("want *ValidationError, got %v", err)
	}
	want := []string{"email must be a valid email address.", "password is required.", "display_name must be at most 5 characters.", "type must be one of totp,sms.", "phone must be an E.164 phone number.", "slug has an invalid format."}
	if !reflect.DeepEqual(invalid.Errors, want) {
		t.Errorf("violations = %q", invalid.Errors)
	}
	body, _ := json.Marshal(invalid)
	wantBody, _ := json.Marshal(map[string]any{"errors": want})
	if string(body) != string(wantBody) {
		t.Errorf("422 body = %s", body)
	}
	if invalid.Error() != strings.Join(want, " ") {
		t.Errorf("Error() = %q", invalid.Error())
	}
}

func TestValidateValueKinds(t *testing.T) {
	field := func(rules ...string) []Field {
		return []Field{{Name: "f", Type: "string", Rules: mustRules(t, rules...)}}
	}
	cases := []struct {
		rules []string
		value any
		want  string
	}{
		{[]string{"required"}, nil, "f is required."},
		{[]string{"required"}, "", "f is required."},
		{[]string{"required"}, float64(0), ""},
		{[]string{"required"}, json.Number("0"), ""},
		{[]string{"string"}, float64(1), "f must be a string."},
		{[]string{"string"}, json.Number("1"), "f must be a string."},
		{[]string{"string"}, "x", ""},
		{[]string{"string"}, nil, ""},
		{[]string{"max:3"}, "äöü", ""},
		{[]string{"max:3"}, "äöüx", "f must be at most 3 characters."},
		{[]string{"max:3"}, float64(1), "f must be at most 3 characters."},
		{[]string{"max:3abc"}, "abcd", "f must be at most 3 characters."},
		{[]string{"max:abc"}, "a", "f must be at most 0 characters."},
		{[]string{"in:a, b"}, " b", ""},
		{[]string{"in:a,b"}, "b ", "f must be one of a,b."},
		{[]string{"in:1,2"}, float64(1), "f must be one of 1,2."},
		{[]string{"regex:/^[a-z]+$/"}, "abc\n", ""}, // PCRE "$" also matches before a final newline
		{[]string{"regex:/^[a-z]+$/D"}, "abc\n", "f has an invalid format."},
		{[]string{"regex:/^[a-z]+$/i"}, "ABC", ""},
		{[]string{"regex:#^a/b$#"}, "a/b", ""},
		{[]string{"regex:/^[a-z]+$/"}, true, "f has an invalid format."},
		{[]string{"e164"}, "+15551234567\n", ""}, // the pattern has no D modifier
		{[]string{"e164"}, "+0555", "f must be an E.164 phone number."},
		{[]string{"email"}, float64(1), "f must be a valid email address."},
		{[]string{"password_policy", "suspended", "optional"}, "x", ""},
		{[]string{"optional", "string", "max:1"}, "xy", "f must be at most 1 characters."},
	}
	for _, c := range cases {
		err := Validate(field(c.rules...), map[string]any{"f": c.value})
		got := ""
		if err != nil {
			ve, _ := errors.AsType[*ValidationError](err)
			got = strings.Join(ve.Errors, "|")
		}
		if got != c.want {
			t.Errorf("%v on %#v = %q, want %q", c.rules, c.value, got, c.want)
		}
	}
	if err := Validate(field("required"), nil); err == nil {
		t.Error("nil data must fail required")
	}
}

func TestParseRuleRegexDelimiters(t *testing.T) {
	for _, text := range []string{"regex:abc", "regex:/abc", "regex:/abc/q", "regex:/(?<=a)b/"} {
		if _, err := ParseRule(text); err == nil {
			t.Errorf("%s: want an error", text)
		}
	}
}

// TestIsEmail replays testdata/manifest/email.tsv: each line is a JSON string and T or F, the
// expected verdict (the known-answer set the email rule must keep).
func TestIsEmail(t *testing.T) {
	data, err := os.ReadFile("../testdata/manifest/email.tsv")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		quoted, verdict, _ := strings.Cut(line, "\t")
		var email string
		if err := json.Unmarshal([]byte(quoted), &email); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if got := IsEmail(email); got != (verdict == "T") {
			t.Errorf("IsEmail(%s) = %v, want %s", quoted, got, verdict)
		}
	}
}
