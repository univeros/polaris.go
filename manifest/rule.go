package manifest

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// RuleNames is the rule vocabulary of the specs' input.fields.*.rules. password_policy and
// suspended are business rules the services enforce: they parse but [Validate] does not evaluate
// them.
var RuleNames = []string{"required", "optional", "string", "email", "max", "in", "regex", "password_policy", "e164", "suspended"}

// e164 is /^\+[1-9]\d{1,14}$/ with PCRE's "$" (a final newline passes).
var e164 = func() *regexp.Regexp {
	re, err := compilePCRE(`/^\+[1-9]\d{1,14}$/`)
	if err != nil {
		panic(err)
	}
	return re
}()

// Rule is one parsed rule: a name and an optional argument after the first colon ("max:320",
// "in:totp,sms", "regex:/^[a-z0-9-]+$/").
type Rule struct {
	text, name, arg string
	re              *regexp.Regexp // compiled argument of a regex rule
}

// ParseRule parses one rule, failing on an unknown name, a max, in or regex rule without an
// argument, or a regex rule whose pattern Go cannot compile.
func ParseRule(text string) (Rule, error) {
	name, arg, _ := strings.Cut(text, ":")
	if !slices.Contains(RuleNames, name) {
		return Rule{}, fmt.Errorf("Unknown validation rule %q.", text)
	}
	if (name == "max" || name == "in" || name == "regex") && arg == "" {
		return Rule{}, fmt.Errorf("Rule %q needs an argument.", name)
	}
	rule := Rule{text: text, name: name, arg: arg}
	if name == "regex" {
		re, err := compilePCRE(arg)
		if err != nil {
			return Rule{}, fmt.Errorf("Rule %q: %w", text, err)
		}
		rule.re = re
	}
	return rule, nil
}

// Name returns the rule's name ("max").
func (r Rule) Name() string { return r.name }

// Arg returns the rule's argument ("320"), "" when it has none.
func (r Rule) Arg() string { return r.arg }

// String returns the rule as written in the spec ("max:320").
func (r Rule) String() string { return r.text }

// ValidationError lists the input rule violations of a request. Encoded as JSON it is the body
// of the 422 response core routes answer ({"errors": [...]}); plugin routes carry the same list
// as the "errors" member of their problem document.
type ValidationError struct {
	Errors []string `json:"errors"`
}

// Error joins the violation messages.
func (e *ValidationError) Error() string {
	return strings.Join(e.Errors, " ")
}

// Validate checks data, a decoded JSON object, against the fields' rules and returns a
// *[ValidationError] listing one message per failing field (its first failing rule), or nil.
//
// A field is present when its key exists with a value other than nil and "". Only Go strings
// satisfy the string rules (string, email, max, in, regex, e164), so numbers fail them whether
// they were decoded as float64 or json.Number.
func Validate(fields []Field, data map[string]any) error {
	var violations []string
	for _, f := range fields {
		value := data[f.Name]
		present := value != nil && value != ""
		for _, rule := range f.Rules {
			if message, ok := rule.check(f.Name, present, value); !ok {
				violations = append(violations, message)
				break
			}
		}
	}
	if violations == nil {
		return nil
	}
	return &ValidationError{Errors: violations}
}

func (r Rule) check(field string, present bool, value any) (string, bool) {
	if r.name == "required" {
		return field + " is required.", present
	}
	if !present {
		return "", true
	}
	s, isString := value.(string)
	switch r.name {
	case "string":
		return field + " must be a string.", isString
	case "email":
		return field + " must be a valid email address.", isString && IsEmail(s)
	case "max":
		limit := leadingInt(r.arg)
		return fmt.Sprintf("%s must be at most %d characters.", field, limit), isString && utf8.RuneCountInString(s) <= limit
	case "in":
		return fmt.Sprintf("%s must be one of %s.", field, r.arg), isString && slices.Contains(strings.Split(r.arg, ","), s)
	case "regex":
		return field + " has an invalid format.", isString && r.re.MatchString(s)
	case "e164":
		return field + " must be an E.164 phone number.", isString && e164.MatchString(s)
	}
	return "", true
}

// leadingInt is the integer s starts with (after ASCII whitespace and an optional sign), 0 when
// there is none: "max:10abc" limits to 10.
func leadingInt(s string) int {
	s = strings.TrimLeft(s, " \t\n\r\v\f")
	n, sign, i := 0, 1, 0
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		if s[i] == '-' {
			sign = -1
		}
		i++
	}
	for ; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		n = n*10 + int(s[i]-'0')
	}
	return sign * n
}

// compilePCRE compiles a delimited PCRE-style pattern ("/^[a-z]+$/i") with Go's regexp: the delimiters and
// the i, m, s, U, u and D modifiers are honoured, and without m or D a "$" also matches before a
// final newline, as in PCRE. Constructs RE2 lacks (lookaround, backreferences) fail to compile.
func compilePCRE(pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, fmt.Errorf("empty pattern")
	}
	open := pattern[0]
	if open == '\\' || open == ' ' || (open >= '0' && open <= '9') || (open|0x20 >= 'a' && open|0x20 <= 'z') {
		return nil, fmt.Errorf("delimiter must not be alphanumeric, backslash or space")
	}
	closing := map[byte]byte{'(': ')', '[': ']', '{': '}', '<': '>'}[open]
	if closing == 0 {
		closing = open
	}
	end, depth := -1, 0
	for i := 1; i < len(pattern) && end < 0; i++ {
		switch c := pattern[i]; {
		case c == '\\':
			i++
		case c == closing && depth == 0:
			end = i
		case c == closing:
			depth--
		case c == open && closing != open:
			depth++
		}
	}
	if end < 0 {
		return nil, fmt.Errorf("no ending delimiter %q found", closing)
	}
	body, modifiers := pattern[1:end], pattern[end+1:]
	flags, dollarEndOnly := "", false
	for _, m := range modifiers {
		switch m {
		case 'i', 'm', 's', 'U':
			flags += string(m)
		case 'D':
			dollarEndOnly = true
		case 'u':
		default:
			return nil, fmt.Errorf("unsupported modifier %q", m)
		}
	}
	if !dollarEndOnly && !strings.ContainsRune(flags, 'm') {
		body = pcreDollar(body)
	}
	if flags != "" {
		body = "(?" + flags + ")" + body
	}
	return regexp.Compile(body)
}

// pcreDollar rewrites every "$" anchor outside a character class to also match before a final
// newline.
func pcreDollar(body string) string {
	var b strings.Builder
	inClass := false
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case c == '\\' && i+1 < len(body):
			b.WriteString(body[i : i+2])
			i++
		case c == '[' && !inClass:
			inClass = true
			// A "]" right after "[" or "[^" is a literal member, not the end of the class.
			lead := len(body[i:]) - len(strings.TrimPrefix(strings.TrimPrefix(body[i+1:], "^"), "]")) - 1
			b.WriteString(body[i : i+lead+1])
			i += lead
		case c == ']' && inClass:
			inClass = false
			b.WriteByte(c)
		case c == '$' && !inClass:
			b.WriteString(`(?:\n?\z)`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
