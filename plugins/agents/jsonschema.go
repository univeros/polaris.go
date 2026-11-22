package agents

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// The JSON Schema subset a capability's input may use. No dependency is taken for it (stdlib
// first), so the keywords below are checked here, and a schema using any other keyword fails New
// rather than being silently weaker than written. Annotations (title, description, default, examples, format, $schema,
// $comment) are accepted and not checked.
var (
	checkedKeywords = []string{"type", "properties", "required", "additionalProperties", "items", "enum", "const",
		"minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "minLength", "maxLength", "pattern",
		"minItems", "maxItems"}
	annotations = []string{"title", "description", "default", "examples", "format", "$schema", "$comment", "$id"}
)

// checkSchema rejects keywords the validator does not check and patterns RE2 cannot compile.
func checkSchema(s map[string]any, at string) error {
	for _, k := range sortedKeys(s) {
		v := s[k]
		switch {
		case slices.Contains(annotations, k):
		case !slices.Contains(checkedKeywords, k):
			return fmt.Errorf("the input schema uses %q at %s, which this validator does not check; use type, properties, required, additionalProperties, items, enum, const, minimum, maximum, exclusiveMinimum, exclusiveMaximum, minLength, maxLength, pattern, minItems, maxItems", k, at)
		case k == "properties":
			props, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("the input schema's properties at %s is not an object", at)
			}
			for _, name := range sortedKeys(props) {
				sub, ok := props[name].(map[string]any)
				if !ok {
					return fmt.Errorf("the input schema's property %q at %s is not a schema object", name, at)
				}
				if err := checkSchema(sub, at+"/"+name); err != nil {
					return err
				}
			}
		case k == "items" || (k == "additionalProperties" && !isBool(v)):
			sub, ok := v.(map[string]any)
			if !ok {
				return fmt.Errorf("the input schema's %s at %s is not a schema object", k, at)
			}
			if err := checkSchema(sub, at+"/"+k); err != nil {
				return err
			}
		case k == "pattern":
			p, ok := v.(string)
			if _, err := regexp.Compile(p); !ok || err != nil {
				return fmt.Errorf("the input schema's pattern at %s does not compile", at)
			}
		}
	}
	return nil
}

func isBool(v any) bool { _, ok := v.(bool); return ok }

// validateSchema returns the first error as "/path: message" (the root without a
// prefix), "" when data is valid.
func validateSchema(s map[string]any, data any) string {
	path, msg := validate(s, data, "")
	if msg == "" {
		return ""
	}
	if path == "" {
		return msg
	}
	return path + ": " + msg
}

func validate(s map[string]any, data any, path string) (string, string) {
	if t, ok := s["type"]; ok && !typeMatches(t, data) {
		return path, fmt.Sprintf("must be %s, not %s", typeList(t), jsonType(data))
	}
	if enum, ok := s["enum"].([]any); ok && !slices.ContainsFunc(enum, func(e any) bool { return jsonEqual(e, data) }) {
		return path, "must be one of the enum values"
	}
	if c, ok := s["const"]; ok && !jsonEqual(c, data) {
		return path, "must equal the const value"
	}
	switch d := data.(type) {
	case map[string]any:
		return validateObject(s, d, path)
	case []any:
		if n, ok := wholeNumber(s["minItems"]); ok && int64(len(d)) < n {
			return path, fmt.Sprintf("must have at least %d item(s), not %d", n, len(d))
		}
		if n, ok := wholeNumber(s["maxItems"]); ok && int64(len(d)) > n {
			return path, fmt.Sprintf("must have at most %d item(s), not %d", n, len(d))
		}
		if items, ok := s["items"].(map[string]any); ok {
			for i, item := range d {
				if p, m := validate(items, item, fmt.Sprintf("%s/%d", path, i)); m != "" {
					return p, m
				}
			}
		}
	case string:
		n := int64(utf8.RuneCountInString(d))
		if least, ok := wholeNumber(s["minLength"]); ok && n < least {
			return path, fmt.Sprintf("must be at least %d characters, not %d", least, n)
		}
		if most, ok := wholeNumber(s["maxLength"]); ok && n > most {
			return path, fmt.Sprintf("must be at most %d characters, not %d", most, n)
		}
		if p, ok := s["pattern"].(string); ok {
			if re, err := regexp.Compile(p); err != nil || !re.MatchString(d) {
				return path, "must match the pattern " + p
			}
		}
	default:
		if v, ok := number(data); ok {
			return validateNumber(s, v, path)
		}
	}
	return "", ""
}

func validateObject(s map[string]any, d map[string]any, path string) (string, string) {
	if req, ok := s["required"].([]any); ok {
		var missing []string
		for _, r := range req {
			if name, ok := r.(string); ok {
				if _, has := d[name]; !has {
					missing = append(missing, name)
				}
			}
		}
		if len(missing) > 0 {
			return path, "missing required properties: " + strings.Join(missing, ", ")
		}
	}
	props, _ := s["properties"].(map[string]any)
	for _, name := range sortedKeys(props) {
		if v, has := d[name]; has {
			if p, m := validate(props[name].(map[string]any), v, path+"/"+name); m != "" {
				return p, m
			}
		}
	}
	var extra []string
	for _, name := range sortedKeys(d) {
		if _, declared := props[name]; !declared {
			extra = append(extra, name)
		}
	}
	switch ap := s["additionalProperties"].(type) {
	case bool:
		if !ap && len(extra) > 0 {
			return path, "properties not allowed: " + strings.Join(extra, ", ")
		}
	case map[string]any:
		for _, name := range extra {
			if p, m := validate(ap, d[name], path+"/"+name); m != "" {
				return p, m
			}
		}
	}
	return "", ""
}

func validateNumber(s map[string]any, v float64, path string) (string, string) {
	bound := func(k string) (float64, string, bool) {
		n, ok := number(s[k])
		return n, fmt.Sprint(s[k]), ok
	}
	if n, shown, ok := bound("minimum"); ok && v < n {
		return path, "must be at least " + shown
	}
	if n, shown, ok := bound("maximum"); ok && v > n {
		return path, "must be at most " + shown
	}
	if n, shown, ok := bound("exclusiveMinimum"); ok && v <= n {
		return path, "must be greater than " + shown
	}
	if n, shown, ok := bound("exclusiveMaximum"); ok && v >= n {
		return path, "must be less than " + shown
	}
	return "", ""
}

// jsonType names data by its JSON Schema type; a whole number is "integer", not "number".
func jsonType(data any) string {
	switch d := data.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		if kind(d) == "int" {
			return "integer"
		}
		if _, ok := number(d); ok {
			return "number"
		}
	}
	return "unknown"
}

func typeList(t any) string {
	if list, ok := t.([]any); ok {
		names := make([]string, 0, len(list))
		for _, n := range list {
			names = append(names, fmt.Sprint(n))
		}
		return strings.Join(names, " or ")
	}
	return fmt.Sprint(t)
}

func typeMatches(t any, data any) bool {
	names := []any{t}
	if list, ok := t.([]any); ok {
		names = list
	}
	actual := jsonType(data)
	for _, n := range names {
		switch n {
		case actual:
			return true
		case "number":
			if actual == "integer" {
				return true
			}
		case "integer":
			if f, ok := number(data); ok && actual == "number" && f == math.Trunc(f) {
				return true
			}
		}
	}
	return false
}

// jsonEqual compares decoded JSON values (numbers by value).
func jsonEqual(a, b any) bool {
	if x, ok := number(a); ok {
		y, ok := number(b)
		return ok && x == y
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return string(ja) == string(jb)
}
