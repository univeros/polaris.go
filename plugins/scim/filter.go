package scim

import (
	"net/http"
	"regexp"
	"strings"
)

// clausePattern is one `attr eq|co|sw "value"` clause and what follows it (an `and` or the
// end), case-insensitive as upstream's /i pattern.
// (PCRE's \s is [\t\n\v\f\r ]; RE2's lacks \v, so the class is spelled out.)
var clausePattern = regexp.MustCompile(`(?i)([A-Za-z][A-Za-z0-9_.]*(?:\[[^\]]*\])?(?:\.[A-Za-z]+)?)[\t\n\v\f\r ]+(eq|co|sw)[\t\n\v\f\r ]+"((?:[^"\\]|\\.)*)"(?:[\t\n\v\f\r ]+and[\t\n\v\f\r ]+|$)`)

var errFilter = &Error{Status: http.StatusBadRequest, Type: TypeInvalidFilter,
	Detail: `The filter is not supported: use attr eq|co|sw "value", joined by and.`}

// clause is one comparison: a lower-case attribute, an operator (eq, co, sw) and the value.
type clause struct{ attribute, operator, value string }

// filter is the subset of SCIM filters a directory sends when it looks a resource up:
// `attr eq "value"`, `co`, `sw`, joined by `and`; values compared case-insensitively. An empty
// filter matches everything.
type filter []clause

// parseFilter reads a filter; anything outside the subset is the invalidFilter error.
func parseFilter(raw string) (filter, error) {
	raw = phpTrim(raw)
	if raw == "" {
		return nil, nil
	}
	consumed := 0
	var out filter
	for _, m := range clausePattern.FindAllStringSubmatchIndex(raw, -1) {
		if m[0] != consumed {
			return nil, errFilter
		}
		consumed = m[1]
		attribute := strings.ToLower(raw[m[2]:m[3]])
		if strings.HasPrefix(attribute, "emails") {
			attribute = "emails"
		}
		out = append(out, clause{attribute, strings.ToLower(raw[m[4]:m[5]]), stripSlashes(raw[m[6]:m[7]])})
	}
	if out == nil || consumed != len(raw) {
		return nil, errFilter
	}
	return out, nil
}

// matches reports whether a resource, flattened to lower-case attribute names and their string
// values, satisfies every clause.
func (f filter) matches(attributes map[string][]string) bool {
	for _, c := range f {
		want := strings.ToLower(c.value)
		hit := false
		for _, v := range attributes[c.attribute] {
			v = strings.ToLower(v)
			switch c.operator {
			case "eq":
				hit = hit || v == want
			case "co":
				hit = hit || strings.Contains(v, want)
			default:
				hit = hit || strings.HasPrefix(v, want)
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// stripSlashes is PHP's stripslashes: a backslash escapes the next byte (\0 is NUL); a lone
// trailing backslash is dropped.
func stripSlashes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		i++
		if i < len(s) {
			if s[i] == '0' {
				b.WriteByte(0)
			} else {
				b.WriteByte(s[i])
			}
		}
	}
	return b.String()
}

// phpTrim is PHP's trim(): space, tab, newline, carriage return, NUL and vertical tab.
func phpTrim(s string) string { return strings.Trim(s, " \t\n\r\x00\x0b") }
