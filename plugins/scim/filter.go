package scim

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// clausePattern is one `attr eq|co|sw "value"` clause and what follows it (an `and` or the
// end), case-insensitive. Whitespace is [\t\n\v\f\r ], spelled out because RE2's \s lacks \v.
var clausePattern = regexp.MustCompile(`(?i)([A-Za-z][A-Za-z0-9_.]*(?:\[[^\]]*\])?(?:\.[A-Za-z]+)?)[\t\n\v\f\r ]+(eq|co|sw)[\t\n\v\f\r ]+"((?:[^"\\]|\\.)*)"(?:[\t\n\v\f\r ]+and[\t\n\v\f\r ]+|$)`)

var errFilter = &Error{Status: http.StatusBadRequest, Type: TypeInvalidFilter,
	Detail: `The filter is not supported: use attr eq|co|sw "value", joined by and.`}

// clause is one comparison: a lower-case attribute, an operator (eq, co, sw) and the value.
type clause struct{ attribute, operator, value string }

// filter is the subset of SCIM filters a directory sends when it looks a resource up:
// `attr eq "value"`, `co`, `sw`, joined by `and`; values compared case-insensitively. An empty
// filter matches everything.
type filter []clause

// parseFilter reads a filter; anything outside the subset is the invalidFilter error. A value is a
// JSON string (RFC 7644 §3.4.2.2), decoded as one: an escape JSON does not define, a raw control
// character or a NUL (the value is compared with stored text) is refused.
func parseFilter(raw string) (filter, error) {
	raw = strings.TrimSpace(raw)
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
		var value string
		if json.Unmarshal([]byte(raw[m[6]-1:m[7]+1]), &value) != nil || strings.ContainsRune(value, 0) {
			return nil, errFilter
		}
		out = append(out, clause{attribute, strings.ToLower(raw[m[4]:m[5]]), value})
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
