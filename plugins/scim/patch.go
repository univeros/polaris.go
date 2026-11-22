package scim

import (
	"regexp"
	"slices"
	"strings"
)

// PatchSchema is the schema a PATCH body carries (RFC 7644 §3.5.2).
const PatchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

var pathPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:]*(\[[^\]]*\])?(\.[A-Za-z]+)?$`)

// operation is one PatchOp operation: op lower-case (add, replace, remove), path as given ("" for
// none), value as sent (nil when absent).
type operation struct {
	op, path string
	value    any
}

// parsePatch reads the Operations of a PATCH body.
func parsePatch(body map[string]any) ([]operation, error) {
	schemas, _ := body["schemas"].([]any)
	if !slices.Contains(schemas, any(PatchSchema)) {
		return nil, invalid("A PATCH carries the PatchOp schema.", TypeInvalidSyntax)
	}
	raw, _ := body["Operations"].([]any)
	if len(raw) == 0 {
		return nil, invalid("A PATCH carries at least one operation.", TypeInvalidSyntax)
	}
	ops := make([]operation, 0, len(raw))
	for _, item := range raw {
		m, _ := item.(map[string]any)
		name, _ := m["op"].(string)
		name = strings.ToLower(name)
		if name != "add" && name != "replace" && name != "remove" {
			return nil, invalid("op must be add, replace or remove.", TypeInvalidSyntax)
		}
		path, _ := m["path"].(string)
		if path != "" && !pathPattern.MatchString(path) {
			return nil, invalid("The path is not supported.", TypeInvalidPath)
		}
		if path == "" && name != "remove" && !isArray(m["value"]) {
			return nil, invalid("An operation without a path takes an object value.", TypeInvalidValue)
		}
		ops = append(ops, operation{op: name, path: path, value: m["value"]})
	}
	return ops, nil
}

// scalar is the value the operation sets for attribute ("active", "userName",
// "name.givenName"), given as the path or as a key of a path-less value; nil when the operation
// does not touch it.
func (o operation) scalar(attribute string) any {
	attribute = strings.ToLower(attribute)
	if o.path != "" {
		if strings.ToLower(stripURN(o.path)) == attribute {
			return o.value
		}
		return nil
	}
	value, _ := o.value.(map[string]any)
	parent, child, _ := strings.Cut(attribute, ".")
	dotted := strings.Count(attribute, ".") == 1
	for k, candidate := range value {
		k = strings.ToLower(stripURN(k))
		if k == attribute {
			return candidate
		}
		if inner, ok := candidate.(map[string]any); ok && dotted && k == parent {
			for sub, v := range inner {
				if strings.ToLower(sub) == child {
					return v
				}
			}
		}
	}
	return nil
}

// stripURN drops a schema URN prefix: "urn:…:User:displayName" is "displayName".
func stripURN(path string) string {
	if i := strings.LastIndexByte(path, ':'); i >= 0 {
		return path[i+1:]
	}
	return path
}

// isArray reports whether a decoded JSON value is an object or a list.
func isArray(v any) bool {
	switch v.(type) {
	case map[string]any, []any:
		return true
	}
	return false
}
