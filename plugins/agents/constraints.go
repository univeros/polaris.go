package agents

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// operators are AAP's per-argument operators plus pattern, in the order violations list them.
var operators = []string{"max", "min", "in", "not_in", "pattern"}

const (
	maxConstrained = 50
	maxList        = 200
	maxPattern     = 500
	maxBudget      = math.MaxInt64 / 2
)

var (
	fieldName  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,79}$`)
	phpNumeric = regexp.MustCompile(`^[ \t\n\r\v\f]*[+-]?([0-9]+(\.[0-9]*)?|\.[0-9]+)([eE][+-]?[0-9]+)?[ \t\n\r\v\f]*$`)
)

// Budget is what a grant may spend: Count executions, or an Amount summed from one argument
// (Field), optionally within a Window that becomes the grant's lifetime.
type Budget struct {
	Count  int64
	Amount int64
	Field  string
	Window time.Duration // whole seconds; 0 for none
}

// budget is a validated budget.
type budget struct {
	kind   string
	total  int64
	field  string
	window int64 // seconds, 0 for none
}

func (b Budget) parse() (*budget, error) {
	spec := map[string]any{"field": nil, "window": nil}
	if b.Count != 0 {
		spec["count"] = json.Number(strconv.FormatInt(b.Count, 10))
	}
	if b.Amount != 0 {
		spec["amount"] = json.Number(strconv.FormatInt(b.Amount, 10))
		spec["field"] = b.Field
	}
	if b.Window != 0 {
		if b.Window%time.Second != 0 {
			return nil, refuse(ErrInvalidInput, "A budget window is a positive number of seconds.")
		}
		spec["window"] = json.Number(strconv.FormatInt(int64(b.Window/time.Second), 10))
	}
	return parseBudget(spec)
}

// constraints are a grant's parsed constraints.
type constraints struct {
	fields map[string]map[string]any
	budget *budget
}

// parseConstraints validates constraints written by an agent or an owner: argument → operators,
// plus "budget". An empty list is no constraint, as PHP reads [].
func parseConstraints(raw any) (constraints, error) {
	out := constraints{fields: map[string]map[string]any{}}
	var m map[string]any
	switch v := raw.(type) {
	case nil:
		return out, nil
	case map[string]any:
		m = v
	case []any:
		if len(v) > maxConstrained {
			return out, refuse(ErrInvalidInput, fmt.Sprintf("At most %d arguments may be constrained.", maxConstrained))
		}
		if len(v) > 0 {
			return out, refuse(ErrInvalidInput, "Constraints map an argument name to an object of operators.")
		}
		return out, nil
	default:
		return out, refuse(ErrInvalidInput, "Constraints map an argument name to an object of operators.")
	}
	if len(m) > maxConstrained {
		return out, refuse(ErrInvalidInput, fmt.Sprintf("At most %d arguments may be constrained.", maxConstrained))
	}
	for _, field := range sortedKeys(m) {
		ops := m[field]
		if field == "budget" {
			spec, ok := asSpec(ops)
			if !ok {
				return out, refuse(ErrInvalidInput, "budget is an object: {count} or {amount, field}, with an optional window.")
			}
			b, err := parseBudget(spec)
			if err != nil {
				return out, err
			}
			out.budget = b
			continue
		}
		opMap, isMap := ops.(map[string]any)
		list, isList := ops.([]any)
		if !fieldName.MatchString(field) || (!isMap && !isList) {
			return out, refuse(ErrInvalidInput, "Constraints map an argument name to an object of operators.")
		}
		if isList && len(list) > 0 {
			return out, refuse(ErrUnknownConstraintOperator, fmt.Sprintf(`Unknown constraint operator "?" on "%s"; known: max, min, in, not_in, pattern, and budget.`, field))
		}
		parsed := map[string]any{}
		for _, op := range sortedKeys(opMap) {
			if !slices.Contains(operators, op) {
				return out, refuse(ErrUnknownConstraintOperator, fmt.Sprintf(`Unknown constraint operator "%s" on "%s"; known: max, min, in, not_in, pattern, and budget.`, op, field))
			}
			v, err := operand(field, op, opMap[op])
			if err != nil {
				return out, err
			}
			parsed[op] = v
		}
		out.fields[field] = parsed
	}
	return out, nil
}

func asSpec(v any) (map[string]any, bool) {
	switch v := v.(type) {
	case map[string]any:
		return v, true
	case []any:
		return map[string]any{}, true
	}
	return nil, false
}

// parseBudget validates {count: N} or {amount: N, field: argument}, with an optional window.
func parseBudget(spec map[string]any) (*budget, error) {
	count, amount := spec["count"], spec["amount"]
	if (count == nil) == (amount == nil) {
		return nil, refuse(ErrInvalidInput, "A budget is {count: N} or {amount: N, field: argument}.")
	}
	total, ok := phpInt(count)
	if count == nil {
		total, ok = phpInt(amount)
	}
	if !ok || total < 1 || total > maxBudget {
		return nil, refuse(ErrInvalidInput, "A budget total is a positive integer.")
	}
	b := &budget{kind: BudgetCount, total: total}
	if amount != nil {
		field, ok := spec["field"].(string)
		if !ok || !fieldName.MatchString(field) {
			return nil, refuse(ErrInvalidInput, "An amount budget names the argument it sums (field).")
		}
		b.kind, b.field = BudgetAmount, field
	}
	if w := spec["window"]; w != nil {
		n, ok := phpInt(w)
		if !ok || n < 1 {
			return nil, refuse(ErrInvalidInput, "A budget window is a positive number of seconds.")
		}
		b.window = n
	}
	return b, nil
}

func operand(field, op string, v any) (any, error) {
	invalid := func(what string) error {
		return refuse(ErrInvalidInput, fmt.Sprintf(`Constraint "%s" on "%s" takes %s.`, op, field, what))
	}
	switch op {
	case "max", "min":
		if _, ok := number(v); !ok {
			return nil, invalid("a number")
		}
		return v, nil
	case "in", "not_in":
		list, ok := v.([]any)
		if !ok || len(list) > maxList {
			return nil, invalid("a list of scalars")
		}
		for _, item := range list {
			if !scalar(item) {
				return nil, invalid("a list of scalars")
			}
		}
		return list, nil
	}
	s, ok := v.(string)
	if !ok || s == "" || len(s) > maxPattern {
		return nil, invalid("a valid regular expression")
	}
	if _, err := compilePattern(s); err != nil {
		return nil, invalid("a valid regular expression")
	}
	return s, nil
}

// compilePattern anchors a pattern operand as upstream does: /^(?:pattern)$/u. RE2 syntax: a
// PCRE-only construct (lookaround, backreferences) is refused when the constraint is written.
func compilePattern(p string) (*regexp.Regexp, error) { return regexp.Compile(`^(?:` + p + `)$`) }

// Violation is an argument a grant's constraint refuses.
type Violation struct {
	Field      string `json:"field"`
	Constraint string `json:"constraint"`
	Actual     any    `json:"actual"`
}

// violations lists what the arguments violate; a constrained argument that is absent violates
// every operator on it (the constraint exists to bound it).
func violations(fields map[string]map[string]any, args map[string]any) []Violation {
	var out []Violation
	for _, field := range sortedKeys(fields) {
		actual, present := args[field]
		shown := actual
		if !scalar(actual) && actual != nil {
			shown = "<array>"
		}
		for _, op := range operators {
			want, has := fields[field][op]
			if has && (!present || !satisfies(op, want, actual)) {
				out = append(out, Violation{Field: field, Constraint: op, Actual: shown})
			}
		}
	}
	return out
}

func satisfies(op string, want, actual any) bool {
	switch op {
	case "max", "min":
		a, ok := numeric(actual)
		w, _ := number(want)
		if !ok {
			return false
		}
		if op == "max" {
			return a <= w
		}
		return a >= w
	case "in", "not_in":
		if !scalar(actual) {
			return false
		}
		list, _ := want.([]any)
		found := slices.ContainsFunc(list, func(item any) bool { return identical(item, actual) })
		return found == (op == "in")
	case "pattern":
		s, ok := actual.(string)
		p, _ := want.(string)
		re, err := compilePattern(p)
		return ok && err == nil && re.MatchString(s)
	}
	return false
}

// cost is what an execution charges a grant: one for a count, the rounded-up value of the budget's
// argument for an amount.
func cost(g Grant, args map[string]any) (int64, error) {
	if g.BudgetKind != BudgetAmount {
		return 1, nil
	}
	v, ok := number(args[g.BudgetField])
	if !ok || v < 0 || v > maxBudget {
		return 0, refuse(ErrInvalidArguments, fmt.Sprintf(`The budget argument "%s" must be a non-negative number.`, g.BudgetField))
	}
	return int64(math.Ceil(v)), nil
}

// number reads a JSON number (PHP is_int || is_float).
func number(v any) (float64, bool) {
	switch v := v.(type) {
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case int32:
		return float64(v), true
	}
	return 0, false
}

// numeric is PHP's is_numeric plus its value: a number, or a numeric string.
func numeric(v any) (float64, bool) {
	if s, ok := v.(string); ok {
		if !phpNumeric.MatchString(s) {
			return 0, false
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		return f, err == nil
	}
	return number(v)
}

// phpInt reads what PHP would decode as an int: a JSON number without fraction or exponent.
func phpInt(v any) (int64, bool) {
	switch v := v.(type) {
	case json.Number:
		if strings.ContainsAny(v.String(), ".eE") {
			return 0, false
		}
		n, err := v.Int64()
		return n, err == nil
	case int:
		return int64(v), true
	case int64:
		return v, true
	}
	return 0, false
}

// scalar is PHP's is_scalar: a string, a number or a bool.
func scalar(v any) bool {
	switch v.(type) {
	case string, bool, json.Number, float64, float32, int, int64, int32:
		return true
	}
	return false
}

// identical is PHP's === over decoded JSON scalars: an int never equals a float or a string.
func identical(a, b any) bool {
	ka, kb := kind(a), kind(b)
	if ka != kb {
		return false
	}
	switch ka {
	case "int":
		x, _ := phpInt(a)
		y, _ := phpInt(b)
		return x == y
	case "float":
		x, _ := number(a)
		y, _ := number(b)
		return x == y
	}
	return a == b
}

func kind(v any) string {
	switch v := v.(type) {
	case string:
		return "string"
	case bool:
		return "bool"
	case json.Number:
		if strings.ContainsAny(v.String(), ".eE") {
			return "float"
		}
		return "int"
	case int, int64, int32:
		return "int"
	case float64, float32:
		return "float"
	}
	return "other"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
