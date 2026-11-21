package manifest

import (
	"regexp"
	"strconv"
	"strings"
)

const (
	errorSchema      = "#/components/schemas/Error"
	validationSchema = "#/components/schemas/ValidationError"
	problemSchema    = "#/components/schemas/Problem"
)

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// Export returns the manifest as upstream's "polaris manifest --format=json" prints it:
// {"endpoints": [...]}, one entry per route with its policy, input, class, errors and events.
func (m *Manifest) Export() Object {
	endpoints := make([]any, 0, len(m.routes))
	for _, r := range m.routes {
		endpoints = append(endpoints, r.export())
	}
	return Object{{"endpoints", endpoints}}
}

func (r *Route) export() Object {
	fields := make([]any, 0, len(r.Input.Fields))
	for _, f := range r.Input.Fields {
		rules := make([]string, 0, len(f.Rules))
		for _, rule := range f.Rules {
			rules = append(rules, rule.String())
		}
		fields = append(fields, Object{{"name", f.Name}, {"type", f.Type}, {"rules", rules}, {"sensitive", f.Sensitive}})
	}
	errs := make([]any, 0, len(r.Errors))
	for _, e := range r.Errors {
		errs = append(errs, Object{{"status", e.Status}, {"code", nullable(e.Code)}})
	}
	return Object{
		{"method", r.Method},
		{"path", r.Path},
		{"summary", r.Summary},
		{"auth", r.Auth},
		{"rate_limit", nullable(r.RateLimit)},
		{"effect", r.Effect},
		{"receipt", r.Receipt},
		{"step_up", r.StepUp},
		{"session", nullable(string(r.Session))},
		{"requires_permissions", list(r.RequiresPermissions)},
		{"input", Object{{"source", r.Input.Source}, {"fields", fields}}},
		{"class", r.Class},
		{"errors", errs},
		{"events", list(r.Events)},
	}
}

// OpenAPI returns the OpenAPI 3.1 document of the manifest, as upstream's
// "polaris manifest --format=openapi" prints it: one operation per route, request bodies and
// parameters from the input, security from the auth, responses from the output (the success body
// typed from its examples) and errors, and the policy as x-polaris-* extensions. version is
// info.version (internal/version.Module() for the running release).
func (m *Manifest) OpenAPI(version string) Object {
	var paths Object
	for _, r := range m.routes {
		item, _ := paths.Get(r.Path)
		operations, _ := item.(Object)
		paths = paths.With(r.Path, operations.With(strings.ToLower(r.Method), r.operation()))
	}
	return Object{
		{"openapi", "3.1.0"},
		{"info", Object{{"title", "Polaris for Go"}, {"version", version}, {"description", "Authentication and authorization for users and AI agents."}}},
		{"paths", paths},
		{"components", Object{
			{"securitySchemes", Object{
				{"bearerAuth", Object{{"type", "http"}, {"scheme", "bearer"}, {"bearerFormat", "JWT"}}},
				{"mfaToken", Object{{"type", "http"}, {"scheme", "bearer"}, {"bearerFormat", "JWT"}, {"description", "The short-lived login_mfa ticket returned by /auth/login."}}},
			}},
			{"schemas", Object{
				{"Error", Object{{"type", "object"}, {"properties", Object{{"error", typed("string")}, {"message", typed("string")}}}}},
				{"ValidationError", Object{{"type", "object"}, {"properties", Object{{"errors", stringArray()}}}}},
				{"Problem", Object{
					{"type", "object"},
					{"description", "An RFC 9457 problem document, the error shape of the plugins' routes; error and message repeat the core envelope."},
					{"properties", Object{
						{"type", Object{{"type", "string"}, {"format", "uri"}}},
						{"title", typed("string")},
						{"status", typed("integer")},
						{"detail", typed("string")},
						{"error", typed("string")},
						{"message", typed("string")},
						{"errors", stringArray()},
					}},
					{"required", []string{"type", "title", "status", "detail", "error", "message"}},
				}},
			}},
		}},
	}
}

func (r *Route) operation() Object {
	op := Object{
		{"operationId", r.operationID()},
		{"summary", r.Summary},
		{"tags", list(r.Tags)},
		{"x-polaris-effect", r.Effect},
		{"x-polaris-receipt", r.Receipt},
	}
	if r.Plugin != "" {
		op = append(op, Member{"x-polaris-plugin", r.Plugin})
	}
	if r.RateLimit != "" {
		op = append(op, Member{"x-polaris-rate-limit", r.RateLimit})
	}
	if r.StepUp {
		op = append(op, Member{"x-polaris-step-up", true})
	}
	if r.Session != "" {
		op = append(op, Member{"x-polaris-session", r.Session})
	}
	if len(r.RequiresPermissions) > 0 {
		op = append(op, Member{"x-polaris-requires-permissions", r.RequiresPermissions})
	}
	switch r.Auth {
	case AuthBearer:
		op = append(op, Member{"security", []any{Object{{"bearerAuth", []any{}}}}})
	case AuthMfaToken:
		op = append(op, Member{"security", []any{Object{{"mfaToken", []any{}}}}})
	}

	var parameters []any
	for _, match := range pathParam.FindAllStringSubmatch(r.Path, -1) {
		parameters = append(parameters, Object{{"name", match[1]}, {"in", "path"}, {"required", true}, {"schema", typed("string")}})
	}
	if r.Input.Source == SourceQuery {
		for _, f := range r.Input.Fields {
			parameters = append(parameters, Object{{"name", f.Name}, {"in", "query"}, {"required", f.required()}, {"schema", f.schema()}})
		}
	}
	if len(parameters) > 0 {
		op = append(op, Member{"parameters", parameters})
	}
	if r.Input.Source == SourceBody && len(r.Input.Fields) > 0 {
		var properties Object
		var required []string
		for _, f := range r.Input.Fields {
			properties = properties.With(f.Name, f.schema())
			if f.required() {
				required = append(required, f.Name)
			}
		}
		schema := Object{{"type", "object"}, {"properties", properties}}
		if len(required) > 0 {
			schema = append(schema, Member{"required", required})
		}
		op = append(op, Member{"requestBody", Object{{"required", true}, {"content", Object{{"application/json", Object{{"schema", schema}}}}}}})
	}
	return append(op, Member{"responses", r.responses()})
}

func (r *Route) responses() Object {
	status := 200
	if r.Output.Status != 0 {
		status = r.Output.Status
	}
	success := Object{{"description", "Success"}}
	if len(r.Output.Examples) > 0 {
		content := Object{{"schema", examplesSchema(r.Output.Examples)}}
		if len(r.Output.Examples) == 1 {
			content = append(content, Member{"example", r.Output.Examples[0].Value})
		} else {
			examples := make(Object, 0, len(r.Output.Examples))
			for _, e := range r.Output.Examples {
				examples = append(examples, Member{e.Key, Object{{"value", e.Value}}})
			}
			content = append(content, Member{"examples", examples})
		}
		success = append(success, Member{"content", Object{{"application/json", content}}})
	}
	responses := Object{{strconv.Itoa(status), success}}
	for _, e := range r.Errors {
		code := strconv.Itoa(e.Status)
		description := e.Code
		if description == "" {
			description = "Error"
		}
		if existing, ok := responses.Get(code); ok {
			previous, _ := existing.(Object).Get("description")
			responses = responses.With(code, existing.(Object).With("description", previous.(string)+" | "+description))
			continue
		}
		var content Object
		switch {
		case r.Plugin != "":
			content = Object{{"application/problem+json", Object{{"schema", ref(problemSchema)}}}}
		case e.Status == 422:
			content = Object{{"application/json", Object{{"schema", ref(validationSchema)}}}}
		default:
			content = Object{{"application/json", Object{{"schema", ref(errorSchema)}}}}
		}
		responses = append(responses, Member{code, Object{{"description", description}, {"content", content}}})
	}
	return responses
}

// operationID is the method and the endpoint class's short name, with the plugin id between them
// for a plugin's route (a plugin's endpoint may share its short name with a core one).
func (r *Route) operationID() string {
	short := r.Class[strings.LastIndexByte(r.Class, '\\')+1:]
	if r.Plugin == "" {
		return strings.ToLower(r.Method) + "_" + short
	}
	return strings.ToLower(r.Method) + "_" + r.Plugin + "_" + short
}

func (f Field) required() bool {
	for _, rule := range f.Rules {
		if rule.name == "required" {
			return true
		}
	}
	return false
}

// schema is the field's JSON Schema: its type, narrowed by its rules, marked when sensitive.
func (f Field) schema() Object {
	t := strings.TrimLeft(f.Type, "?")
	var s Object
	switch {
	case t == "integer", t == "boolean":
		s = typed(t)
	case t == "array":
		s = typed("array")
	case t == "object":
		s = Object{{"type", "object"}, {"additionalProperties", true}}
	case strings.HasPrefix(t, "list<"):
		inner := t[5:max(5, len(t)-1)]
		if inner != "integer" && inner != "boolean" {
			inner = "string"
		}
		s = Object{{"type", "array"}, {"items", typed(inner)}}
	default:
		s = typed("string")
	}
	for _, rule := range f.Rules {
		switch rule.name {
		case "email":
			s = s.With("format", "email")
		case "max":
			s = s.With("maxLength", phpInt(rule.arg))
		case "in":
			values := strings.Split(rule.arg, ",")
			for i, v := range values {
				values[i] = strings.Trim(v, " \t\n\r\x00\x0B")
			}
			s = s.With("enum", values)
		case "regex":
			s = s.With("pattern", strings.Trim(rule.arg, "/"))
		case "e164":
			s = s.With("pattern", `^\+[1-9]\d{1,14}$`)
		case "password_policy":
			s = s.With("description", "Must satisfy the configured password policy.")
		}
	}
	if f.Sensitive {
		if _, ok := s.Get("format"); !ok {
			s = s.With("format", "password")
		}
		s = s.With("x-polaris-sensitive", true)
	}
	return s
}

func typed(t string) Object { return Object{{"type", t}} }

func stringArray() Object { return Object{{"type", "array"}, {"items", typed("string")}} }

func ref(target string) Object { return Object{{"$ref", target}} }

// nullable is s, or nil (JSON null) when s is empty.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// list is s, or an empty non-nil slice (JSON []) when s is nil.
func list(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
