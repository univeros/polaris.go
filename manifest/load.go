package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Manifest is every route Polaris exposes, as declared by the api/ spec files. It is immutable and
// safe for concurrent use.
type Manifest struct {
	routes    []*Route
	byPattern map[string]*Route
	byName    map[string]*Route
}

// Routes returns the routes in load order: core's, then each plugin's, each directory's files
// sorted by path.
func (m *Manifest) Routes() []*Route {
	return slices.Clone(m.routes)
}

// Find returns the route declared for method (any case) and the declared path ("/orgs/{id}").
func (m *Manifest) Find(method, path string) (*Route, bool) {
	r, ok := m.byPattern[strings.ToUpper(method)+" "+path]
	return r, ok
}

// Named returns the route with the given name ("polaris.auth.login").
func (m *Manifest) Named(name string) (*Route, bool) {
	r, ok := m.byName[name]
	return r, ok
}

// Load reads every *.yaml spec under each directory: core's api/ first, then each plugin's, in
// registration order (for the embedded upstream manifests, fs.Sub(upstream.API, "api/core"), then
// fs.Sub(upstream.API, "api/<package>")). A spec in a later directory belongs to the plugin named by
// its first path segment ("audit/me.yaml" is plugin "audit").
//
// Load fails on the first invalid spec: a missing or unknown endpoint.method, path, auth or effect,
// an unknown input source or session, a missing domain.class, an unparsable rule, an error without
// a status, or a route (method and path) or route name declared twice.
func Load(dirs ...fs.FS) (*Manifest, error) {
	if len(dirs) == 0 {
		return nil, errors.New("manifest: no spec directory given; pass core's api directory first")
	}
	m := &Manifest{byPattern: map[string]*Route{}, byName: map[string]*Route{}}
	for i, dir := range dirs {
		files, err := specFiles(dir)
		if err != nil {
			return nil, err
		}
		for _, file := range files {
			r, err := parseFile(dir, file, i > 0)
			if err != nil {
				return nil, err
			}
			if prev, ok := m.byPattern[r.Pattern()]; ok {
				return nil, fmt.Errorf("%s declares route %s already declared by %s.", r.File, r.Pattern(), prev.File)
			}
			if prev, ok := m.byName[r.Name]; ok {
				return nil, fmt.Errorf("%s declares route name %s already declared by %s.", r.File, r.Name, prev.File)
			}
			m.byPattern[r.Pattern()], m.byName[r.Name] = r, r
			m.routes = append(m.routes, r)
		}
	}
	return m, nil
}

func specFiles(dir fs.FS) ([]string, error) {
	var files []string
	err := fs.WalkDir(dir, ".", func(path string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".yaml") {
			files = append(files, path)
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("manifest: reading spec directory: %w", err)
	}
	slices.Sort(files) // whole paths, as upstream sorts them: "a-b.yaml" before "a/b.yaml"
	return files, nil
}

func parseFile(dir fs.FS, file string, plugin bool) (*Route, error) {
	data, err := fs.ReadFile(dir, file)
	if err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	var node yaml.Node
	if err := yaml.Unmarshal(data, &node); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var document any
	if len(node.Content) > 0 {
		if document, err = fromNode(node.Content[0]); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
	}
	r, err := parse(document, file)
	if err != nil {
		return nil, err
	}
	if plugin {
		r.Plugin, _, _ = strings.Cut(file, "/")
	}
	return r, nil
}

// fromNode turns a YAML node into strings, ints, float64s, bools, nils, []anys and Objects.
func fromNode(n *yaml.Node) (any, error) {
	switch n.Kind {
	case yaml.AliasNode:
		return fromNode(n.Alias)
	case yaml.SequenceNode:
		list := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := fromNode(c)
			if err != nil {
				return nil, err
			}
			list = append(list, v)
		}
		return list, nil
	case yaml.MappingNode:
		object := make(Object, 0, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			if _, ok := object.Get(key); ok {
				return nil, fmt.Errorf("line %d: mapping key %q already defined", n.Content[i].Line, key)
			}
			v, err := fromNode(n.Content[i+1])
			if err != nil {
				return nil, err
			}
			object = append(object, Member{key, v})
		}
		return object, nil
	}
	var v any
	err := n.Decode(&v)
	return v, err
}

func parse(document any, file string) (*Route, error) {
	doc, ok := asMap(document)
	if !ok {
		return nil, fmt.Errorf("%s is not a spec document.", file)
	}
	endpoint, err := section(doc, "endpoint", file)
	if err != nil {
		return nil, err
	}
	domain, err := section(doc, "domain", file)
	if err != nil {
		return nil, err
	}
	input, ok := asMap(get(doc, "input"))
	if !ok {
		input = Object{{"source", "none"}}
	}
	output, _ := asMap(get(doc, "output"))

	r := &Route{File: file, Name: routeName(file)}
	// Checked in upstream's order, so a spec with several faults reports the same one.
	method, err := required(endpoint, "method", file)
	if err != nil {
		return nil, err
	}
	auth, err := required(endpoint, "auth", file)
	if err != nil {
		return nil, err
	}
	effect, err := required(endpoint, "effect", file)
	if err != nil {
		return nil, err
	}
	source, ok := get(input, "source").(string)
	if !ok {
		source = string(SourceNone)
	}
	r.Method, r.Auth, r.Effect, r.Input.Source = strings.ToUpper(method), Auth(auth), Effect(effect), Source(source)
	if !slices.Contains(Auths, r.Auth) {
		return nil, fmt.Errorf("%s: unknown auth %q.", file, auth)
	}
	if !slices.Contains(Effects, r.Effect) {
		return nil, fmt.Errorf("%s: unknown effect %q.", file, effect)
	}
	if !slices.Contains(Sources, r.Input.Source) {
		return nil, fmt.Errorf("%s: unknown input source %q.", file, source)
	}
	if session := get(endpoint, "session"); session != nil {
		s, _ := session.(string)
		if !slices.Contains(Sessions, Session(s)) {
			return nil, fmt.Errorf("%s: unknown session %q.", file, debugString(session))
		}
		r.Session = Session(s)
	}
	if r.Class, err = required(domain, "class", file); err != nil {
		return nil, err
	}
	if r.Path, err = required(endpoint, "path", file); err != nil {
		return nil, err
	}

	r.Summary, _ = get(endpoint, "summary").(string)
	r.Tags = stringList(get(endpoint, "tags"))
	r.RateLimit, _ = get(endpoint, "rate_limit").(string)
	r.Receipt = r.Effect != EffectRead
	if receipt := get(endpoint, "receipt"); receipt != nil {
		r.Receipt = truthy(receipt)
	}
	r.StepUp = truthy(get(endpoint, "step_up"))
	r.RequiresPermissions = stringList(get(endpoint, "requires_permissions"))
	r.Description, _ = get(domain, "description").(string)
	if r.Input.Fields, err = fields(get(input, "fields"), file); err != nil {
		return nil, err
	}
	r.Output.Status, _ = get(output, "status").(int)
	r.Output.Examples = examples(output)
	if r.Errors, err = errorList(get(doc, "errors"), file); err != nil {
		return nil, err
	}
	r.Events = stringList(get(doc, "events"))
	return r, nil
}

// routeName is "polaris." and the file's path without .yaml, slashes as dots, as the upstream
// framework adapters name their routes.
func routeName(file string) string {
	return "polaris." + strings.ReplaceAll(strings.TrimSuffix(file, ".yaml"), "/", ".")
}

func get(o Object, key string) any {
	v, _ := o.Get(key)
	return v
}

// asMap reports whether v is a YAML collection (PHP's is_array), giving its keys when it is a mapping.
func asMap(v any) (Object, bool) {
	switch v := v.(type) {
	case Object:
		return v, true
	case []any:
		return Object{}, true
	}
	return nil, false
}

func section(doc Object, key, file string) (Object, error) {
	s, ok := asMap(get(doc, key))
	if !ok {
		return nil, fmt.Errorf("%s: missing %q section.", file, key)
	}
	return s, nil
}

func required(section Object, key, file string) (string, error) {
	s, _ := get(section, key).(string)
	if s == "" {
		return "", fmt.Errorf("%s: %q is required.", file, key)
	}
	return s, nil
}

// values is a YAML collection's values (PHP's array_values); nothing for a scalar.
func values(v any) []any {
	switch v := v.(type) {
	case []any:
		return v
	case Object:
		out := make([]any, 0, len(v))
		for _, m := range v {
			out = append(out, m.Value)
		}
		return out
	}
	return nil
}

// stringList reads a YAML collection of scalars as strings.
func stringList(v any) []string {
	list := values(v)
	out := make([]string, 0, len(list))
	for _, x := range list {
		out = append(out, scalarString(x))
	}
	return out
}

// scalarString converts a YAML scalar to a string as PHP's (string) cast does.
func scalarString(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case bool:
		if v {
			return "1"
		}
		return ""
	case int:
		return strconv.Itoa(v)
	case float64:
		return strconv.FormatFloat(v, 'G', 14, 64)
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// debugString names a value the way upstream's error messages do: scalars as text, others by type.
func debugString(v any) string {
	switch v.(type) {
	case Object, []any:
		return "array"
	}
	return scalarString(v)
}

// truthy is PHP's (bool) cast of a YAML value.
func truthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	case int:
		return v != 0
	case float64:
		return v != 0
	case string:
		return v != "" && v != "0"
	case Object:
		return len(v) > 0
	case []any:
		return len(v) > 0
	}
	return true
}

func fields(v any, file string) ([]Field, error) {
	defs, _ := v.(Object)
	if list, ok := v.([]any); ok {
		for i, x := range list {
			defs = append(defs, Member{strconv.Itoa(i), x})
		}
	}
	var out []Field
	for _, m := range defs {
		def, ok := asMap(m.Value)
		if !ok {
			return nil, fmt.Errorf("%s: field %q must be a map.", file, m.Key)
		}
		f := Field{Name: m.Key, Type: "string", Sensitive: truthy(get(def, "sensitive"))}
		if t, ok := get(def, "type").(string); ok {
			f.Type = t
		}
		for _, text := range stringList(get(def, "rules")) {
			rule, err := ParseRule(text)
			if err != nil {
				return nil, fmt.Errorf("%s: field %q: %w", file, m.Key, err)
			}
			f.Rules = append(f.Rules, rule)
		}
		out = append(out, f)
	}
	return out, nil
}

func examples(output Object) []Example {
	var out []Example
	for _, m := range output {
		if m.Key != "example" && !strings.HasPrefix(m.Key, "example_") {
			continue
		}
		if _, ok := asMap(m.Value); ok {
			out = append(out, Example{m.Key, m.Value})
		}
	}
	return out
}

func errorList(v any, file string) ([]Error, error) {
	var out []Error
	for _, x := range values(v) {
		e, _ := x.(Object)
		status, isInt := get(e, "status").(int)
		code, isString := get(e, "code").(string)
		if e == nil || !isInt || (get(e, "code") != nil && !isString) {
			return nil, fmt.Errorf("%s: every error needs a status and a code (null for a codeless body).", file)
		}
		out = append(out, Error{Status: status, Code: code})
	}
	return out, nil
}
