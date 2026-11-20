package mcp

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/univeros/polaris-go/manifest"
	"github.com/univeros/polaris-go/pipeline"
	"github.com/univeros/polaris-go/wiring"
)

var pathParam = regexp.MustCompile(`\{(\w+)\}`)

// ToolName is a route's tool name: its route name with "-" read as "." ("polaris.orgs.members.list").
func ToolName(rt *manifest.Route) string { return strings.ReplaceAll(rt.Name, "-", ".") }

// toolSchema is a route's tool schemas, folded from its OpenAPI operation.
type toolSchema struct {
	input, output manifest.Object
}

// schemasOf folds each route's OpenAPI operation into one input object (path parameters, query
// parameters, body properties, with required) and an output object {status, body}, the body typed
// from the spec's example as the OpenAPI document types it.
func schemasOf(m *manifest.Manifest) map[string]toolSchema {
	paths := at(m.OpenAPI(manifest.UpstreamVersion), "paths")
	out := map[string]toolSchema{}
	for _, rt := range m.Routes() {
		op := at(paths, rt.Path, strings.ToLower(rt.Method))
		out[rt.Name] = toolSchema{input: inputSchema(op), output: outputSchema(rt, op)}
	}
	return out
}

func get(o manifest.Object, key string) any {
	v, _ := o.Get(key)
	return v
}

// at follows keys through nested objects; nil when one is missing.
func at(o manifest.Object, keys ...string) manifest.Object {
	for _, k := range keys {
		o, _ = get(o, k).(manifest.Object)
	}
	return o
}

func inputSchema(op manifest.Object) manifest.Object {
	var properties manifest.Object
	var required []string
	params, _ := get(op, "parameters").([]any)
	for _, raw := range params {
		param, _ := raw.(manifest.Object)
		name, _ := get(param, "name").(string)
		if name == "" {
			continue
		}
		schema, ok := get(param, "schema").(manifest.Object)
		if !ok {
			schema = manifest.Object{{Key: "type", Value: "string"}}
		}
		in, _ := get(param, "in").(string)
		properties = properties.With(name, schema.With("description", in+" parameter"))
		if get(param, "required") == true {
			required = append(required, name)
		}
	}
	body := at(op, "requestBody", "content", "application/json", "schema")
	props, _ := get(body, "properties").(manifest.Object)
	for _, p := range props {
		properties = properties.With(p.Key, p.Value)
	}
	bodyRequired, _ := get(body, "required").([]string)
	required = append(required, bodyRequired...)
	schema := manifest.Object{{Key: "type", Value: "object"}, {Key: "properties", Value: properties}}
	if len(required) > 0 {
		schema = append(schema, manifest.Member{Key: "required", Value: required})
	}
	return schema
}

func outputSchema(rt *manifest.Route, op manifest.Object) manifest.Object {
	status := rt.Output.Status
	if status == 0 {
		status = 200
	}
	body := at(op, "responses", strconv.Itoa(status), "content", "application/json", "schema")
	if body == nil {
		body = manifest.Object{{Key: "description", Value: "The response body"}}
	}
	return manifest.Object{
		{Key: "type", Value: "object"},
		{Key: "properties", Value: manifest.Object{
			{Key: "status", Value: manifest.Object{{Key: "type", Value: "integer"}, {Key: "description", Value: "The HTTP status the route answered"}}},
			{Key: "body", Value: body},
		}},
		{Key: "required", Value: []string{"status", "body"}},
	}
}

// routeTool is a route as a tool for caller.
func (p *Plugin) routeTool(rt *manifest.Route, c caller) wiring.Tool {
	s := p.schemas()[rt.Name]
	summary := rt.Summary
	if summary == "" {
		summary = rt.Pattern()
	}
	return wiring.Tool{
		Name:         ToolName(rt),
		Description:  fmt.Sprintf("%s (%s)", summary, rt.Pattern()),
		InputSchema:  s.input,
		OutputSchema: s.output,
		ReadOnly:     rt.Effect == manifest.EffectRead,
		Destructive:  rt.Effect == manifest.EffectDestructive,
		Call: func(ctx context.Context, args map[string]any) (wiring.ToolResult, error) {
			return p.call(ctx, rt, args, c)
		},
	}
}

// tools lists what caller may call: public routes (never an mfa_token one), bearer routes whose
// permissions the caller's authority holds and the delegation rule allows, routes tagged admin for
// an operator; then the tools of every plugin implementing wiring.ToolProvider. The mcp routes are
// not tools.
func (p *Plugin) tools(ctx context.Context, c caller) ([]wiring.Tool, error) {
	var allows func(...string) bool
	if c.token != nil {
		authority, err := p.g.Gate().Authority(ctx, wiring.Caller(c.token))
		if err != nil {
			return nil, err
		}
		allows = authority.Allows
	}
	var tools []wiring.Tool
	for _, rt := range p.g.Manifest().Routes() {
		if p.lists(rt, c, allows) {
			tools = append(tools, p.routeTool(rt, c))
		}
	}
	for _, plugin := range p.g.Plugins() {
		if tp, ok := plugin.(wiring.ToolProvider); ok {
			more, err := tp.MCPTools(ctx, c.token)
			if err != nil {
				return nil, fmt.Errorf("mcp: plugin %q tools: %w", plugin.ID(), err)
			}
			tools = append(tools, more...)
		}
	}
	return tools, nil
}

func (p *Plugin) lists(rt *manifest.Route, c caller, allows func(...string) bool) bool {
	switch {
	case rt.Plugin == ID || rt.Auth == manifest.AuthMfaToken:
		return false
	case slices.Contains(rt.Tags, tagAdmin):
		return c.operator
	case rt.Auth == manifest.AuthPublic:
		return true
	case c.token == nil:
		return false
	}
	probe := *rt
	if rt.Plugin != "" && strings.HasPrefix(rt.Path, orgRoute) {
		// A plugin's organization route is authorized against the organization in its path,
		// which the listing does not know: it is listed as a permissionless route would be (as
		// upstream lists it), and the call itself is authorized by the route.
		probe.RequiresPermissions = nil
	}
	return !pipeline.DeniesDelegate(&probe, c.token) && allows(probe.RequiresPermissions...)
}

const orgRoute = "/orgs/{id}/"
