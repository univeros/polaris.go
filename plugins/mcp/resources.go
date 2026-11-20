package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/manifest"
)

// The server's resources.
const (
	// ResourceManifest is the OpenAPI 3.1 document of every route, core and plugins.
	ResourceManifest = "polaris://manifest"
	// ResourceSchema is the DDL of every table (listed when Config.Schema is set).
	ResourceSchema = "polaris://schema"
	// ResourceProblems is the template of a plugin's problem type: its URL, statuses and routes.
	ResourceProblems = "polaris://problems/{plugin}/{name}"
)

var problemTemplate = map[string]any{
	"uriTemplate": ResourceProblems,
	"name":        "problem",
	"title":       "A problem type",
	"description": "An RFC 9457 problem type a plugin answers (https://polaris.univeros.io/problems/<plugin>/<name>): its statuses and routes.",
	"mimeType":    "application/json",
}

func (p *Plugin) resources() []any {
	list := []any{map[string]any{"uri": ResourceManifest, "name": "manifest", "title": "The Polaris manifest",
		"description": "OpenAPI 3.1 document of every Polaris route, core and plugins.", "mimeType": "application/json"}}
	if p.cfg.Schema != nil {
		list = append(list, map[string]any{"uri": ResourceSchema, "name": "schema", "title": "The Polaris schema",
			"description": "The DDL of every Polaris table (core and plugins) for PostgreSQL, as polaris schema:export prints it.", "mimeType": "text/x-sql"})
	}
	return list
}

func (p *Plugin) readResource(ctx context.Context, uri string) (map[string]any, *rpcError) {
	var text, mime string
	switch {
	case uri == ResourceManifest:
		raw, _ := json.MarshalIndent(p.g.Manifest().OpenAPI(manifest.UpstreamVersion), "", "    ")
		text, mime = string(raw), "application/json"
	case uri == ResourceSchema && p.cfg.Schema != nil:
		ddl, err := p.cfg.Schema(ctx)
		if err != nil {
			p.g.Logger().ErrorContext(ctx, "polaris mcp: schema export failed", "error", err)
			return nil, newError(codeInternal, http.StatusInternalServerError, "Internal server error.")
		}
		text, mime = ddl, "text/x-sql"
	case strings.HasPrefix(uri, "polaris://problems/"):
		doc, rerr := p.problem(strings.TrimPrefix(uri, "polaris://problems/"))
		if rerr != nil {
			return nil, rerr
		}
		raw, _ := json.MarshalIndent(doc, "", "    ")
		text, mime = string(raw), "application/json"
	default:
		return nil, newError(codeResourceNotFound, http.StatusBadRequest, "Resource \"%s\" not found.", uri)
	}
	return map[string]any{"contents": []any{map[string]any{"uri": uri, "mimeType": mime, "text": text}}}, nil
}

// problem describes the problem type plugin/name as the manifest declares it: the statuses and
// routes answering an error code name (or plugin_name).
func (p *Plugin) problem(path string) (manifest.Object, *rpcError) {
	plugin, name, _ := strings.Cut(path, "/")
	var statuses []int
	var routes []string
	for _, rt := range p.g.Manifest().Routes() {
		if rt.Plugin != plugin || plugin == "" {
			continue
		}
		for _, e := range rt.Errors {
			if e.Code != "" && (e.Code == name || e.Code == plugin+"_"+name) {
				if !slices.Contains(statuses, e.Status) {
					statuses = append(statuses, e.Status)
				}
				if !slices.Contains(routes, rt.Pattern()) {
					routes = append(routes, rt.Pattern())
				}
			}
		}
	}
	if len(routes) == 0 {
		return nil, newError(codeInvalidParams, http.StatusBadRequest, "No plugin declares the problem %s/%s.", plugin, name)
	}
	slices.Sort(statuses)
	return manifest.Object{
		{Key: "type", Value: endpoint.ProblemTypes + plugin + "/" + name},
		{Key: "title", Value: title(name)},
		{Key: "status", Value: statuses},
		{Key: "routes", Value: routes},
	}, nil
}
