// Package apispec embeds the route specs every Polaris endpoint is built from: api/<package>/**/*.yaml
// (method, path, input rules, output, errors, events) and api/core/schema.json. They are the
// router and the source of the OpenAPI document; edit them with the endpoint they describe.
// fixtures/<package> holds the recorded request/response contract tests internal/contracttest
// replays.
package apispec

import "embed"

// API holds api/<package>/**/*.yaml and api/core/schema.json.
//
//go:embed api
var API embed.FS
