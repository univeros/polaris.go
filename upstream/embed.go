// Package upstream embeds the endpoint manifests mirrored from PHP polaris-core
// (docs/port/spec.md §2). Do not edit api/ or fixtures/ by hand: run scripts/sync-upstream.sh.
package upstream

import "embed"

// API holds api/<package>/**/*.yaml and api/core/schema.json, byte-identical to the pinned ref.
//
//go:embed api
var API embed.FS
