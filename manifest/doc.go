// Package manifest loads the endpoint specs (api/**/*.yaml) that declare every Polaris route, checks
// request input against their field rules, and exports them: the JSON manifest and an OpenAPI 3.1
// document.
//
// A spec's route name comes from its file path ("auth/login.yaml" is "polaris.auth.login",
// a plugin's "agents/execute.yaml" is "polaris.agents.execute"); endpoints register under it.
// domain.class is kept only for the exports.
//
// Load core's directory first, then each plugin's, in registration order:
//
//	core, _ := fs.Sub(apispec.API, "api/core")
//	audit, _ := fs.Sub(apispec.API, "api/audit")
//	m, err := manifest.Load(core, audit)
//
// Validation errors encode as the 422 body core routes answer: {"errors": ["email is required."]}.
//
// Package manifest is part of the plugin SDK (wiring, endpoint, manifest, event, token): what a
// third-party plugin builds on. API.md states what is stable.
package manifest
