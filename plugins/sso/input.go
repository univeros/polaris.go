package sso

import (
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

var roleSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// providerInput validates a provider from a request body: the new provider's fields, or the
// errors (the first is the problem's detail). With existing (a PATCH), absent fields keep the
// provider's values and the type cannot change.
func providerInput(body map[string]any, existing *Provider) (Provider, []string) {
	typ, _ := body["type"].(string)
	if existing != nil {
		typ = existing.Type
	}
	if typ != TypeSAML && typ != TypeOIDC {
		return Provider{}, []string{"type must be saml or oidc."}
	}
	var errs []string
	keep := func(key string) bool { return existing != nil && body[key] == nil }
	text := func(key, current string) string {
		if s, ok := body[key].(string); ok {
			return trimBlank(s)
		}
		if existing != nil {
			return current
		}
		return ""
	}
	var cur Provider
	if existing != nil {
		cur = *existing
	}
	p := Provider{Type: typ, Name: text("name", cur.Name), Issuer: text("issuer", cur.Issuer)}
	if p.Name == "" || utf8.RuneCountInString(p.Name) > 120 {
		errs = append(errs, "name must be 1 to 120 characters.")
	}
	if p.Issuer == "" || utf8.RuneCountInString(p.Issuer) > 512 {
		errs = append(errs, "issuer is required (the IdP entity id, or the OIDC issuer URL).")
	}

	config, isMap := body["config"].(map[string]any)
	switch {
	case !isMap && keep("config"):
		config = withoutSecret(cur.Config) // the stored secret stays as it is
	case !isMap && body["config"] != nil:
		errs = append(errs, "config must be an object.")
	}
	p.Config, errs = configOf(typ, config, errs)

	p.Attributes = map[string]string{}
	if attributes, ok := body["attributes"].(map[string]any); ok || !keep("attributes") {
		if !ok && body["attributes"] != nil {
			errs = append(errs, "attributes must map field names to claim or attribute names.")
		}
		for _, field := range sortedAnyKeys(attributes) {
			claim, ok := attributes[field].(string)
			if !ok || claim == "" {
				errs = append(errs, "attributes must map field names to claim or attribute names.")
				break
			}
			p.Attributes[field] = claim
		}
	} else {
		p.Attributes = cur.Attributes
	}

	if jit, ok := body["jit"].(map[string]any); ok || !keep("jit") {
		if !ok && body["jit"] != nil {
			errs = append(errs, "jit must be an object.")
		}
		enabled, isBool := jit["enabled"].(bool)
		if !isBool && jit["enabled"] != nil {
			errs = append(errs, "jit.enabled must be a boolean.")
		}
		p.JIT.Enabled = enabled
		roles, isList := jit["roles"].([]any)
		if !isList && jit["roles"] != nil {
			errs = append(errs, "jit.roles must be a list of role slugs.")
		}
		p.JIT.Roles = []string{}
		for _, r := range roles {
			slug, ok := r.(string)
			if !ok || !roleSlug.MatchString(slug) {
				errs = append(errs, "jit.roles must be a list of role slugs.")
				break
			}
			p.JIT.Roles = append(p.JIT.Roles, slug)
		}
	} else {
		p.JIT = cur.JIT
	}

	uris, ok := body["redirect_uris"].([]any)
	valid := true
	switch {
	case !ok && keep("redirect_uris"):
		uris = make([]any, len(cur.RedirectURIs))
		for i, u := range cur.RedirectURIs {
			uris[i] = u
		}
	case !ok && body["redirect_uris"] != nil:
		errs = append(errs, "redirect_uris must be a list of http(s) URLs.")
		valid = false
	}
	p.RedirectURIs = []string{}
	for _, u := range uris {
		s, ok := u.(string)
		if !ok || !validURL(s) {
			errs = append(errs, "redirect_uris must be a list of http(s) URLs.")
			valid = false
			break
		}
		p.RedirectURIs = append(p.RedirectURIs, s)
	}
	if valid && len(p.RedirectURIs) == 0 {
		errs = append(errs, "redirect_uris needs at least one URL the sign-in may end on.")
	}

	p.Enabled = existing == nil || cur.Enabled
	if v := body["enabled"]; v != nil {
		b, ok := v.(bool)
		if !ok {
			errs = append(errs, "enabled must be a boolean.")
		}
		p.Enabled = b
	}
	return p, errs
}

// configOf keeps the members of the type's configuration, non-empty, and checks them.
func configOf(typ string, config map[string]any, errs []string) (map[string]any, []string) {
	keys := oidcKeys
	if typ == TypeSAML {
		keys = samlKeys
	}
	clean := map[string]any{}
	for _, k := range keys {
		if v := config[k]; v != nil && v != "" {
			clean[k] = v
		}
	}
	if typ == TypeSAML {
		for _, k := range []string{"sso_url", "slo_url", "slo_response_url"} {
			if v, set := clean[k]; set {
				if s, ok := v.(string); !ok || !validURL(s) {
					errs = append(errs, "config."+k+" must be an http(s) URL.")
				}
			}
		}
		if _, set := clean["sso_url"]; !set {
			errs = append(errs, "config.sso_url is required.")
		}
		if _, ok := clean["certificate"].(string); !ok {
			errs = append(errs, "config.certificate (the IdP signing certificate, PEM or base64) is required.")
		}
		if v, set := clean["idp_initiated"]; set {
			if _, ok := v.(bool); !ok {
				errs = append(errs, "config.idp_initiated must be a boolean.")
			}
		}
		return clean, errs
	}
	if _, ok := clean["client_id"].(string); !ok {
		errs = append(errs, "config.client_id is required.")
	}
	for _, k := range []string{"client_secret", "scopes", "issuer"} {
		if v, set := clean[k]; set {
			if _, ok := v.(string); !ok {
				errs = append(errs, "config."+k+" must be a string.")
			}
		}
	}
	return clean, errs
}

// validURL is the check for every URL a provider names (the SAML endpoints the browser is sent
// to, the redirect URIs a sign-in ends on): an absolute http or https URL with a host, as
// net/url parses it, written in printable ASCII (RFC 3986: spaces, controls and other characters
// are percent-encoded).
func validURL(s string) bool {
	if strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r >= 0x7f }) {
		return false
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return (scheme == "http" || scheme == "https") && u.Host != ""
}

func sortedAnyKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func withoutSecret(config map[string]any) map[string]any {
	out := make(map[string]any, len(config))
	for k, v := range config {
		if k != secretKey {
			out[k] = v
		}
	}
	return out
}

// trimBlank strips surrounding spaces, tabs, newlines, carriage returns, NUL and vertical tabs
// (not the other Unicode spaces strings.TrimSpace strips). It trims what is stored and compared
// with stored values (a provider's name and issuer, a claimed domain), so it keeps the set
// earlier releases trimmed: the same input keeps naming the same row.
func trimBlank(s string) string { return strings.Trim(s, " \t\n\r\x00\x0b") }
