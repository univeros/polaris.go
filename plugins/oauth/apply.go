package oauth

import (
	"encoding/base64"
	"fmt"
	"maps"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

var (
	absoluteURI = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://[^\s#]+$`)
	basicHeader = regexp.MustCompile(`(?i)^Basic\s+(\S+)$`)
	// browserSchemes are schemes a browser would run or open: never a redirect URI.
	browserSchemes = []string{"javascript", "data", "vbscript", "file", "blob", "about"}
	loopbackHosts  = []string{"localhost", "127.0.0.1", "[::1]"}
)

func invalidMetadata(format string, args ...any) *Error {
	return refusal(CodeInvalidClientMetadata, fmt.Sprintf(format, args...))
}

// set reports whether key is present and not null.
func (f ClientFields) set(key string) bool { v, ok := f[key]; return ok && v != nil }

// has reports whether key is present, null included.
func (f ClientFields) has(key string) bool { _, ok := f[key]; return ok }

// apply validates fields onto a copy of c: what is given is checked and replaces what c holds;
// creating, the absent fields take their defaults. The result is checked as a whole.
func (s *clients) apply(c Client, f ClientFields, mayTrust, creating bool) (Client, error) {
	if f.set("name") || creating {
		name, ok := f["name"].(string)
		name = strings.Trim(name, " \t\n\r\x00\x0B")
		if !ok || name == "" || utf8.RuneCountInString(name) > 160 {
			return c, invalidMetadata("name is required, at most 160 characters.")
		}
		c.Name = name
	}
	if f.set("type") || creating {
		typ := TypeConfidential
		if f.set("type") {
			typ, _ = f["type"].(string)
		}
		if typ != TypeConfidential && typ != TypePublic {
			return c, invalidMetadata("type is confidential or public.")
		}
		c.Type = typ
	}
	if f.set("redirect_uris") {
		uris, err := validURIs(f["redirect_uris"], "redirect_uris", true)
		if err != nil {
			return c, err
		}
		c.RedirectURIs = uris
	}
	if f.set("grant_types") || creating {
		grants := []any{GrantAuthorizationCode, GrantRefreshToken}
		if f.set("grant_types") {
			var ok bool
			if grants, ok = anyList(f["grant_types"]); !ok {
				return c, invalidMetadata("grant_types is a list.")
			}
		}
		out := []string{}
		for _, g := range grants {
			name, ok := g.(string)
			if !ok || !slices.Contains(allGrants, name) {
				if !ok {
					name = "?"
				}
				return c, invalidMetadata("Unsupported grant type \"%s\".", name)
			}
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
		c.GrantTypes = out
	}
	if f.set("scopes") || (f.set("scope") && creating) {
		var list []any
		ok := true
		if f.set("scopes") {
			list, ok = anyList(f["scopes"])
		} else {
			scope, _ := f["scope"].(string)
			for _, w := range strings.Split(scope, " ") {
				list = append(list, w)
			}
		}
		if !ok {
			return c, invalidMetadata("scopes is a list.")
		}
		out := []string{}
		for _, v := range list {
			name, isString := v.(string)
			if !isString || !s.scopes.known(name) {
				if !isString {
					name = "?"
				}
				return c, invalidMetadata("Unknown scope \"%s\".", name)
			}
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
		// A trusted client's permission scopes are its own authority (tokens.held): only an
		// operator changes them.
		if !mayTrust && c.Trusted && !slices.Equal(out, c.Scopes) {
			return c, invalidMetadata("Only an operator changes the scopes of a trusted client.")
		}
		c.Scopes = out
	}
	if f.set("token_endpoint_auth_method") || creating {
		method := AuthSecretBasic
		if c.Type == TypePublic {
			method = AuthNone
		}
		if f.set("token_endpoint_auth_method") {
			method, _ = f["token_endpoint_auth_method"].(string)
		}
		if !slices.Contains(allAuthMethods, method) {
			return c, invalidMetadata("token_endpoint_auth_method is client_secret_basic, client_secret_post, private_key_jwt or none.")
		}
		c.TokenEndpointAuthMethod = method
	}
	if f.has("jwks") {
		if f["jwks"] == nil {
			c.JWKS = nil
		} else {
			jwks, ok := f["jwks"].(map[string]any)
			if !ok || jwksKeys(jwks) == nil {
				return c, invalidMetadata("jwks is a JWK Set with keys.")
			}
			c.JWKS = maps.Clone(jwks)
		}
	}
	if f.has("jwks_uri") {
		c.JWKSURI = ""
		if f["jwks_uri"] != nil {
			uri, ok := f["jwks_uri"].(string)
			if !ok {
				return c, invalidMetadata("jwks_uri is a URL.")
			}
			if err := assertPublicHTTPSURL(uri, "jwks_uri"); err != nil {
				return c, err
			}
			c.JWKSURI = uri
		}
	}
	links := []struct {
		field string
		dst   *string
	}{{"logo_uri", &c.LogoURI}, {"client_uri", &c.ClientURI}, {"policy_uri", &c.PolicyURI}, {"tos_uri", &c.TosURI}}
	for _, link := range links {
		field, dst := link.field, link.dst
		if !f.has(field) {
			continue
		}
		*dst = ""
		if f[field] != nil {
			uris, err := validURIs([]any{f[field]}, field, false)
			if err != nil {
				return c, err
			}
			*dst = uris[0]
		}
	}
	if f.set("dpop_bound_access_tokens") {
		b, ok := f["dpop_bound_access_tokens"].(bool)
		if !ok {
			return c, invalidMetadata("dpop_bound_access_tokens is a boolean.")
		}
		c.DPoPBound = b
	}
	if mayTrust && f.set("trusted") {
		b, ok := f["trusted"].(bool)
		if !ok {
			return c, invalidMetadata("trusted is a boolean.")
		}
		c.Trusted = b
	}
	if f.has("disabled") && !creating {
		c.DisabledAt = nil
		if f["disabled"] == true {
			now := s.clock.Now()
			c.DisabledAt = &now
		}
	}
	return c, s.consistent(c, mayTrust)
}

// consistent checks the client as a whole.
func (s *clients) consistent(c Client, mayTrust bool) error {
	switch {
	case c.Type == TypePublic && c.TokenEndpointAuthMethod != AuthNone:
		return invalidMetadata("A public client authenticates with none.")
	case c.Type == TypeConfidential && c.TokenEndpointAuthMethod == AuthNone:
		return invalidMetadata("A confidential client needs a secret or a key.")
	case c.TokenEndpointAuthMethod == AuthPrivateKeyJWT && c.JWKS == nil && c.JWKSURI == "":
		return invalidMetadata("private_key_jwt needs jwks or jwks_uri.")
	case c.Type == TypePublic && c.AllowsGrant(GrantClientCredentials):
		return invalidMetadata("A public client cannot use client_credentials.")
	case c.AllowsGrant(GrantAuthorizationCode) && len(c.RedirectURIs) == 0:
		return invalidMetadata("redirect_uris is required for the authorization_code grant.")
	case c.DPoPBound && s.settings.dpop == DPoPOff:
		return invalidMetadata("DPoP is off on this server.")
	case !mayTrust && c.AllowsGrant(GrantCIBA):
		return invalidMetadata("The backchannel grant (CIBA) reaches people by name; an operator grants it.")
	case c.IsMetadataClient() && (c.AllowsGrant(GrantClientCredentials) || c.AllowsGrant(GrantTokenExchange)):
		return invalidMetadata("A client described by a metadata document may only act for a user (authorization_code, refresh_token, device_code).")
	}
	return nil
}

// validURIs checks a list of absolute URIs: https, http on loopback only, and for a redirect an
// application's reverse-domain scheme (com.example.app) but never a browser scheme.
func validURIs(v any, field string, redirect bool) ([]string, error) {
	list, ok := anyList(v)
	if !ok {
		return nil, invalidMetadata("%s is a list of URIs.", field)
	}
	out := []string{}
	for _, item := range list {
		uri, ok := item.(string)
		var parsed *url.URL
		if ok && absoluteURI.MatchString(uri) {
			parsed, _ = url.Parse(uri)
		}
		if parsed == nil {
			return nil, invalidMetadata("%s holds absolute URIs without a fragment.", field)
		}
		scheme := strings.ToLower(parsed.Scheme)
		host := strings.ToLower(parsed.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
		if scheme == "http" && !slices.Contains(loopbackHosts, host) {
			return nil, invalidMetadata("%s: http is accepted for loopback only; use https.", field)
		}
		if !redirect && scheme != "https" {
			return nil, invalidMetadata("%s must be https.", field)
		}
		if redirect && scheme != "https" && scheme != "http" && (!strings.Contains(scheme, ".") || slices.Contains(browserSchemes, scheme)) {
			return nil, invalidMetadata("%s: a custom scheme must be a reverse-domain name such as com.example.app.", field)
		}
		if !slices.Contains(out, uri) {
			out = append(out, uri)
		}
	}
	return out, nil
}

// anyList reads a JSON list ([]any or []string).
func anyList(v any) ([]any, bool) {
	switch l := v.(type) {
	case []any:
		return l, true
	case []string:
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// basicAuth reads HTTP Basic client authentication: both halves form-urldecoded (RFC 6749 §2.3.1).
func basicAuth(header string) (id, secret string, ok bool) {
	m := basicHeader.FindStringSubmatch(header)
	if m == nil {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		return "", "", false
	}
	user, password, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", false
	}
	if id, err = url.QueryUnescape(user); err != nil {
		id = user
	}
	if secret, err = url.QueryUnescape(password); err != nil {
		secret = password
	}
	return id, secret, true
}

// sortedKeys is m's keys in order.
func sortedKeys[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }
