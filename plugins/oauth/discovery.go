package oauth

import "slices"

// authorizationServer is the RFC 8414 metadata: exactly what is enabled.
func (p *Plugin) authorizationServer() map[string]any {
	base := p.settings.baseURL
	grants := []string{GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials, GrantCIBA, GrantTokenExchange}
	if p.settings.deviceURL != "" {
		grants = append(grants, GrantDeviceCode)
	}
	doc := map[string]any{
		"issuer":                                           p.issuer,
		"authorization_endpoint":                           base + "/oauth2/authorize",
		"token_endpoint":                                   base + "/oauth2/token",
		"jwks_uri":                                         base + "/auth/.well-known/jwks.json",
		"revocation_endpoint":                              base + "/oauth2/revoke",
		"introspection_endpoint":                           base + "/oauth2/introspect",
		"backchannel_authentication_endpoint":              base + "/oauth2/ciba",
		"scopes_supported":                                 slices.Clone(p.scopes.names),
		"response_types_supported":                         []string{"code"},
		"response_modes_supported":                         []string{"query"},
		"grant_types_supported":                            grants,
		"token_endpoint_auth_methods_supported":            allAuthMethods,
		"token_endpoint_auth_signing_alg_values_supported": asymmetricAlgorithms,
		"revocation_endpoint_auth_methods_supported":       allAuthMethods,
		"introspection_endpoint_auth_methods_supported":    allAuthMethods,
		"code_challenge_methods_supported":                 []string{"S256"},
		"backchannel_token_delivery_modes_supported":       []string{"poll"},
		"backchannel_user_code_parameter_supported":        false,
		"authorization_response_iss_parameter_supported":   true,
		"client_id_metadata_document_supported":            p.settings.clientIDMetadata,
	}
	if p.settings.deviceURL != "" {
		doc["device_authorization_endpoint"] = base + "/oauth2/device/code"
	}
	if p.settings.dynamicRegistration {
		doc["registration_endpoint"] = base + "/oauth2/register"
	}
	if p.settings.dpop != DPoPOff {
		doc["dpop_signing_alg_values_supported"] = []string{"ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"}
	}
	return doc
}

// openIDConfiguration is OpenID Connect Discovery: the same plus the OpenID members.
func (p *Plugin) openIDConfiguration() map[string]any {
	doc := p.authorizationServer()
	doc["userinfo_endpoint"] = p.settings.baseURL + "/oauth2/userinfo"
	doc["subject_types_supported"] = []string{"public"}
	doc["id_token_signing_alg_values_supported"] = []string{string(p.graph.Auth.AccessToken.Signer)}
	doc["claims_supported"] = []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified", "name", "updated_at", "org"}
	doc["claims_parameter_supported"] = false
	doc["request_parameter_supported"] = false
	doc["request_uri_parameter_supported"] = false
	return doc
}
