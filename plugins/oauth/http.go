package oauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/token"
)

// noStore are the headers of a response that must never be cached (token responses, RFC 6749
// §5.1, and every OAuth refusal).
func noStore(r endpoint.Result) endpoint.Result {
	return r.WithHeader("Cache-Control", "no-store").WithHeader("Pragma", "no-cache")
}

// refuse answers an OAuth refusal: an RFC 9457 problem whose error is the RFC 6749 code, with
// error_description.
func refuse(e *Error) endpoint.Result {
	words := strings.Fields(strings.ReplaceAll(e.Code, "_", " "))
	for i, w := range words {
		words[i] = strings.ToUpper(w[:1]) + w[1:]
	}
	res := noStore(endpoint.Result{Status: e.Status, Problem: true, Body: map[string]any{
		"type":              endpoint.ProblemTypes + "oauth/" + e.Code,
		"title":             strings.Join(words, " "),
		"status":            e.Status,
		"detail":            e.Description,
		"error":             e.Code,
		"error_description": e.Description,
		"message":           e.Description,
	}})
	if e.Code == CodeInvalidClient && e.Status == http.StatusUnauthorized {
		res = res.WithHeader("WWW-Authenticate", `Basic realm="oauth"`)
	}
	return res
}

// fail answers err: an OAuth refusal as such, anything else a logged 500.
func (p *Plugin) fail(ctx context.Context, err error) endpoint.Result {
	var oe *Error
	if errors.As(err, &oe) {
		return refuse(oe)
	}
	p.graph.Logger().ErrorContext(ctx, "oauth: request failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

// text is a trimmed string input, "" when absent, not a string or blank.
func text(in *endpoint.Input, key string) string { return strings.TrimSpace(in.String(key)) }

// actorOrg is the principal's active organization.
func actorOrg(t *token.Token) string { return t.Organization() }

// endpoints maps every route name to its endpoint.
func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	f := func(fn func(context.Context, *endpoint.Input) endpoint.Result) endpoint.Endpoint {
		return endpoint.Func(fn)
	}
	return map[string]endpoint.Endpoint{
		"polaris.oauth.authorize":            f(p.serveAuthorize),
		"polaris.oauth.decision":             f(p.serveDecision),
		"polaris.oauth.token":                f(p.serveToken),
		"polaris.oauth.revoke":               f(p.serveRevoke),
		"polaris.oauth.introspect":           f(p.serveIntrospect),
		"polaris.oauth.userinfo":             f(p.serveUserinfo),
		"polaris.oauth.userinfo-post":        f(p.serveUserinfo),
		"polaris.oauth.register":             f(p.serveRegister),
		"polaris.oauth.device-code":          f(p.serveDeviceCode),
		"polaris.oauth.device-verify":        f(p.serveDeviceVerify),
		"polaris.oauth.device-approve":       f(p.serveDeviceApprove),
		"polaris.oauth.ciba":                 f(p.serveCIBA),
		"polaris.oauth.ciba-pending":         f(p.serveCIBAPending),
		"polaris.oauth.ciba-decide":          f(p.serveCIBADecide),
		"polaris.oauth.consents-list":        f(p.serveConsents),
		"polaris.oauth.consents-revoke":      f(p.serveConsentRevoke),
		"polaris.oauth.openid-configuration": f(p.serveOpenIDConfiguration),
		"polaris.oauth.authorization-server": f(p.serveAuthorizationServer),
		"polaris.oauth.org-clients-list":     f(p.serveOrgClientsList),
		"polaris.oauth.org-clients-create":   f(p.serveOrgClientsCreate),
		"polaris.oauth.org-clients-read":     f(p.serveOrgClientsRead),
		"polaris.oauth.org-clients-update":   f(p.serveOrgClientsUpdate),
		"polaris.oauth.org-clients-delete":   f(p.serveOrgClientsDelete),
		"polaris.oauth.admin-clients-list":   f(p.serveAdminClientsList),
		"polaris.oauth.admin-clients-create": f(p.serveAdminClientsCreate),
		"polaris.oauth.admin-clients-delete": f(p.serveAdminClientsDelete),
	}
}

// authenticated is the client the request authenticates as, for path (a signed assertion's
// audience; the issuer is accepted too).
func (p *Plugin) authenticated(ctx context.Context, in *endpoint.Input, path string) (*Client, error) {
	return p.clients.authenticate(ctx, clientCredentials(in.Request, in.All()), p.settings.baseURL+path, p.issuer)
}

// proof is the thumbprint of the DPoP key the request proved, "" without a proof; a client
// registered for DPoP-bound tokens, or a server requiring DPoP, must prove one.
func (p *Plugin) proof(ctx context.Context, r *http.Request, c *Client) (string, error) {
	if p.settings.dpop == DPoPOff {
		return "", nil
	}
	jkt, err := p.dpop.verify(ctx, r.Header.Get(DPoPHeader), r.Method, requestURL(r), "")
	if err != nil {
		return "", err
	}
	if jkt == "" && (p.settings.dpop == DPoPRequired || (c != nil && c.DPoPBound)) {
		return "", refusal(CodeInvalidDPoPProof, "A DPoP proof is required.")
	}
	return jkt, nil
}

// checkResource validates a resource parameter (RFC 8707).
func checkResource(resource, description string) error {
	if resource != "" && !resourceFormat.MatchString(resource) {
		return refusal(CodeInvalidTarget, description)
	}
	return nil
}
