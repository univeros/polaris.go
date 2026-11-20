package oauth

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/repository"
)

const decisionEndpoint = "/oauth2/authorize/decision"

// serveAuthorize is GET /oauth2/authorize: validates and parks the request; a browser is sent to
// the consent page, an XHR client (Accept: application/json) or a server without a consent page
// gets the request's data; ?request=<id> alone answers a parked request's data.
func (p *Plugin) serveAuthorize(ctx context.Context, in *endpoint.Input) endpoint.Result {
	jsonOnly := p.settings.consentURL == "" || strings.Contains(in.Request.Header.Get("Accept"), "application/json")
	parked := text(in, "request")
	var (
		req pendingRequest
		c   *Client
		err error
	)
	if parked != "" {
		req, c, err = p.authorization.pending(ctx, parked)
	} else {
		req, c, err = p.authorization.start(ctx, func(k string) string { return in.String(k) })
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	if !jsonOnly && parked == "" {
		return noStore(endpoint.Result{Status: http.StatusFound}.
			WithHeader("Location", redirectWith(p.settings.consentURL, "request", req.ID)))
	}
	return noStore(endpoint.Data(http.StatusOK, map[string]any{
		"request": req.ID, "client": c.publicView(), "scopes": p.scopes.described(req.Scopes),
		"redirect_uri": req.RedirectURI, "state": null(req.State), "prompt": null(req.Prompt),
		"decision_endpoint": decisionEndpoint,
	}))
}

// serveDecision is POST /oauth2/authorize/decision: the signed-in user approves or refuses a parked
// request; a trusted client or scopes already granted need no approval.
func (p *Plugin) serveDecision(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	userID, org := tok.Subject(), actorOrg(tok)
	req, c, err := p.authorization.pending(ctx, text(in, "request"))
	if err != nil {
		return p.fail(ctx, err)
	}
	approve := true
	if v := in.Value("approve"); v == nil {
		needs, err := p.authorization.needsConsent(ctx, req, c, userID)
		if err != nil {
			return p.fail(ctx, err)
		}
		if needs {
			return refuse(refusalWith(CodeConsentRequired, "The user must approve the scopes: answer with approve true or false.", http.StatusConflict))
		}
	} else {
		approve = v == true
	}
	to, recorded, err := p.authorization.decide(ctx, req, c, userID, org, approve, authTimeOf(tok))
	if err != nil {
		return p.fail(ctx, err)
	}
	name := EventConsentDenied
	if approve {
		name = EventConsentGranted
	}
	p.emit(ctx, name, userID, c.ClientID, org, map[string]any{"scopes": list(req.Scopes), "recorded": recorded})
	return noStore(endpoint.Data(http.StatusOK, map[string]any{"redirect_to": to, "approved": approve}))
}

// serveUserinfo is GET|POST /oauth2/userinfo: the OpenID claims the token's scopes allow about
// its user. Only the provider's access tokens with openid qualify.
func (p *Plugin) serveUserinfo(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	scope, _ := tok.Claim(ClaimScope).(string)
	scopes := words(scope)
	const description = "An access token with the openid scope is required."
	user, err := p.graph.Repos().Users.Get(ctx, tok.Subject())
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return p.fail(ctx, err)
	}
	if !hasAMR(tok) || !slices.Contains(scopes, ScopeOpenID) || err != nil {
		return noStore(endpoint.JSON(http.StatusUnauthorized, map[string]any{"error": CodeInvalidToken, "error_description": description}).
			WithHeader("WWW-Authenticate", `Bearer error="invalid_token", error_description="`+description+`"`))
	}
	body := map[string]any{"sub": user.ID}
	claims := openIDClaims(user, scopes)
	for _, name := range claims.Names() {
		body[name], _ = claims.Get(name)
	}
	return noStore(endpoint.JSON(http.StatusOK, body))
}

// serveRevoke is POST /oauth2/revoke (RFC 7009): the client's own token stops.
func (p *Plugin) serveRevoke(ctx context.Context, in *endpoint.Input) endpoint.Result {
	c, err := p.authenticated(ctx, in, "/oauth2/revoke")
	if err != nil {
		return p.fail(ctx, err)
	}
	raw := text(in, "token")
	if raw == "" {
		return refuse(refusal(CodeInvalidRequest, "token is required."))
	}
	revoked, err := p.tokens.revoke(ctx, raw, *c)
	if err != nil {
		return p.fail(ctx, err)
	}
	if revoked != nil {
		p.emit(ctx, EventTokenRevoked, revoked.UserID, c.ClientID, revoked.OrganizationID, map[string]any{"kind": revoked.Kind})
	}
	return noStore(endpoint.Data(http.StatusOK, map[string]any{"status": "revoked"}))
}

// serveIntrospect is POST /oauth2/introspect (RFC 7662), for clients that authenticate.
func (p *Plugin) serveIntrospect(ctx context.Context, in *endpoint.Input) endpoint.Result {
	c, err := p.authenticated(ctx, in, "/oauth2/introspect")
	if err != nil {
		return p.fail(ctx, err)
	}
	if c.TokenEndpointAuthMethod == AuthNone {
		return refuse(unauthorizedClient("Introspection is for clients that authenticate (RFC 7662 §2.1)."))
	}
	raw := text(in, "token")
	if raw == "" {
		return refuse(refusal(CodeInvalidRequest, "token is required."))
	}
	out, err := p.tokens.introspect(ctx, raw)
	if err != nil {
		return p.fail(ctx, err)
	}
	return noStore(endpoint.JSON(http.StatusOK, out))
}

// serveRegister is POST /oauth2/register (RFC 7591), when dynamic registration is on.
func (p *Plugin) serveRegister(ctx context.Context, in *endpoint.Input) endpoint.Result {
	if !p.settings.dynamicRegistration {
		return refuse(refusalWith(CodeRegistrationDisabled, "Dynamic client registration is off on this server; ask an operator or an organization admin for a client.", http.StatusForbidden))
	}
	fields := ClientFields(in.All())
	if name, ok := fields["client_name"]; ok && name != nil {
		fields["name"] = name
	}
	fields["type"] = TypeConfidential
	if fields["token_endpoint_auth_method"] == AuthNone {
		fields["type"] = TypePublic
	}
	if scope, ok := fields["scope"].(string); ok && !fields.has("scopes") {
		fields["scopes"] = []any{}
		if scope != "" {
			fields["scopes"], _ = anyList(strings.Split(scope, " "))
		}
	}
	issued, err := p.clients.create(ctx, fields, "", "", false)
	if err != nil {
		return p.fail(ctx, err)
	}
	p.emit(ctx, EventClientCreated, "", issued.Client.ClientID, "", map[string]any{"name": issued.Client.Name, "how": "dynamic_registration"})
	body := issued.Client.view()
	body["client_name"] = issued.Client.Name
	for _, k := range []string{"id", "organization_id", "created_by", "trusted", "disabled_at"} {
		delete(body, k)
	}
	if issued.Secret != "" {
		body["client_secret"] = issued.Secret
		body["client_secret_expires_at"] = 0
	}
	return noStore(endpoint.JSON(http.StatusCreated, body))
}

// serveOpenIDConfiguration is GET /.well-known/openid-configuration.
func (p *Plugin) serveOpenIDConfiguration(context.Context, *endpoint.Input) endpoint.Result {
	return endpoint.JSON(http.StatusOK, p.openIDConfiguration()).WithHeader("Cache-Control", "public, max-age=3600")
}

// serveAuthorizationServer is GET /.well-known/oauth-authorization-server (RFC 8414).
func (p *Plugin) serveAuthorizationServer(context.Context, *endpoint.Input) endpoint.Result {
	return endpoint.JSON(http.StatusOK, p.authorizationServer()).WithHeader("Cache-Control", "public, max-age=3600")
}

// serveConsents is GET /oauth2/consents: every client the caller approved.
func (p *Plugin) serveConsents(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	all, err := p.consents.forUser(ctx, tok.Subject())
	if err != nil {
		return p.fail(ctx, err)
	}
	data := []map[string]any{}
	for _, consent := range all {
		v := consent.view()
		if v["client"], err = p.publicClient(ctx, consent.ClientID); err != nil {
			return p.fail(ctx, err)
		}
		data = append(data, v)
	}
	return endpoint.Data(http.StatusOK, data)
}

// publicClient is the public view of a client, nil when it is gone or its document cannot be read.
func (p *Plugin) publicClient(ctx context.Context, clientID string) (any, error) {
	c, err := p.clients.find(ctx, clientID)
	var oe *Error
	if errors.As(err, &oe) {
		return nil, nil
	}
	if err != nil || c == nil {
		return nil, err
	}
	return c.publicView(), nil
}

// serveConsentRevoke is DELETE /oauth2/consents/{clientId}: the consent and the client's tokens for
// the caller go.
func (p *Plugin) serveConsentRevoke(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	clientID, userID := in.String("clientId"), tok.Subject()
	found, err := p.consents.revoke(ctx, userID, clientID)
	if err != nil {
		return p.fail(ctx, err)
	}
	if !found {
		return endpoint.Problem(http.StatusNotFound, "oauth/not_found", "Not found", "You have not granted that client anything.", nil)
	}
	n, err := p.tokens.revokeWhere(ctx, map[string]any{"user_id": userID, "client_id": clientID})
	if err != nil {
		return p.fail(ctx, err)
	}
	p.emit(ctx, EventConsentRevoked, userID, clientID, actorOrg(tok), map[string]any{"tokens_revoked": n})
	return endpoint.Data(http.StatusOK, map[string]any{"status": "revoked", "tokens_revoked": n})
}
