package oauth

import (
	"context"
	"net/http"

	"github.com/univeros/polaris.go/endpoint"
)

// serveDeviceCode is POST /oauth2/device/code (RFC 8628 §3.1).
func (p *Plugin) serveDeviceCode(ctx context.Context, in *endpoint.Input) endpoint.Result {
	resp, err := func() (DeviceAuthorization, error) {
		c, err := p.authenticated(ctx, in, "/oauth2/device/code")
		if err != nil {
			return DeviceAuthorization{}, err
		}
		resource := text(in, "resource")
		if err := checkResource(resource, "resource must be an absolute URI."); err != nil {
			return DeviceAuthorization{}, err
		}
		scopes, err := p.scopes.parse(text(in, "scope"), c)
		if err != nil {
			return DeviceAuthorization{}, err
		}
		return p.devices.start(ctx, *c, scopes, resource)
	}()
	if err != nil {
		return p.fail(ctx, err)
	}
	return noStore(endpoint.JSON(http.StatusOK, resp))
}

// serveDeviceVerify is GET /oauth2/device/verify: the client and scopes behind a user code.
func (p *Plugin) serveDeviceVerify(ctx context.Context, in *endpoint.Input) endpoint.Result {
	if endpoint.Token(ctx) == nil {
		return endpoint.Unauthorized()
	}
	device, err := p.devices.byUserCode(ctx, text(in, "user_code"))
	if err != nil {
		return p.fail(ctx, err)
	}
	c, err := p.clients.find(ctx, device.ClientID)
	if err != nil {
		return p.fail(ctx, err)
	}
	if c == nil {
		return refuse(refusal(CodeInvalidClient, "Unknown client."))
	}
	return noStore(endpoint.Data(http.StatusOK, map[string]any{
		"user_code": device.UserCode, "client": c.publicView(), "scopes": p.scopes.described(device.Scopes),
		"expires_at": atom(device.ExpiresAt),
	}))
}

// serveDeviceApprove is POST /oauth2/device/approve: the signed-in user decides on a device.
func (p *Plugin) serveDeviceApprove(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	approve := in.Value("approve") == true
	device, err := p.devices.byUserCode(ctx, text(in, "user_code"))
	if err == nil {
		err = p.devices.decide(ctx, device, approve, tok.Subject(), actorOrg(tok), authTimeOf(tok))
	}
	if err != nil {
		return p.fail(ctx, err)
	}
	p.emit(ctx, EventDeviceDecided, tok.Subject(), device.ClientID, actorOrg(tok),
		map[string]any{"approved": approve, "scopes": list(device.Scopes)})
	status := statusDenied
	if approve {
		status = statusApproved
	}
	return noStore(endpoint.Data(http.StatusOK, map[string]any{"status": status}))
}

// serveCIBA is POST /oauth2/ciba: a client asks a user, named by email, to approve a sign-in.
func (p *Plugin) serveCIBA(ctx context.Context, in *endpoint.Input) endpoint.Result {
	var c *Client
	resp, req, err := func() (BackchannelAuthorization, pollable, error) {
		var err error
		if c, err = p.authenticated(ctx, in, "/oauth2/ciba"); err != nil {
			return BackchannelAuthorization{}, pollable{}, err
		}
		resource := text(in, "resource")
		if err := checkResource(resource, "resource must be an absolute URI."); err != nil {
			return BackchannelAuthorization{}, pollable{}, err
		}
		scopes, err := p.scopes.parse(text(in, "scope"), c)
		if err != nil {
			return BackchannelAuthorization{}, pollable{}, err
		}
		return p.ciba.request(ctx, *c, scopes, text(in, "login_hint"), text(in, "binding_message"), resource)
	}()
	if err != nil {
		return p.fail(ctx, err)
	}
	p.emit(ctx, EventCIBARequested, req.UserID, c.ClientID, "",
		map[string]any{"auth_req_id": req.ID, "binding_message": null(req.BindingMessage), "scopes": req.Scopes})
	return noStore(endpoint.JSON(http.StatusOK, resp))
}

// serveCIBAPending is GET /oauth2/ciba/pending: the caller's requests to decide, newest first.
func (p *Plugin) serveCIBAPending(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	pending, err := p.ciba.pending(ctx, tok.Subject())
	if err != nil {
		return p.fail(ctx, err)
	}
	data := []map[string]any{}
	for _, req := range pending {
		v := p.ciba.view(req)
		if v["client"], err = p.publicClient(ctx, req.ClientID); err != nil {
			return p.fail(ctx, err)
		}
		data = append(data, v)
	}
	return noStore(endpoint.Data(http.StatusOK, data))
}

// serveCIBADecide is POST /oauth2/ciba/{id}/decide.
func (p *Plugin) serveCIBADecide(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	approve := in.Value("approve") == true
	req, err := p.ciba.decide(ctx, in.String("id"), tok.Subject(), approve, actorOrg(tok), authTimeOf(tok))
	if err != nil {
		return p.fail(ctx, err)
	}
	p.emit(ctx, EventCIBADecided, tok.Subject(), req.ClientID, actorOrg(tok), map[string]any{"approved": approve, "auth_req_id": req.ID})
	return noStore(endpoint.Data(http.StatusOK, map[string]any{"status": req.Status}))
}
