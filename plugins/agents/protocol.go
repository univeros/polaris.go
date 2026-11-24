package agents

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/endpoint"
)

// The Agent Auth Protocol's own routes (https://agent-auth-protocol.com/specification, v1.0-draft;
// § numbers below are its). What they share with the Polaris routes is the service behind them;
// what differs is here: the discovery document, the bodies, the error codes and whom a JWT names.

// DiscoveryMode is which document /.well-known/agent-configuration serves.
type DiscoveryMode string

// The discovery modes; the zero value is DiscoveryPolaris. The Polaris document is also at
// GET /agents/configuration in every mode, and the Agent Auth Protocol routes are served in both.
const (
	// DiscoveryPolaris is Polaris's document: what the Go agent SDK reads.
	DiscoveryPolaris DiscoveryMode = "polaris"
	// DiscoveryAgentAuth is the Agent Auth Protocol's document: what its clients (@auth/agent) read.
	// A Go agent SDK older than v1.1.0 does not find the server then.
	DiscoveryAgentAuth DiscoveryMode = "agent-auth"
)

const (
	// maxPage is the most capabilities GET /capability/list answers at once, and its default.
	maxPage = 100
	// protocolSkew is the most a JWT's iat may be ahead on the protocol routes, a MUST (§8.2).
	protocolSkew = 30 * time.Second
	// pathExecute is the protocol's execute endpoint, under the mount.
	pathExecute = "/capability/execute"
)

// protocolDiscovery is the protocol's discovery document (§5.1): the issuer is where Polaris is
// mounted, the base every path resolves against, and the endpoints are the ones served.
func (p *Plugin) protocolDiscovery() map[string]any {
	return map[string]any{
		"version": "1.0-draft", "provider_name": p.s.settings.providerName, "description": p.s.settings.description,
		"issuer": p.s.settings.baseURL, "algorithms": []string{"Ed25519"}, "modes": modes,
		"approval_methods": []string{MethodDevice, MethodCIBA},
		"default_location": p.s.settings.baseURL + pathExecute,
		"endpoints": map[string]string{"register": "/agent/register", "capabilities": "/capability/list", "describe_capability": "/capability/describe",
			"execute": pathExecute, "request_capability": "/agent/request-capability", "status": "/agent/status",
			"reactivate": "/agent/reactivate", "introspect": "/agent/introspect",
			"revoke": "/agent/revoke", "revoke_host": "/host/revoke", "rotate_key": "/agent/rotate-key", "rotate_host_key": "/host/rotate-key"},
		"jwks_uri": p.s.settings.baseURL + "/auth/.well-known/jwks.json",
	}
}

// protocolFail answers err as the protocol's routes do (§5.13): its codes and its statuses, in the
// problem document every Polaris refusal is.
func (p *Plugin) protocolFail(ctx context.Context, err error) endpoint.Result {
	e, ok := asError(err)
	if !ok {
		p.s.log.ErrorContext(ctx, "agents: request failed", "error", err)
		return endpoint.Error(http.StatusInternalServerError, "internal_error", "The server could not complete the request.")
	}
	as := func(typ string) *Error { return &Error{Type: typ, Detail: e.Detail, Extra: e.Extra} }
	switch e.Type {
	case ErrUnauthorized:
		e = as(ErrInvalidJWT)
	case ErrAudMismatch:
		e = refuse(ErrInvalidJWT, "aud must be exactly the server's issuer, or the location on an execution.")
	case ErrAgentInactive:
		e = as(e.Code)
	case ErrInvalidInput, ErrInvalidArguments:
		e = as(ErrInvalidRequest)
	case ErrBudgetExhausted:
		e = as(ErrLimitExceeded)
	}
	out := e.result()
	if over, ok := errors.AsType[overLimit](err); ok {
		out.Header = over.header
	}
	return out
}

// protocolGrants authenticates the caller of a capability route (§5.2) and answers the names its
// agent holds a live grant for; nil without a credential, or with a host's, which sees what everyone
// does. Any other credential is refused, never read as anonymous.
func (p *Plugin) protocolGrants(ctx context.Context, in *endpoint.Input) (map[string]bool, error) {
	authorization := in.Request.Header.Get("Authorization")
	if authorization == "" {
		return nil, nil
	}
	if m := bearerOnly.FindStringSubmatch(authorization); m != nil {
		if _, isHost := peekJWT(m[1], HostJWTType); isHost {
			h, _, err := p.s.hostOf(in.Request)
			if err == nil {
				err = p.s.spendHost(ctx, h)
			}
			return nil, err
		}
	}
	pr, err := p.agentCalling(ctx, p.s.issuerJWTs, in)
	if err != nil {
		return nil, err
	}
	live, err := p.s.liveGrants(ctx, pr.agent)
	if err != nil {
		return nil, err
	}
	granted := map[string]bool{}
	for _, g := range live {
		granted[g.Capability] = true
	}
	return granted, nil
}

// capabilityResult answers body: cached for five minutes (§10.6) when it is everyone's, not at all
// when it holds an agent's grants.
func capabilityResult(body map[string]any, granted map[string]bool) endpoint.Result {
	cacheControl := "public, max-age=300"
	if granted != nil {
		cacheControl = "no-store"
	}
	return endpoint.JSON(http.StatusOK, body).WithHeader("Cache-Control", cacheControl).WithHeader("Vary", "Authorization")
}

// summary is the capability as GET /capability/list shows it. §5.2 names name, description and
// grant_status; location (§2.12) is there because the reference client executes at the location the
// list gave it and at no other.
func (c *Capability) summary(granted map[string]bool) map[string]any {
	out := map[string]any{"name": c.Name, "description": c.Description}
	if c.Location != "" {
		out["location"] = c.Location
	}
	if granted != nil {
		out["grant_status"] = "not_granted"
		if granted[c.Name] {
			out["grant_status"] = "granted"
		}
	}
	return out
}

// listProtocolCapabilities is GET /capability/list (§5.2).
func (p *Plugin) listProtocolCapabilities(ctx context.Context, in *endpoint.Input) endpoint.Result {
	granted, err := p.protocolGrants(ctx, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	limit, ok := intField(in, "limit", maxPage)
	if !ok || limit < 1 {
		return p.protocolFail(ctx, refuse(ErrInvalidRequest, "limit is a positive integer."))
	}
	page, more, ok := p.caps.page(in.String("query"), in.String("cursor"), min(limit, maxPage))
	if !ok {
		return p.protocolFail(ctx, refuse(ErrInvalidRequest, "cursor is not one this server answered; list from the start."))
	}
	list := []any{}
	for _, c := range page {
		list = append(list, c.summary(granted))
	}
	var next any
	if more {
		next = base64.RawURLEncoding.EncodeToString([]byte(page[len(page)-1].Name))
	}
	return capabilityResult(map[string]any{"capabilities": list, "next_cursor": next, "has_more": more}, granted)
}

// describeProtocolCapability is GET /capability/describe (§5.2.1).
func (p *Plugin) describeProtocolCapability(ctx context.Context, in *endpoint.Input) endpoint.Result {
	granted, err := p.protocolGrants(ctx, in)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	name := in.String("name")
	if name == "" {
		return p.protocolFail(ctx, refuse(ErrInvalidRequest, "name is required: the capability to describe."))
	}
	c := p.caps.find(name)
	if c == nil {
		return p.protocolFail(ctx, refuse(ErrCapabilityNotFound, "The capability does not exist."))
	}
	out := c.summary(granted)
	out["input"] = c.Input
	return capabilityResult(out, granted)
}

// page is at most limit (positive) capabilities matching query, in the configured order, after the one cursor
// names; more is whether others follow. ok is false for a cursor that names no capability. query
// matches when each of its words is in the name or the description, whatever the case.
func (c *capabilities) page(query, cursor string, limit int) (page []*Capability, more, ok bool) {
	rest := c.list
	if cursor != "" {
		name, err := base64.RawURLEncoding.DecodeString(cursor)
		at := slices.IndexFunc(rest, func(x *Capability) bool { return x.Name == string(name) })
		if err != nil || at < 0 {
			return nil, false, false
		}
		rest = rest[at+1:]
	}
	words := strings.Fields(strings.ToLower(query))
	for _, x := range rest {
		text := strings.ToLower(x.Name + " " + x.Description)
		if slices.ContainsFunc(words, func(w string) bool { return !strings.Contains(text, w) }) {
			continue
		}
		if len(page) == limit {
			return page, true, true
		}
		page = append(page, x)
	}
	return page, false, true
}
