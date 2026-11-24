package agents

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/netguard"
	"github.com/univeros/polaris.go/plugins/oauth"
)

// protocolIntrospect is POST /agent/introspect (§5.12), for a resource server: an OAuth client an operator
// trusted, as POST /oauth2/introspect asks of who reads other clients' tokens. The JWT is not spent: the
// resource server holds its jti to one use itself. Who is refused spends their address's budget.
func (p *Plugin) protocolIntrospect(ctx context.Context, in *endpoint.Input) endpoint.Result {
	_, err := p.s.oauth.AuthenticateTrusted(ctx, in, "/agent/introspect")
	var refused *oauth.Error
	if err != nil && !errors.As(err, &refused) {
		return p.protocolFail(ctx, err)
	}
	if err != nil {
		if err := p.s.withinRate(ctx, p.s.settings.addressLimit, "address", netguard.RateKey(clientOf(ctx).ip)); err != nil {
			return p.protocolFail(ctx, err)
		}
		return (&Error{Type: ErrUnauthorized, Code: "unauthorized", Detail: "Introspection is for an OAuth client that authenticates and that an operator trusted."}).result().
			WithHeader("WWW-Authenticate", `Basic realm="agents"`)
	}
	raw, _ := in.Value("token").(string)
	pr, aud, err := p.s.introspected(ctx, raw)
	if _, inactive := asError(err); inactive {
		return noStore(http.StatusOK, map[string]any{"active": false})
	}
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	live, err := p.s.liveGrants(ctx, pr.agent)
	if err != nil {
		return p.protocolFail(ctx, err)
	}
	grants := []any{}
	for _, g := range live {
		if pr.mayUse(g.Capability) && p.caps.find(g.Capability) != nil {
			grants = append(grants, map[string]any{"capability": g.Capability, "status": GrantActive})
		}
	}
	body := map[string]any{"active": true, "agent_id": pr.agent.ID, "host_id": null(pr.agent.HostID), "user_id": null(pr.agent.Subject()),
		"agent_capability_grants": grants, "mode": pr.agent.Mode, "aud": aud}
	if expiry := p.s.settings.lifetimes.expiry(pr.agent); expiry != nil {
		body["expires_at"] = timestamp(*expiry)
	}
	return noStore(http.StatusOK, body)
}

// introspected is the agent a JWT authenticates (§4.5) and the aud it is for: this server, its execute route
// or a capability's location. One made for another resource server is not told to this one's caller.
func (s *service) introspected(ctx context.Context, raw string) (principal, string, error) {
	peeked, ok := peekRequestJWT(raw)
	if !ok {
		return principal{}, "", invalidJWT("The token is not an agent JWT (typ agent+jwt).")
	}
	a, err := s.named(ctx, peeked.sub)
	if err == nil {
		err = assertActive(a)
	}
	if err != nil {
		return principal{}, "", err
	}
	claims, err := s.issuerJWTs.signed(raw, a)
	if err != nil {
		return principal{}, "", err
	}
	aud, _ := claims["aud"].(string)
	ours := aud == s.issuerJWTs.audience || aud == s.executeJWTs.audience || slices.ContainsFunc(s.caps.list, func(c *Capability) bool { return c.Location != "" && c.Location == aud })
	jti, _ := claims["jti"].(string)
	caps, listed, err := jwtCapabilities(claims)
	if err = errors.Join(err, s.issuerJWTs.lifetime(claims)); err != nil || !ours || jti == "" || len(jti) > maxJTI {
		return principal{}, "", invalidJWT("The JWT is not for this server.")
	}
	if err := s.checkHost(ctx, a, peeked.iss, peeked.hasISS); err != nil {
		return principal{}, "", err
	}
	if err := s.used(ctx, a); err != nil {
		return principal{}, "", err
	}
	pr := principal{agent: a, via: ViaJWT}
	if listed {
		pr.capabilities = caps
	}
	return pr, aud, nil
}
