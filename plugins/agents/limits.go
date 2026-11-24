package agents

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/internal/netguard"
	"github.com/univeros/polaris.go/ratelimit"
)

// RateLimits bound what the Agent Auth Protocol's routes take (§8.13), and agents of hosts with a key at a
// capability's Location. A zero RateLimit is its default; KeyPrefix is not read. What a capability may do
// is bounded by its grants' budgets.
type RateLimits struct {
	// Agent is per agent, for requests it signed: 60 a minute by default.
	Agent config.RateLimit
	// Host is per host, for requests it or one of its agents signed: 300 a minute by default.
	Host config.RateLimit
	// Address is per client address, before anything is verified: 600 a minute by default, as many agents
	// may share an address. Behind a proxy, set RemoteAddr to the client's before Polaris.
	Address config.RateLimit
}

// resolve fills in the defaults, each limit under its own key.
func (r RateLimits) resolve(s *settings, bad func(format string, args ...any)) {
	for _, l := range []struct {
		name   string
		set    config.RateLimit
		limit  int
		to     *config.RateLimit
		prefix string
	}{
		{"Agent", r.Agent, 60, &s.agentLimit, "agents.agent"},
		{"Host", r.Host, 300, &s.hostLimit, "agents.host"},
		{"Address", r.Address, 600, &s.addressLimit, "agents.address"},
	} {
		if l.set.Limit == 0 && l.set.Window == 0 {
			l.set = config.RateLimit{Limit: l.limit, Window: time.Minute}
		}
		if err := l.set.Validate(); err != nil {
			bad("Config.RateLimits.%s: %s", l.name, err)
		}
		l.set.KeyPrefix = l.prefix
		*l.to = l.set
	}
}

// overLimit is a request refused for its rate: *Error, with the headers that say when to come back.
type overLimit struct {
	refusal *Error
	header  http.Header
}

func (e overLimit) Error() string { return e.refusal.Error() }
func (e overLimit) Unwrap() error { return e.refusal }

// withinRate spends one hit of the policy under key.
func (s *service) withinRate(ctx context.Context, policy config.RateLimit, whose, key string) error {
	res, err := ratelimit.Check(ctx, s.rates, policy, key)
	if err != nil || res.Allowed {
		return err
	}
	return overLimit{refuse(ErrRateLimited, fmt.Sprintf("The %s exceeded %d requests in %s.", whose, policy.Limit, policy.Window)), ratelimit.Headers(res, s.clock.Now())}
}

// spendAgent spends a request the agent signed, of its budget and its host's.
func (s *service) spendAgent(ctx context.Context, a Agent) error {
	if err := s.withinRate(ctx, s.settings.agentLimit, "agent", a.ID); err != nil || a.HostID == "" {
		return err
	}
	return s.withinRate(ctx, s.settings.hostLimit, "host", a.HostID)
}

// spendHost spends a request the host signed; one the server does not know is its key.
func (s *service) spendHost(ctx context.Context, h Host) error {
	key := h.ID
	if key == "" {
		key = h.KeyThumbprint
	}
	return s.withinRate(ctx, s.settings.hostLimit, "host", key)
}

// perAddress is next within the address's budget. It is not the route's rate_limit: those groups are shared
// with what people send from the same address.
func (p *Plugin) perAddress(next endpoint.Func) endpoint.Func {
	return func(ctx context.Context, in *endpoint.Input) endpoint.Result {
		if err := p.s.withinRate(ctx, p.s.settings.addressLimit, "address", netguard.RateKey(clientOf(ctx).ip)); err != nil {
			return p.protocolFail(ctx, err)
		}
		return next(ctx, in)
	}
}

// agentCalling is the agent a protocol route is called by, within its budgets.
func (p *Plugin) agentCalling(ctx context.Context, jwts *requestJWTs, in *endpoint.Input) (principal, error) {
	pr, err := p.s.authenticateWith(jwts, in.Request, rawBody(ctx), ownURL(p.s.settings.baseURL, in.Request))
	if err != nil {
		return pr, err
	}
	return pr, p.s.spendAgent(ctx, pr.agent)
}
