package agents

import (
	"context"
	"time"

	"github.com/univeros/polaris.go/plugins/oauth"
)

var _ oauth.ClientGrantWindows = (*Plugin)(nil)

// ClientPermissionsUntil implements oauth.ClientGrantWindows: the permissions the agent's live
// grants require, each with the time its last grant expires (the zero time when one has no
// expires_at). The provider puts a permission scope in an agent's token only while a grant covers
// it, and ends the token with the grant: a service that checks the token without the database
// (package verify, mcp.Protect) reads the scope until the token expires. An inactive agent holds
// none; owned is false when clientID is not an agent.
func (p *Plugin) ClientPermissionsUntil(ctx context.Context, clientID string) (map[string]time.Time, bool, error) {
	a, found, err := p.s.agent(ctx, clientID)
	if err != nil || !found {
		return nil, false, err
	}
	until := map[string]time.Time{}
	if !a.Active() {
		return until, true, nil
	}
	live, err := p.s.liveGrants(ctx, a)
	if err != nil {
		return nil, true, err
	}
	for _, g := range live {
		c := p.s.caps.find(g.Capability)
		if c == nil {
			continue
		}
		end, seen := until[c.Permission]
		switch {
		case g.ExpiresAt == nil:
			until[c.Permission] = time.Time{}
		case !seen || (!end.IsZero() && g.ExpiresAt.After(end)):
			until[c.Permission] = *g.ExpiresAt
		}
	}
	return until, true, nil
}
