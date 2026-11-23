package oauth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/univeros/polaris.go/store"
)

// This file is the Go API other plugins (plugins/agents) and hosts use; reach the plugin with
// g.Plugin(oauth.ID).(*oauth.Plugin) after Init.

// Client returns the client clientID names: a registered one, or (an https client id) the one
// its metadata document describes. ErrClientNotFound when nobody registered it; an *Error when its
// metadata document is refused.
func (p *Plugin) Client(ctx context.Context, clientID string) (Client, error) {
	c, err := p.clients.find(ctx, clientID)
	if err != nil {
		return Client{}, err
	}
	if c == nil {
		return Client{}, ErrClientNotFound
	}
	return *c, nil
}

// CreateClient registers a client for organizationID ("" for an instance-wide one), created by
// createdBy (a user id, or ""). mayTrust honours fields["trusted"] and allows the CIBA grant (an
// operator's privileges); without it both are refused or ignored as for an organization. The
// secret, for a client_secret_* client, is in the result only. Validation failures are *Error with
// CodeInvalidClientMetadata.
func (p *Plugin) CreateClient(ctx context.Context, fields ClientFields, organizationID, createdBy string, mayTrust bool) (IssuedClient, error) {
	return p.clients.create(ctx, fields, organizationID, createdBy, mayTrust)
}

// UpdateClient changes a registered client (a field left out keeps its value; disabled true stops
// it at the token endpoint) and returns it with the names of what changed. Without mayTrust (an
// organization), a client an operator trusted keeps its type, redirect URIs, grants, scopes,
// authentication method, keys, client_uri and DPoP binding: changing one is an *Error with
// CodeInvalidClientMetadata.
func (p *Plugin) UpdateClient(ctx context.Context, c Client, fields ClientFields, mayTrust bool) (Client, []string, error) {
	return p.clients.update(ctx, c, fields, mayTrust)
}

// DeleteClient removes a registered client and every token it holds.
func (p *Plugin) DeleteClient(ctx context.Context, c Client) error {
	if c.IsMetadataClient() {
		return errors.New("oauth: a metadata-document client is not stored")
	}
	return p.graph.DB().Tx(ctx, func(ctx context.Context) error {
		if err := p.tokens.deleteWhere(ctx, store.Criteria{"client_id": c.ClientID}); err != nil {
			return err
		}
		return p.clients.delete(ctx, c)
	})
}

// RevokeClientTokens revokes every live token of a client (an agent's kill switch) and returns
// how many.
func (p *Plugin) RevokeClientTokens(ctx context.Context, clientID string) (int64, error) {
	return p.tokens.revokeWhere(ctx, store.Criteria{"client_id": clientID})
}

// IssueTokens mints the token response for a grant to c, as the token endpoint does: an at+jwt
// access token signed with core's key (aud the resource or the issuer, scope, client_id, org,
// cnf.jkt when DPoP-bound, act), a rotating refresh token when a user is behind the grant and c
// may refresh, an ID token when openid was granted to a user.
func (p *Plugin) IssueTokens(ctx context.Context, c Client, g Grant) (TokenResponse, error) {
	return p.tokens.issueWhile(ctx, c, g, nil)
}

// Exchange performs a token exchange (RFC 8693) for c, as the token endpoint does: the subject's
// scopes narrowed, its audience kept, act naming c (or the actor token's subject) and chained.
// The subject is a live session of the user (not an impersonation token nor a session an identity
// provider opened) or an access token issued to c (any client's when an operator trusted c), else
// CodeInvalidGrant; a resource other than the subject's audience is CodeInvalidTarget unless the
// subject was for this server or c is trusted.
func (p *Plugin) Exchange(ctx context.Context, c Client, req ExchangeRequest) (TokenResponse, error) {
	return p.exchange(ctx, c, req)
}

// VerifyDPoP verifies the DPoP proof of r (bound to accessToken when not "") and returns the
// thumbprint of its key, "" when r carries no proof. The proof must name the URL of r on this
// server: the origin of Config.BaseURL and the path requested, never the Host header. A proof is
// accepted once.
func (p *Plugin) VerifyDPoP(r *http.Request, accessToken string) (string, error) {
	return p.dpop.verify(r.Context(), r.Header.Get(DPoPHeader), r.Method, ownURL(p.settings.baseURL, r), accessToken)
}

// Permissions are the permission names among scopes: what a token with them may do on Polaris
// routes.
func (p *Plugin) Permissions(scopes []string) []string { return p.scopes.permissions(scopes) }

// Issuer is the iss of the provider's tokens.
func (p *Plugin) Issuer() string { return p.issuer }

// BaseURL is where the provider's endpoints are mounted.
func (p *Plugin) BaseURL() string { return p.settings.baseURL }

// Prune deletes the rows that can no longer be used: expired authorization codes, device codes
// and backchannel requests, and tokens that expired more than a refresh lifetime ago. It returns
// the rows deleted per table; a host schedules it beside maintenance.PruneExpired.
func (p *Plugin) Prune(ctx context.Context) (map[string]int64, error) {
	now := p.graph.Clock().Now()
	cutoffs := map[string]any{
		TableCodes:        now,
		TableDeviceCodes:  now,
		TableCIBARequests: now,
		TableTokens:       now.Add(-time.Duration(p.settings.refreshTTL) * time.Second),
	}
	out := map[string]int64{}
	for _, table := range sortedKeys(cutoffs) {
		n, err := p.graph.DB().Delete(ctx, table, store.Criteria{"expires_at": store.Lt(cutoffs[table])})
		if err != nil {
			return out, err
		}
		out[table] = n
	}
	return out, nil
}
