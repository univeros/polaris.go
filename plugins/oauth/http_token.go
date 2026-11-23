package oauth

import (
	"context"
	"errors"
	"slices"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/store"
)

// issued is a grant's token response and who it was for (the oauth.token_issued event).
type issued struct {
	resp      TokenResponse
	userID    string
	orgID     string
	exchanged bool
}

// serveToken is POST /oauth2/token: every grant. The client authenticates as it registered; a DPoP
// proof binds the tokens to its key; the response is never cached.
func (p *Plugin) serveToken(ctx context.Context, in *endpoint.Input) endpoint.Result {
	grant := text(in, "grant_type")
	var c *Client
	out, err := func() (issued, error) {
		var err error
		if c, err = p.authenticated(ctx, in, "/oauth2/token"); err != nil {
			return issued{}, err
		}
		jkt, err := p.proof(ctx, in.Request, c)
		if err != nil {
			return issued{}, err
		}
		switch grant {
		case GrantAuthorizationCode:
			return p.grantCode(ctx, in, *c, jkt)
		case GrantRefreshToken:
			return p.grantRefresh(ctx, in, *c, jkt)
		case GrantClientCredentials:
			return p.grantClientCredentials(ctx, in, *c, jkt)
		case GrantDeviceCode:
			return p.grantPolled(ctx, *c, jkt, text(in, "device_code"), "device_code is required.", TableDeviceCodes, p.devices.pollCode)
		case GrantCIBA:
			return p.grantPolled(ctx, *c, jkt, text(in, "auth_req_id"), "auth_req_id is required.", TableCIBARequests, p.ciba.pollRequest)
		case GrantTokenExchange:
			return p.grantExchange(ctx, in, *c, jkt)
		case "":
			return issued{}, refusal(CodeInvalidRequest, "grant_type is required.")
		default:
			return issued{}, refusal(CodeUnsupportedGrantType, "Unsupported grant_type.")
		}
	}()
	if err != nil {
		var oe *Error
		if c != nil && errors.As(err, &oe) && oe.Code != CodeAuthorizationPending && oe.Code != CodeSlowDown {
			p.emit(ctx, EventTokenRefused, "", c.ClientID, "", map[string]any{"grant": null(grant), "error": oe.Code})
		}
		return p.fail(ctx, err)
	}
	var act any
	if out.exchanged {
		act = true
	}
	p.emit(ctx, EventTokenIssued, out.userID, c.ClientID, out.orgID,
		map[string]any{"grant": grant, "scope": out.resp.Scope, "dpop": out.resp.TokenType == "DPoP", "act": act})
	return noStore(endpoint.JSON(200, out.resp))
}

func (p *Plugin) grantCode(ctx context.Context, in *endpoint.Input, c Client, jkt string) (issued, error) {
	value := text(in, "code")
	if value == "" {
		return issued{}, refusal(CodeInvalidRequest, "code is required.")
	}
	stored, err := p.codes.consume(ctx, value, c, text(in, "redirect_uri"), text(in, "code_verifier"))
	var reused codeReused
	if errors.As(err, &reused) {
		// The code goes too, so a redemption still in flight issues nothing.
		err := p.tokens.hold(ctx, reused.userID, func(ctx context.Context) error {
			if _, err := p.tokens.revokeWhere(ctx, store.Criteria{"family_id": reused.codeID}); err != nil {
				return err
			}
			return deleteWhere(ctx, p.graph.DB(), TableCodes, store.Criteria{"id": reused.codeID})
		})
		if err != nil {
			return issued{}, err
		}
		return issued{}, refusal(CodeInvalidGrant, "The authorization code was already used; the tokens it issued are revoked.")
	}
	if err != nil {
		return issued{}, err
	}
	if stored.DPoPJKT != "" && stored.DPoPJKT != jkt {
		return issued{}, refusal(CodeInvalidDPoPProof, "The code was bound to another DPoP key (dpop_jkt).")
	}
	// The tokens' family is the code, so a replay of the code can end them.
	resp, err := p.tokens.issueWhile(ctx, c, Grant{
		UserID: stored.UserID, OrganizationID: stored.OrganizationID, Scopes: stored.Scopes, Resource: stored.Resource,
		DPoPJKT: jkt, AuthTime: stored.AuthTime, Nonce: stored.Nonce, FamilyID: stored.ID,
	}, p.tokens.stands(TableCodes, stored.ID))
	return issued{resp: resp, userID: stored.UserID, orgID: stored.OrganizationID}, err
}

func (p *Plugin) grantRefresh(ctx context.Context, in *endpoint.Input, c Client, jkt string) (issued, error) {
	secret := text(in, "refresh_token")
	if secret == "" {
		return issued{}, refusal(CodeInvalidRequest, "refresh_token is required.")
	}
	resp, err := p.tokens.refresh(ctx, secret, c, jkt, words(text(in, "scope")))
	var oe *Error
	if errors.As(err, &oe) && oe.reused {
		p.emit(ctx, EventRefreshReused, "", c.ClientID, "", nil)
	}
	return issued{resp: resp}, err
}

func (p *Plugin) grantClientCredentials(ctx context.Context, in *endpoint.Input, c Client, jkt string) (issued, error) {
	if c.Type == TypePublic || !c.AllowsGrant(GrantClientCredentials) {
		return issued{}, refusal(CodeUnauthorizedClient, "The client may not use client_credentials.")
	}
	scopes, err := p.scopes.parse(text(in, "scope"), &c)
	if err != nil {
		return issued{}, err
	}
	if slices.Contains(scopes, ScopeOpenID) || slices.Contains(scopes, ScopeOfflineAccess) {
		return issued{}, refusal(CodeInvalidScope, "openid and offline_access need a user.")
	}
	resource := text(in, "resource")
	if err := checkResource(resource, "resource must be an absolute URI without a fragment."); err != nil {
		return issued{}, err
	}
	resp, err := p.tokens.issue(ctx, c, Grant{OrganizationID: c.OrganizationID, Scopes: scopes, Resource: resource, DPoPJKT: jkt})
	return issued{resp: resp}, err
}

// grantPolled is the device and backchannel grants: the approved request, spent, issues tokens.
func (p *Plugin) grantPolled(ctx context.Context, c Client, jkt, id, missing, table string, poll func(context.Context, string, Client) (pollable, error)) (issued, error) {
	if id == "" {
		return issued{}, refusal(CodeInvalidRequest, missing)
	}
	approved, err := poll(ctx, id, c)
	if err != nil {
		return issued{}, err
	}
	g := approved.grant()
	g.DPoPJKT = jkt
	resp, err := p.tokens.issueWhile(ctx, c, g, p.tokens.stands(table, approved.ID))
	return issued{resp: resp, userID: approved.UserID, orgID: approved.OrganizationID}, err
}

func (p *Plugin) grantExchange(ctx context.Context, in *endpoint.Input, c Client, jkt string) (issued, error) {
	resource := text(in, "resource")
	if err := checkResource(resource, "resource must be an absolute URI without a fragment."); err != nil {
		return issued{}, err
	}
	if resource == "" {
		resource = text(in, "audience")
	}
	resp, err := p.exchange(ctx, c, ExchangeRequest{
		SubjectToken: text(in, "subject_token"), SubjectTokenType: text(in, "subject_token_type"),
		ActorToken: text(in, "actor_token"), ActorTokenType: text(in, "actor_token_type"),
		Resource: resource, Scopes: words(text(in, "scope")), DPoPJKT: jkt,
	})
	return issued{resp: resp, exchanged: true}, err
}
