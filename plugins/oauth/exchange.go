package oauth

import (
	"context"
	"slices"
	"strings"

	"github.com/univeros/polaris-go/token"
)

// Token types of the token exchange (RFC 8693 §3).
const (
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)

// ExchangeRequest is a token exchange (RFC 8693): the subject token (a Polaris session's access
// token or one of the provider's), an optional actor token, the resource the new token is for, the
// scopes asked (nil: the subject's) and the DPoP key the request proved.
type ExchangeRequest struct {
	SubjectToken, SubjectTokenType string
	ActorToken, ActorTokenType     string
	Resource                       string
	Scopes                         []string
	DPoPJKT                        string
}

// subject is what a subject or actor token says.
type subject struct {
	sub, user, org, clientID string
	scopes                   []string // nil for a session: anything the client may ask
	act                      *Actor
	authTime                 *int64
	jkt                      string
}

// exchange issues an access token for a subject, within its scopes, carrying act: the requesting
// client (or the actor token's subject), chained to the subject's own act.
func (p *Plugin) exchange(ctx context.Context, c Client, req ExchangeRequest) (TokenResponse, error) {
	if !c.AllowsGrant(GrantTokenExchange) {
		return TokenResponse{}, refusal(CodeUnauthorizedClient, "The client may not exchange tokens.")
	}
	tokenTypes := []string{TokenTypeAccessToken, TokenTypeJWT}
	if req.SubjectToken == "" || !slices.Contains(tokenTypes, req.SubjectTokenType) {
		return TokenResponse{}, refusal(CodeInvalidRequest, "subject_token and subject_token_type (access_token or jwt) are required.")
	}
	if req.Resource != "" && !resourceFormat.MatchString(req.Resource) {
		return TokenResponse{}, refusal(CodeInvalidTarget, "resource must be an absolute URI.")
	}
	subj, err := p.subject(ctx, req.SubjectToken)
	if err != nil {
		return TokenResponse{}, err
	}
	if subj.jkt != "" && subj.jkt != req.DPoPJKT {
		return TokenResponse{}, refusal(CodeInvalidDPoPProof, "The subject token is bound to a DPoP key; prove it, and the exchanged token stays bound to it.")
	}
	scopes := subj.scopes
	switch {
	case req.Scopes != nil && subj.scopes == nil:
		scopes, err = p.scopes.parse(strings.Join(req.Scopes, " "), &c)
	case req.Scopes != nil:
		scopes, err = within(req.Scopes, subj.scopes)
	}
	if err != nil {
		return TokenResponse{}, err
	}
	actor := &Actor{Sub: c.ClientID, ClientID: c.ClientID}
	if req.ActorToken != "" {
		if !slices.Contains(tokenTypes, req.ActorTokenType) {
			return TokenResponse{}, refusal(CodeInvalidRequest, "actor_token_type must be access_token or jwt.")
		}
		presented, err := p.subject(ctx, req.ActorToken)
		if err != nil {
			return TokenResponse{}, err
		}
		actor = &Actor{Sub: presented.sub, ClientID: c.ClientID}
		if presented.clientID != "" {
			actor.ClientID = presented.clientID
		}
	}
	actor.Act = subj.act
	resp, err := p.tokens.issue(ctx, c, Grant{
		UserID: subj.user, OrganizationID: subj.org, Scopes: scopes, Resource: req.Resource,
		DPoPJKT: req.DPoPJKT, Actor: actor, AuthTime: subj.authTime,
	})
	if err != nil {
		return TokenResponse{}, err
	}
	resp.RefreshToken, resp.IDToken, resp.IssuedTokenType = "", "", TokenTypeAccessToken
	return resp, nil
}

// subject reads a session's access token (core's parser) or one of the provider's (live in the
// token table).
func (p *Plugin) subject(ctx context.Context, raw string) (subject, error) {
	if header := JWTHeader(raw); header != nil && header["typ"] == AccessTokenType {
		claims, err := p.tokens.verifyAccess(raw)
		if err != nil {
			return subject{}, err
		}
		jti, _ := claims["jti"].(string)
		var rec *record
		if jti != "" {
			if rec, err = p.tokens.find(ctx, jti); err != nil {
				return subject{}, err
			}
		}
		if rec == nil || !rec.live(p.graph.Clock.Now()) {
			return subject{}, refusal(CodeInvalidGrant, "The subject token is revoked or unknown.")
		}
		sub, _ := claims["sub"].(string)
		return subject{sub: sub, user: rec.UserID, org: rec.OrganizationID, clientID: rec.ClientID,
			scopes: rec.Scopes, act: rec.Actor, authTime: rec.AuthTime, jkt: rec.DPoPJKT}, nil
	}
	session, err := p.graph.Tokens.Parse(raw)
	if err != nil {
		return subject{}, refusal(CodeInvalidGrant, "The subject token is not a token this server knows.")
	}
	sub := session.Subject()
	if sub == "" {
		return subject{}, refusal(CodeInvalidGrant, "The subject token has no subject.")
	}
	return subject{sub: sub, user: sub, org: session.Organization(), authTime: authTimeOf(session)}, nil
}

// authTimeOf is a token's auth_time claim, nil when absent.
func authTimeOf(t *token.Token) *int64 {
	if v, ok := t.Claim("auth_time").(int64); ok {
		return &v
	}
	return nil
}
