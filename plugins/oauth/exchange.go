package oauth

import (
	"context"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/session"
	"github.com/univeros/polaris.go/token"
)

// Token types of the token exchange (RFC 8693 §3).
const (
	TokenTypeAccessToken = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeJWT         = "urn:ietf:params:oauth:token-type:jwt"
)

// ExchangeRequest is a token exchange (RFC 8693): the subject token (a Polaris session's access
// token or one of the provider's), an optional actor token, the resource the new token is for
// ("": the subject token's own audience), the scopes asked (nil: the subject's) and the DPoP key
// the request proved.
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
	resource                 string // the token's audience; "" for this server (a session, aud the issuer)
}

// thisServer reports whether resource, a token's audience, names this server: "" (the issuer),
// the issuer by name, or one of Config.Audiences.
func (p *Plugin) thisServer(resource string) bool {
	return resource == "" || resource == p.issuer || slices.Contains(p.settings.audiences, resource)
}

// target is the audience of the token exchanged from subj (RFC 8707: a token restricted to an
// audience does not become one for another). Without a resource asked it is the subject's own. A
// subject for this server narrows to any resource. A subject for another resource is moved only
// by a client an operator trusted, or, away from this server, by the authenticated client its
// audience names.
func (p *Plugin) target(c Client, subj subject, asked string) (string, error) {
	switch {
	case asked == "" || asked == subj.resource:
		return subj.resource, nil
	case p.thisServer(subj.resource), p.settings.trusts(c):
		return asked, nil
	case subj.resource == c.ClientID && c.TokenEndpointAuthMethod != AuthNone && !p.thisServer(asked):
		return asked, nil
	}
	return "", refusal(CodeInvalidTarget, "The subject token is for "+subj.resource+"; the exchanged token keeps that audience.")
}

// exchange issues an access token for a subject, within its scopes and its audience, carrying
// act: the requesting client (or the actor token's subject), chained to the subject's own act.
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
	subj, err := p.subject(ctx, c, req.SubjectToken)
	if err != nil {
		return TokenResponse{}, err
	}
	resource, err := p.target(c, subj, req.Resource)
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
		presented, err := p.subject(ctx, c, req.ActorToken)
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
		UserID: subj.user, OrganizationID: subj.org, Scopes: scopes, Resource: resource,
		DPoPJKT: req.DPoPJKT, Actor: actor, AuthTime: subj.authTime,
	})
	if err != nil {
		return TokenResponse{}, err
	}
	resp.RefreshToken, resp.IDToken, resp.IssuedTokenType = "", "", TokenTypeAccessToken
	return resp, nil
}

// subject reads a token c presents as the subject or the actor: one of the provider's (live in
// the token table, and c's to present: issued to c, or for c as its audience, or c is a client an
// operator trusted), or a session's access token (core's parser) that is still the user's own
// session (sessionSubject).
func (p *Plugin) subject(ctx context.Context, c Client, raw string) (subject, error) {
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
		if rec == nil || !rec.live(p.graph.Clock().Now()) {
			return subject{}, refusal(CodeInvalidGrant, "The subject token is revoked or unknown.")
		}
		if rec.ClientID != c.ClientID && rec.Resource != c.ClientID && !p.settings.trusts(c) {
			return subject{}, refusal(CodeInvalidGrant, "The token was issued to another client; a client exchanges the tokens issued to it.")
		}
		sub, _ := claims["sub"].(string)
		return subject{sub: sub, user: rec.UserID, org: rec.OrganizationID, clientID: rec.ClientID,
			scopes: rec.Scopes, act: rec.Actor, authTime: rec.AuthTime, jkt: rec.DPoPJKT, resource: rec.Resource}, nil
	}
	session, err := p.graph.Tokens().Parse(raw)
	if err != nil {
		return subject{}, refusal(CodeInvalidGrant, "The subject token is not a token this server knows.")
	}
	sub := session.Subject()
	if sub == "" {
		return subject{}, refusal(CodeInvalidGrant, "The subject token has no subject.")
	}
	if err := p.sessionSubject(ctx, session); err != nil {
		return subject{}, err
	}
	return subject{sub: sub, user: sub, org: session.Organization(), authTime: authTimeOf(session)}, nil
}

// sessionSubject refuses a session token that is not the user's own live session. An exchanged
// token is an hour of the user's authority with none of the session's marks, so a session that
// speaks for the user on someone else's word (an operator's impersonation, an organization's
// identity provider: token.Token.OrganizationBound) is not exchanged, nor one that ended: its
// user logged out everywhere (the denylist's watermark, read whether or not the pipeline enforces
// it) or its own session (sid) was revoked.
func (p *Plugin) sessionSubject(ctx context.Context, tok *token.Token) error {
	if tok.Claim(impersonationClaim) != nil || tok.OrganizationBound() {
		return refusal(CodeInvalidGrant, "An impersonation token or a session an identity provider opened is not exchanged.")
	}
	ended, err := p.graph.Denylist().IsRevoked(ctx, tok.Subject(), tok.IssuedAt())
	if err != nil {
		return err
	}
	if sid, _ := tok.Claim("sid").(string); sid != "" && !ended {
		live, err := p.graph.Sessions().List(ctx, tok.Subject(), sid)
		if err != nil {
			return err
		}
		ended = !slices.ContainsFunc(live, func(s session.Info) bool { return s.Current })
	}
	if ended {
		return refusal(CodeInvalidGrant, "The subject token's session has ended.")
	}
	return nil
}

// authTimeOf is a token's auth_time claim, nil when absent.
func authTimeOf(t *token.Token) *int64 {
	if v, ok := t.Claim("auth_time").(int64); ok {
		return &v
	}
	return nil
}
