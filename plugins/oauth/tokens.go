package oauth

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

const (
	kindAccess    = "access"
	kindRefresh   = "refresh"
	refreshPepper = "oauth_refresh"
	refreshPrefix = "prt_"
	// verifyLeeway is the clock skew tolerated when verifying the provider's own JWTs.
	verifyLeeway = 60 * time.Second
)

// Actor is the act claim of an exchanged token (RFC 8693 §4.1): who acts, and for an exchanged
// token presented again, who acted before.
type Actor struct {
	Sub      string `json:"sub"`
	ClientID string `json:"client_id"`
	Act      *Actor `json:"act,omitempty"`
}

// claims renders a in upstream's member order.
func (a *Actor) claims() token.Claims {
	c := token.Claims{}.With("sub", a.Sub).With("client_id", a.ClientID)
	if a.Act != nil {
		c = c.With("act", a.Act.claims())
	}
	return c
}

func (a *Actor) view() map[string]any {
	m := map[string]any{"sub": a.Sub, "client_id": a.ClientID}
	if a.Act != nil {
		m["act"] = a.Act.view()
	}
	return m
}

// Grant is what a token is issued for: whose (UserID "" for the client itself), in which
// organization, which scopes, for which resource, bound to which DPoP key, by which actor.
type Grant struct {
	UserID         string
	OrganizationID string
	Scopes         []string
	Resource       string // the aud; "" is the issuer
	DPoPJKT        string // "" for a bearer token
	Actor          *Actor
	AuthTime       *int64
	Nonce          string // the ID token's nonce
	FamilyID       string // the rotation family; "" for a new one
}

// TokenResponse is an RFC 6749 token response.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
	RefreshToken    string `json:"refresh_token,omitempty"`
	IDToken         string `json:"id_token,omitempty"`
	IssuedTokenType string `json:"issued_token_type,omitempty"`
}

// LogValue keeps the bearer secrets out of logs.
func (t TokenResponse) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token_type", t.TokenType), slog.String("scope", t.Scope))
}

// record is a row of polaris_oauth_token: an access token by jti, or a refresh token by hash.
type record struct {
	ID, Kind, TokenHash, ClientID, UserID, OrganizationID string
	Scopes                                                []string
	FamilyID, Resource, DPoPJKT                           string
	Actor                                                 *Actor
	AuthTime                                              *int64
	ExpiresAt                                             time.Time
	RevokedAt                                             *time.Time
	CreatedAt                                             time.Time
}

func (r record) live(now time.Time) bool { return r.RevokedAt == nil && r.ExpiresAt.After(now) }

func (r record) row() (store.Row, error) {
	scopes, err := store.JSONValue(list(r.Scopes))
	if err != nil {
		return nil, err
	}
	var actor any
	if r.Actor != nil {
		if actor, err = store.JSONValue(r.Actor); err != nil {
			return nil, err
		}
	}
	return store.Row{
		"id": r.ID, "kind": r.Kind, "token_hash": null(r.TokenHash), "client_id": r.ClientID,
		"user_id": null(r.UserID), "organization_id": null(r.OrganizationID), "scopes": scopes,
		"family_id": null(r.FamilyID), "resource": null(r.Resource), "dpop_jkt": null(r.DPoPJKT),
		"actor": actor, "auth_time": store.Nullable(r.AuthTime), "expires_at": r.ExpiresAt,
		"revoked_at": store.Nullable(r.RevokedAt), "created_at": r.CreatedAt,
	}, nil
}

func recordFromRow(row store.Row) record {
	r := record{
		ID: row.String("id"), Kind: row.String("kind"), TokenHash: row.String("token_hash"),
		ClientID: row.String("client_id"), UserID: row.String("user_id"), OrganizationID: row.String("organization_id"),
		Scopes: stringList(row, "scopes"), FamilyID: row.String("family_id"), Resource: row.String("resource"),
		DPoPJKT: row.String("dpop_jkt"), AuthTime: intPtr(row, "auth_time"), RevokedAt: row.TimePtr("revoked_at"),
	}
	var actor Actor
	if row.JSON("actor", &actor) == nil && actor.Sub != "" {
		r.Actor = &actor
	}
	r.ExpiresAt, _ = row.Time("expires_at")
	r.CreatedAt, _ = row.Time("created_at")
	return r
}

func intPtr(row store.Row, col string) *int64 {
	if row[col] == nil {
		return nil
	}
	v := row.Int(col)
	return &v
}

// tokens issues, rotates, revokes and introspects the provider's tokens.
type tokens struct {
	db       store.Adapter
	pepper   *security.Pepper
	codec    *token.Codec
	repos    *repository.Repos
	issuer   string
	settings settings
	clock    clock.Clock
}

// issue mints the token response for a grant: the access token, a refresh token when a user is
// behind the grant and the client may refresh, an ID token when openid was granted to a user.
func (t *tokens) issue(ctx context.Context, c Client, g Grant) (TokenResponse, error) {
	now := t.clock.Now()
	expiresAt := now.Add(time.Duration(t.settings.accessTTL) * time.Second)
	refreshable := g.UserID != "" && c.AllowsGrant(GrantRefreshToken)
	if g.FamilyID == "" && refreshable {
		g.FamilyID = repository.NewID()
	}
	access := record{
		ID: repository.NewID(), Kind: kindAccess, ClientID: c.ClientID, UserID: g.UserID,
		OrganizationID: g.OrganizationID, Scopes: list(g.Scopes), FamilyID: g.FamilyID, Resource: g.Resource,
		DPoPJKT: g.DPoPJKT, Actor: g.Actor, AuthTime: g.AuthTime, ExpiresAt: expiresAt, CreatedAt: now,
	}
	if err := t.insert(ctx, access); err != nil {
		return TokenResponse{}, err
	}
	scope := strings.Join(access.Scopes, " ")
	sub, aud := g.UserID, g.Resource
	if sub == "" {
		sub = c.ClientID
	}
	if aud == "" {
		aud = t.issuer
	}
	claims := token.Claims{}.With("sub", sub).With("jti", access.ID).With("aud", aud).
		With("client_id", c.ClientID).With("scope", scope)
	if g.OrganizationID != "" {
		claims = claims.With("org", g.OrganizationID)
	}
	if g.AuthTime != nil {
		claims = claims.With("auth_time", *g.AuthTime)
	}
	if g.DPoPJKT != "" {
		claims = claims.With("cnf", token.Claims{}.With("jkt", g.DPoPJKT))
	}
	if g.Actor != nil {
		claims = claims.With("act", g.Actor.claims())
	}
	jwt, err := t.codec.Mint(AccessTokenType, claims, expiresAt)
	if err != nil {
		return TokenResponse{}, err
	}
	resp := TokenResponse{AccessToken: jwt, TokenType: tokenType(g.DPoPJKT), ExpiresIn: t.settings.accessTTL, Scope: scope}
	if refreshable {
		if resp.RefreshToken, err = t.mintRefresh(ctx, c, g, now); err != nil {
			return TokenResponse{}, err
		}
	}
	if g.UserID != "" && slices.Contains(g.Scopes, ScopeOpenID) {
		user, err := t.repos.Users.Get(ctx, g.UserID)
		switch {
		case err == nil:
			if resp.IDToken, err = t.mintIDToken(c, user.ID, openIDClaims(user, g.Scopes), g, now); err != nil {
				return TokenResponse{}, err
			}
		case !errors.Is(err, repository.ErrNotFound):
			return TokenResponse{}, err
		}
	}
	return resp, nil
}

func tokenType(jkt string) string {
	if jkt == "" {
		return "Bearer"
	}
	return "DPoP"
}

func (t *tokens) insert(ctx context.Context, r record) error {
	row, err := r.row()
	if err != nil {
		return err
	}
	return t.db.Insert(ctx, TableTokens, row)
}

func (t *tokens) mintRefresh(ctx context.Context, c Client, g Grant, now time.Time) (string, error) {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	secret := refreshPrefix + b64(buf)
	r := record{
		ID: repository.NewID(), Kind: kindRefresh, TokenHash: t.pepper.Hash(refreshPepper, secret),
		ClientID: c.ClientID, UserID: g.UserID, OrganizationID: g.OrganizationID, Scopes: list(g.Scopes),
		FamilyID: g.FamilyID, Resource: g.Resource, DPoPJKT: g.DPoPJKT, Actor: g.Actor, AuthTime: g.AuthTime,
		ExpiresAt: now.Add(time.Duration(t.settings.refreshTTL) * time.Second), CreatedAt: now,
	}
	return secret, t.insert(ctx, r)
}

func (t *tokens) mintIDToken(c Client, userID string, openID token.Claims, g Grant, now time.Time) (string, error) {
	claims := token.Claims{}.With("sub", userID).With("aud", c.ClientID).With("jti", repository.NewID())
	for _, name := range openID.Names() {
		v, _ := openID.Get(name)
		claims = claims.With(name, v)
	}
	if g.AuthTime != nil {
		claims = claims.With("auth_time", *g.AuthTime)
	}
	if g.Nonce != "" {
		claims = claims.With("nonce", g.Nonce)
	}
	return t.codec.Mint("", claims, now.Add(time.Duration(t.settings.accessTTL)*time.Second))
}

// refresh spends a refresh token and issues its successor in the same family; a spent token
// presented again is a theft signal and ends the family. The claim and the new tokens are one
// transaction.
func (t *tokens) refresh(ctx context.Context, secret string, c Client, jkt string, requested []string) (TokenResponse, error) {
	stored, err := t.findRefresh(ctx, secret)
	if err != nil {
		return TokenResponse{}, err
	}
	if stored == nil || stored.ClientID != c.ClientID {
		return TokenResponse{}, refusal(CodeInvalidGrant, "The refresh token is unknown.")
	}
	now := t.clock.Now()
	if stored.RevokedAt != nil {
		if stored.FamilyID != "" {
			if _, err := t.revokeFamily(ctx, stored.FamilyID); err != nil {
				return TokenResponse{}, err
			}
		}
		e := refusal(CodeInvalidGrant, "The refresh token was already used; every token of its family is revoked.")
		e.reused = true
		return TokenResponse{}, e
	}
	if !stored.ExpiresAt.After(now) {
		return TokenResponse{}, refusal(CodeInvalidGrant, "The refresh token expired.")
	}
	if stored.DPoPJKT != "" && stored.DPoPJKT != jkt {
		return TokenResponse{}, refusal(CodeInvalidDPoPProof, "The refresh token is bound to another DPoP key.")
	}
	scopes := stored.Scopes
	if requested != nil {
		if scopes, err = within(requested, stored.Scopes); err != nil {
			return TokenResponse{}, err
		}
	}
	var resp TokenResponse
	err = t.db.Tx(ctx, func(ctx context.Context) error {
		n, err := t.db.Update(ctx, TableTokens, store.Criteria{"id": stored.ID, "revoked_at": nil}, store.Data{"revoked_at": now})
		if err != nil {
			return err
		}
		if n != 1 {
			return refusal(CodeInvalidGrant, "The refresh token was already used.")
		}
		resp, err = t.issue(ctx, c, Grant{
			UserID: stored.UserID, OrganizationID: stored.OrganizationID, Scopes: scopes, Resource: stored.Resource,
			DPoPJKT: stored.DPoPJKT, Actor: stored.Actor, AuthTime: stored.AuthTime, FamilyID: stored.FamilyID,
		})
		return err
	})
	return resp, err
}

// revoke ends the client's own token (RFC 7009); an unknown one is not an error. It returns what
// was revoked, nil when nothing was.
func (t *tokens) revoke(ctx context.Context, raw string, c Client) (*record, error) {
	found, err := t.lookup(ctx, raw)
	if err != nil || found == nil || found.ClientID != c.ClientID || found.RevokedAt != nil {
		return nil, err
	}
	now := t.clock.Now()
	if _, err := t.db.Update(ctx, TableTokens, store.Criteria{"id": found.ID}, store.Data{"revoked_at": now}); err != nil {
		return nil, err
	}
	if found.Kind == kindRefresh && found.FamilyID != "" {
		if _, err := t.revokeFamily(ctx, found.FamilyID); err != nil {
			return nil, err
		}
	}
	revoked := *found
	revoked.RevokedAt = &now
	return &revoked, nil
}

// introspect answers RFC 7662: whether the token is live, and its claims when it is.
func (t *tokens) introspect(ctx context.Context, raw string) (map[string]any, error) {
	found, err := t.lookup(ctx, raw)
	if err != nil {
		return nil, err
	}
	if found == nil || !found.live(t.clock.Now()) {
		return map[string]any{"active": false}, nil
	}
	sub := found.UserID
	if sub == "" {
		sub = found.ClientID
	}
	out := map[string]any{
		"active": true, "client_id": found.ClientID, "token_type": tokenType(found.DPoPJKT),
		"scope": strings.Join(found.Scopes, " "), "sub": sub, "iss": t.issuer,
		"iat": found.CreatedAt.Unix(), "exp": found.ExpiresAt.Unix(), "jti": found.ID,
	}
	if found.Resource != "" {
		out["aud"] = found.Resource
	}
	if found.OrganizationID != "" {
		out["org"] = found.OrganizationID
	}
	if found.DPoPJKT != "" {
		out["cnf"] = map[string]any{"jkt": found.DPoPJKT}
	}
	if found.Actor != nil {
		out["act"] = found.Actor.view()
	}
	return out, nil
}

// find is the record behind an access token's jti, live or not; nil when unknown.
func (t *tokens) find(ctx context.Context, jti string) (*record, error) {
	row, err := t.db.FindOne(ctx, TableTokens, store.Criteria{"id": jti})
	if err != nil || row == nil {
		return nil, err
	}
	r := recordFromRow(row)
	return &r, nil
}

func (t *tokens) findRefresh(ctx context.Context, secret string) (*record, error) {
	if !strings.HasPrefix(secret, refreshPrefix) {
		return nil, nil
	}
	row, err := t.db.FindOne(ctx, TableTokens, store.Criteria{"token_hash": t.pepper.Hash(refreshPepper, secret)})
	if err != nil || row == nil {
		return nil, err
	}
	r := recordFromRow(row)
	return &r, nil
}

// lookup is a refresh token by its hash, or an access token by the jti of a JWT this server signed.
func (t *tokens) lookup(ctx context.Context, raw string) (*record, error) {
	if strings.HasPrefix(raw, refreshPrefix) {
		return t.findRefresh(ctx, raw)
	}
	claims, err := t.verifyAccess(raw)
	if err != nil {
		return nil, nil
	}
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, nil
	}
	return t.find(ctx, jti)
}

// verifyAccess verifies one of the provider's access tokens (typ at+jwt) and returns its claims.
func (t *tokens) verifyAccess(raw string) (map[string]any, error) {
	tok, err := t.codec.VerifyJWT(raw, verifyLeeway)
	if err != nil {
		return nil, refusalWith(CodeInvalidToken, "The token is not valid.", 401)
	}
	if tok.Header("typ") != AccessTokenType {
		return nil, refusalWith(CodeInvalidToken, "The token is not a "+AccessTokenType+".", 401)
	}
	return tok.Claims(), nil
}

func (t *tokens) revokeWhere(ctx context.Context, c store.Criteria) (int64, error) {
	live := maps.Clone(c)
	live["revoked_at"] = nil
	return t.db.Update(ctx, TableTokens, live, store.Data{"revoked_at": t.clock.Now()})
}

func (t *tokens) revokeFamily(ctx context.Context, familyID string) (int64, error) {
	return t.revokeWhere(ctx, store.Criteria{"family_id": familyID})
}

func (t *tokens) deleteWhere(ctx context.Context, c store.Criteria) error {
	_, err := t.db.Delete(ctx, TableTokens, c)
	return err
}
