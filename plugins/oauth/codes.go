package oauth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"regexp"
	"time"

	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
)

const codePepper = "oauth_code"

var codeVerifierFormat = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// code is a row of polaris_oauth_code.
type code struct {
	ID, ClientID, UserID, OrganizationID string
	Scopes                               []string
	RedirectURI, CodeChallenge           string
	Nonce, Resource, DPoPJKT             string
	AuthTime                             *int64
	ExpiresAt                            time.Time
	UsedAt                               *time.Time
}

// codeReused is an authorization code presented a second time (RFC 9700 §4.5): the token
// endpoint revokes the family its first redemption issued, whose id is the code's.
type codeReused struct{ codeID string }

func (codeReused) Error() string { return "oauth: the authorization code was already used" }

// codes mints and spends authorization codes, stored as keyed hashes.
type codes struct {
	db     store.Adapter
	pepper *security.Pepper
	ttl    time.Duration
	clock  clock.Clock
}

// issue mints a code for a decided request and returns it.
func (s *codes) issue(ctx context.Context, c Client, userID, organizationID string, req pendingRequest, authTime *int64) (string, error) {
	now := s.clock.Now()
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	value := b64(buf)
	scopes, err := store.JSONValue(list(req.Scopes))
	if err != nil {
		return "", err
	}
	return value, s.db.Insert(ctx, TableCodes, store.Row{
		"id": repository.NewID(), "code_hash": s.pepper.Hash(codePepper, value), "client_id": c.ClientID,
		"user_id": userID, "organization_id": null(organizationID), "scopes": scopes,
		"redirect_uri": req.RedirectURI, "code_challenge": req.CodeChallenge, "nonce": null(req.Nonce),
		"resource": null(req.Resource), "dpop_jkt": null(req.DPoPJKT), "auth_time": store.Nullable(authTime),
		"expires_at": now.Add(s.ttl), "used_at": nil, "created_at": now,
	})
}

// consume spends value for the client, redirect URI and PKCE verifier it was issued against. A
// code spent before answers codeReused.
func (s *codes) consume(ctx context.Context, value string, c Client, redirectURI, verifier string) (code, error) {
	row, err := s.db.FindOne(ctx, TableCodes, store.Criteria{"code_hash": s.pepper.Hash(codePepper, value)})
	if err != nil {
		return code{}, err
	}
	if row == nil {
		return code{}, refusal(CodeInvalidGrant, "The authorization code is unknown.")
	}
	stored := code{
		ID: row.String("id"), ClientID: row.String("client_id"), UserID: row.String("user_id"),
		OrganizationID: row.String("organization_id"), Scopes: stringList(row, "scopes"),
		RedirectURI: row.String("redirect_uri"), CodeChallenge: row.String("code_challenge"),
		Nonce: row.String("nonce"), Resource: row.String("resource"), DPoPJKT: row.String("dpop_jkt"),
		AuthTime: intPtr(row, "auth_time"), UsedAt: row.TimePtr("used_at"),
	}
	stored.ExpiresAt, _ = row.Time("expires_at")
	now := s.clock.Now()
	switch {
	case stored.UsedAt != nil:
		return code{}, codeReused{codeID: stored.ID}
	case stored.ClientID != c.ClientID:
		return code{}, refusal(CodeInvalidGrant, "The authorization code was issued to another client.")
	case !stored.ExpiresAt.After(now):
		return code{}, refusal(CodeInvalidGrant, "The authorization code expired.")
	case redirectURI != "" && redirectURI != stored.RedirectURI:
		return code{}, refusal(CodeInvalidGrant, "redirect_uri does not match the authorization request.")
	case !codeVerifierFormat.MatchString(verifier) ||
		subtle.ConstantTimeCompare([]byte(stored.CodeChallenge), []byte(sha256b64(verifier))) != 1:
		return code{}, refusal(CodeInvalidGrant, "code_verifier does not match the code challenge.")
	}
	n, err := s.db.Update(ctx, TableCodes, store.Criteria{"id": stored.ID, "used_at": nil}, store.Data{"used_at": now})
	if err != nil {
		return code{}, err
	}
	if n != 1 {
		return code{}, refusal(CodeInvalidGrant, "The authorization code was already used.")
	}
	stored.UsedAt = &now
	return stored, nil
}
