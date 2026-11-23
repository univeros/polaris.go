package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/token"
)

// PurposeLoginMFA is the purpose claim of a login-MFA ticket.
const PurposeLoginMFA = "login_mfa"

// MFATickets mints and authenticates the short-lived login_mfa ticket that bridges a password
// success to the MFA challenge/verify step. The ticket is a JWT
// signed like an access token (same key, kid, issuer, audience) with its own TTL
// (config.MFA.LoginTokenTTL) and purpose=login_mfa, which token.Codec.Parse refuses: it can never
// authenticate an ordinary route. Safe for concurrent use.
type MFATickets struct{ codec *token.Codec }

// NewMFATickets builds the ticket codec from the access-token codec's configuration with its TTL
// replaced by ttl. Errors wrap token.ErrInvalidConfig.
func NewMFATickets(accessConfig token.Config, ttl time.Duration) (*MFATickets, error) {
	accessConfig.TTL = ttl
	c, err := token.New(accessConfig)
	if err != nil {
		return nil, err
	}
	return &MFATickets{codec: c}, nil
}

// ticketFactorsClaim lists the factor ids a restricted ticket may complete the gate with.
const ticketFactorsClaim = "mfa_factors"

// Issue mints a ticket for the user who cleared the password step; any of the user's confirmed
// factors completes it.
func (m *MFATickets) Issue(userID string) (string, error) {
	return m.issue(token.Claims{}.With("sub", userID))
}

// IssueFor mints a ticket that only the factors factorIDs (and the user's recovery codes)
// complete: a sign-in whose own proof rules some factors out (a code to the same mailbox, the
// passkey just used) offers the others only.
func (m *MFATickets) IssueFor(userID string, factorIDs []string) (string, error) {
	ids := make([]any, len(factorIDs))
	for i, id := range factorIDs {
		ids[i] = id
	}
	return m.issue(token.Claims{}.With("sub", userID).With(ticketFactorsClaim, ids))
}

func (m *MFATickets) issue(c token.Claims) (string, error) {
	raw, err := m.codec.Issue(c.With("jti", repository.NewID()).With("purpose", PurposeLoginMFA))
	if err != nil {
		return "", fmt.Errorf("session: mfa ticket: %w", err)
	}
	return raw, nil
}

// Authenticate verifies a ticket (signature, issuer, audience, validity window) and returns its
// subject, the user id. Anything else (an access token, another purpose, no subject) fails with
// an error wrapping token.ErrInvalidToken.
func (m *MFATickets) Authenticate(raw string) (string, error) {
	userID, _, err := m.AuthenticateFactors(raw)
	return userID, err
}

// AuthenticateFactors is Authenticate that also returns the factor ids the ticket is restricted to
// (IssueFor); nil when any confirmed factor completes it (Issue).
func (m *MFATickets) AuthenticateFactors(raw string) (string, []string, error) {
	userID, factors, _, err := m.authenticate(raw)
	return userID, factors, err
}

// AuthenticateLive is AuthenticateFactors that also refuses a ticket issued before every session of
// its user, or every other one, was last revoked (a reset or a change of the password, logout
// everywhere, disabling): the first step it stands for ended then. The denylist's watermark is to the
// second; a ticket of that same second passes.
func (m *MFATickets) AuthenticateLive(ctx context.Context, raw string, d *Denylist) (string, []string, error) {
	userID, factors, issuedAt, err := m.authenticate(raw)
	if err != nil {
		return "", nil, err
	}
	revoked, err := d.ticketRevoked(ctx, userID, issuedAt)
	if err != nil {
		return "", nil, err
	}
	if revoked {
		return "", nil, fmt.Errorf("%w: the user's sessions were revoked since the login-MFA ticket was issued", token.ErrInvalidToken)
	}
	return userID, factors, nil
}

func (m *MFATickets) authenticate(raw string) (userID string, factors []string, issuedAt time.Time, err error) {
	t, err := m.codec.Verify(raw)
	if err != nil {
		return "", nil, time.Time{}, err
	}
	if p, _ := t.Claim("purpose").(string); p != PurposeLoginMFA {
		return "", nil, time.Time{}, fmt.Errorf("%w: the token is not a login-MFA ticket", token.ErrInvalidToken)
	}
	if t.Subject() == "" {
		return "", nil, time.Time{}, fmt.Errorf("%w: the login-MFA ticket carries no subject", token.ErrInvalidToken)
	}
	listed, restricted := t.Claim(ticketFactorsClaim).([]any)
	if !restricted {
		if t.Claim(ticketFactorsClaim) != nil {
			return "", nil, time.Time{}, fmt.Errorf("%w: the login-MFA ticket's factors are not a list", token.ErrInvalidToken)
		}
		return t.Subject(), nil, t.IssuedAt(), nil
	}
	factors = make([]string, 0, len(listed))
	for _, v := range listed {
		id, ok := v.(string)
		if !ok {
			return "", nil, time.Time{}, fmt.Errorf("%w: the login-MFA ticket's factors are not strings", token.ErrInvalidToken)
		}
		factors = append(factors, id)
	}
	return t.Subject(), factors, t.IssuedAt(), nil
}

// UserPrincipals is the identity-only PrincipalResolver:
// the user's email_verified flag, no roles or scope. Production wiring uses authz.Principals.
type UserPrincipals struct{ Users repository.Users }

// Resolve implements PrincipalResolver; an unknown user resolves as unverified.
func (u UserPrincipals) Resolve(ctx context.Context, userID, organizationID string) (token.SessionPrincipal, error) {
	user, err := u.Users.Get(ctx, userID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return token.SessionPrincipal{}, fmt.Errorf("session: resolve principal: %w", err)
	}
	return token.SessionPrincipal{UserID: userID, OrganizationID: organizationID, EmailVerified: err == nil && user.EmailVerifiedAt != nil}, nil
}
