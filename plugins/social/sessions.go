package social

import (
	"context"
	"errors"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/mfa"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/token"
)

// user returns the user id names, nil when gone.
func (p *Plugin) user(ctx context.Context, id string) (*model.User, error) {
	u, err := p.g.Repos().Users.Get(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil
	}
	return &u, err
}

func (p *Plugin) userByEmail(ctx context.Context, email string) (*model.User, error) {
	u, err := p.g.Repos().Users.ByEmail(ctx, identity.NormalizeEmail(email))
	if errors.Is(err, repository.ErrNotFound) {
		return nil, nil
	}
	return &u, err
}

// createUser signs up a user without a password, verified when the provider vouched for the email.
func (p *Plugin) createUser(ctx context.Context, email string, verified bool, name string) (model.User, error) {
	now := p.now()
	u := model.User{ID: repository.NewID(), Email: identity.NormalizeEmail(email), Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if verified {
		u.EmailVerifiedAt = &now
	}
	if name != "" {
		u.DisplayName = &name
	}
	return u, p.g.Identity().InsertUser(ctx, u)
}

// openSession is how a social sign-in ends: core's MFA gate when it applies, else a session as
// core opens one with amr ["social:<provider>"], answered as core's login envelope.
func (p *Plugin) openSession(ctx context.Context, u model.User, providerID string, client token.ClientContext) (map[string]any, error) {
	if u.Status == model.UserStatusDisabled {
		return nil, refuse(kindAccountDisabled, "This account is disabled.")
	}
	if p.g.Auth().Flows.RequireVerifiedEmail && u.EmailVerifiedAt == nil {
		return nil, refuse(kindEmailUnverified, "The provider does not vouch for this email address: sign up with the address another way, then link the provider from your account.")
	}
	if p.settings.respectMFA {
		factors, err := p.g.MFA().ConfirmedFactors(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		if len(factors) > 0 {
			return mfaRequired(p.g.MFA().BeginLogin(u.ID, factors))
		}
	}
	principal, err := p.g.Principals().Resolve(ctx, u.ID, "")
	if err != nil {
		return nil, err
	}
	now := p.now()
	authTime := now.Unix()
	amr := []string{"social:" + providerID}
	principal.MFA, principal.AMR, principal.AuthTime = false, amr, &authTime
	next := u
	next.LastLoginAt, next.UpdatedAt = &now, now
	var issued token.IssuedTokens
	err = p.g.DB().Tx(ctx, func(ctx context.Context) error {
		if err := services.Of(p.g).Identity.HoldForSignIn(ctx, u); err != nil {
			return err
		}
		if err := p.g.Repos().Users.Update(ctx, u, next); err != nil {
			return err
		}
		issued, err = p.g.Sessions().Issue(ctx, principal, client)
		return err
	})
	switch {
	case errors.Is(err, identity.ErrAccountDisabled):
		return nil, refuse(kindAccountDisabled, "This account is disabled.")
	case errors.Is(err, identity.ErrInvalidCredentials):
		return nil, refuse(kindTokenInvalid, "The account changed while the provider's answer was checked.")
	case err != nil:
		return nil, err
	}
	p.g.Events().Dispatch(ctx, event.UserLoggedIn{UserID: u.ID, SessionID: issued.SessionID, IP: optional(client.IP), UserAgent: optional(client.UserAgent), AMR: amr})
	return map[string]any{
		"access_token": issued.AccessToken, "token_type": "Bearer", "expires_in": issued.AccessExpiresIn, "refresh_token": issued.RefreshToken,
		"user": map[string]any{"id": u.ID, "email": u.Email, "email_verified": u.EmailVerifiedAt != nil},
	}, nil
}

func mfaRequired(c mfa.LoginChallenge, err error) (map[string]any, error) {
	if err != nil {
		return nil, err
	}
	return map[string]any{"mfa_required": true, "mfa_token": c.MFAToken, "factors": c.Factors}, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
