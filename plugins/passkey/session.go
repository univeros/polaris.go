package passkey

import (
	"context"
	"fmt"

	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/mfa"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/token"
)

// amr is what a passkey sign-in records.
const amr = "passkey"

// openSession is how a passkey sign-in ends. With user verification the passkey is two factors:
// a session with mfa true. Without it core's gate applies, offering the user's other confirmed
// factors (the signing passkey cannot be its own second factor); a user whose only factor is
// that passkey is refused.
func (p *Plugin) openSession(ctx context.Context, u model.User, client token.ClientContext, userVerified bool, usedFactorID string) (map[string]any, error) {
	if u.Status == model.UserStatusDisabled {
		return nil, &refusal{kindAccountDisabled, "This account is disabled."}
	}
	if p.g.Auth.Flows.RequireVerifiedEmail && u.EmailVerifiedAt == nil {
		return nil, &refusal{kindEmailUnverified, "Verify your email address before signing in."}
	}
	if !userVerified {
		all, err := p.g.MFA.ConfirmedFactors(ctx, u.ID)
		if err != nil {
			return nil, err
		}
		var others []model.MFAFactor
		for _, f := range all {
			if f.ID != usedFactorID {
				others = append(others, f)
			}
		}
		if len(all) > 0 && len(others) == 0 {
			return nil, &refusal{kindUserVerificationReqd, "This passkey is the account's only second factor: the authenticator must verify the user (a PIN, a fingerprint, a face)."}
		}
		if len(others) > 0 {
			c, err := p.g.MFA.BeginLogin(u.ID, others)
			if err != nil {
				return nil, err
			}
			return map[string]any{"mfa_required": true, "mfa_token": c.MFAToken, "factors": c.Factors}, nil
		}
	}
	principal, err := p.g.Principals.Resolve(ctx, u.ID, "")
	if err != nil {
		return nil, fmt.Errorf("passkey: resolve principal: %w", err)
	}
	now := p.now()
	authTime := now.Unix()
	principal.MFA, principal.AMR, principal.AuthTime = userVerified, []string{amr}, &authTime
	next := u
	next.LastLoginAt, next.UpdatedAt = &now, now
	var issued token.IssuedTokens
	err = p.g.DB.Tx(ctx, func(ctx context.Context) error {
		if err := p.g.Repos.Users.Update(ctx, u, next); err != nil {
			return err
		}
		issued, err = p.g.Sessions.Issue(ctx, principal, client)
		return err
	})
	if err != nil {
		return nil, err
	}
	p.g.Events.Dispatch(ctx, event.UserLoggedIn{UserID: u.ID, SessionID: issued.SessionID, IP: optional(client.IP), UserAgent: optional(client.UserAgent), AMR: []string{amr}})
	return map[string]any{
		"access_token": issued.AccessToken, "token_type": "Bearer", "expires_in": issued.AccessExpiresIn, "refresh_token": issued.RefreshToken,
		"user": map[string]any{"id": u.ID, "email": u.Email, "email_verified": u.EmailVerifiedAt != nil},
	}, nil
}

func optional(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// factor is the passkey factor type for core's gate and step-up: the code is the assertion the
// browser answered to POST /passkey/authenticate/options, verified for the passkey behind the factor.
type factor struct{ p *Plugin }

// Type implements mfa.FactorType.
func (factor) Type() string { return FactorType }

// Verify implements mfa.FactorType: why an assertion failed stays here, core answers every
// refused second factor the same way.
func (f factor) Verify(ctx context.Context, fac model.MFAFactor, code string, _ mfa.ChallengePurpose) error {
	err := f.p.verifyFactor(ctx, fac, code)
	if _, refused := asRefusal(err); refused {
		return fmt.Errorf("%w: the passkey assertion does not verify", mfa.ErrInvalidOTP)
	}
	return err
}
