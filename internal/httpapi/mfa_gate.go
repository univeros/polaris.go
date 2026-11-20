package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/mfa"
	"github.com/univeros/polaris-go/session"
)

// challenge sends the login-gate OTP; the caller holds the login_mfa ticket, not a session.
func (m *mfaAPI) challenge(ctx context.Context, in *endpoint.Input) endpoint.Result {
	userID, ok := endpoint.MFATicket(ctx)
	if !ok {
		return endpoint.Unauthorized()
	}
	return m.sendChallenge(ctx, in, userID, mfa.PurposeLoginMFA)
}

// stepUpChallenge sends the step-up OTP inside a live session.
func (m *mfaAPI) stepUpChallenge(ctx context.Context, in *endpoint.Input) endpoint.Result {
	userID := mfaSubject(ctx)
	if userID == "" {
		return endpoint.Unauthorized()
	}
	return m.sendChallenge(ctx, in, userID, mfa.PurposeStepUp)
}

func (m *mfaAPI) sendChallenge(ctx context.Context, in *endpoint.Input, userID string, purpose mfa.ChallengePurpose) endpoint.Result {
	factorID := mfaField(in, "factor_id")
	if factorID == "" {
		return endpoint.Unprocessable([]string{mfaMsgNeedFactor})
	}
	r, err := m.g.MFA().Challenge(ctx, userID, factorID, purpose, endpoint.Client(ctx))
	switch {
	case errors.Is(err, mfa.ErrFactorNotFound):
		return endpoint.NotFound(mfaMsgFactorNotFound)
	case errors.Is(err, mfa.ErrOTPCooldown):
		return endpoint.Error(http.StatusTooManyRequests, "too_many_requests", mfaMsgWait)
	case errors.Is(err, mfa.ErrInvalidOTP):
		return endpoint.Error(http.StatusUnprocessableEntity, "unsupported_factor", "This factor does not use a sent challenge.")
	case err != nil:
		return m.fail(ctx, "send challenge", err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"channel": r.Channel, "destination": r.MaskedDestination})
}

// verify completes an MFA login and mints the real session.
func (m *mfaAPI) verify(ctx context.Context, in *endpoint.Input) endpoint.Result {
	userID, ok := endpoint.MFATicket(ctx)
	if !ok {
		return endpoint.Unauthorized()
	}
	code := mfaField(in, "code")
	if code == "" {
		return endpoint.Unprocessable([]string{mfaMsgNeedCode})
	}
	tokens, err := m.g.MFA().VerifyLogin(ctx, userID, mfaVerifyFactor(in), code, endpoint.Client(ctx))
	if res, failed := m.verifyFailure(ctx, "verify login", err); failed {
		return res
	}
	return endpoint.Data(http.StatusOK, map[string]any{
		"access_token":  tokens.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    tokens.AccessExpiresIn,
		"refresh_token": tokens.RefreshToken,
	})
}

// stepUp re-verifies a factor in a live session and returns a fresh access token for it.
func (m *mfaAPI) stepUp(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	sessionID, _ := tok.Claim("sid").(string)
	if tok.Subject() == "" || sessionID == "" {
		return endpoint.Unauthorized()
	}
	code := mfaField(in, "code")
	if code == "" {
		return endpoint.Unprocessable([]string{mfaMsgNeedCode})
	}
	access, err := m.g.MFA().VerifyStepUp(ctx, tok.Subject(), tok.Organization(), sessionID, mfaVerifyFactor(in), code)
	if errors.Is(err, session.ErrInvalidGrant) {
		return endpoint.Unauthorized() // the session ended while its access token was still valid
	}
	if res, failed := m.verifyFailure(ctx, "step up", err); failed {
		return res
	}
	return endpoint.Data(http.StatusOK, map[string]any{"access_token": access, "token_type": "Bearer"})
}

func (m *mfaAPI) verifyFailure(ctx context.Context, op string, err error) (endpoint.Result, bool) {
	switch {
	case err == nil:
		return endpoint.Result{}, false
	case errors.Is(err, mfa.ErrFactorNotFound):
		return endpoint.NotFound(mfaMsgFactorNotFound), true
	case errors.Is(err, mfa.ErrInvalidOTP):
		return endpoint.Error(http.StatusUnprocessableEntity, "invalid_code", mfaMsgInvalidCode), true
	}
	return m.fail(ctx, op, err), true
}

// mfaVerifyFactor is the factor a code is checked against, "" for the recovery-code path:
// chosen by type=recovery or by omitting factor_id.
func mfaVerifyFactor(in *endpoint.Input) string {
	if mfaField(in, "type") == "recovery" {
		return ""
	}
	return mfaField(in, "factor_id")
}
