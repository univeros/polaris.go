package httpapi

import (
	"context"
	"errors"
	"github.com/univeros/polaris.go/internal/services"
	"net/http"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/mfa"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/session"
	"github.com/univeros/polaris.go/token"
)

func (a *authAPI) login(ctx context.Context, in *endpoint.Input) endpoint.Result {
	email := authTrim(authString(in, "email"))
	password := authString(in, "password")
	if email == "" || password == "" {
		return endpoint.Unprocessable([]string{"An email and password are required."})
	}
	if !manifest.IsEmail(email) {
		return endpoint.Unprocessable([]string{authInvalidEmail})
	}
	res, err := a.g.Identity().Login(ctx, email, password, endpoint.Client(ctx))
	switch {
	case errors.Is(err, identity.ErrEmailNotVerified):
		return endpoint.JSON(http.StatusForbidden, map[string]any{
			"error":   "email_unverified",
			"message": "Verify your email address before logging in.",
			"resend":  "/auth/email/verify/resend",
		})
	case errors.Is(err, identity.ErrAccountDisabled):
		return endpoint.Error(http.StatusForbidden, "account_disabled", "This account is disabled.")
	case errors.Is(err, identity.ErrInvalidCredentials):
		return endpoint.Error(http.StatusUnauthorized, "invalid_credentials", "Invalid email or password.")
	case err != nil:
		return a.fail(ctx, "login", err)
	}
	if res.MFA != nil {
		return endpoint.Data(http.StatusOK, map[string]any{
			"mfa_required": true,
			"mfa_token":    res.MFA.Ticket,
			"factors":      authFactorViews(res.MFA.Factors),
		})
	}
	body := authTokenPair(res.Tokens)
	body["user"] = map[string]any{"id": res.UserID, "email": res.Email, "email_verified": res.EmailVerified}
	return endpoint.Data(http.StatusOK, body)
}

func authFactorViews(factors []model.MFAFactor) []mfa.FactorView {
	views := make([]mfa.FactorView, 0, len(factors))
	for _, f := range factors {
		views = append(views, mfa.ViewOf(f))
	}
	return views
}

func authTokenPair(t token.IssuedTokens) map[string]any {
	return map[string]any{
		"access_token":  t.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    t.AccessExpiresIn,
		"refresh_token": t.RefreshToken,
	}
}

func (a *authAPI) refresh(ctx context.Context, in *endpoint.Input) endpoint.Result {
	presented := authTrim(authString(in, "refresh_token"))
	if presented == "" {
		return endpoint.Unprocessable([]string{"A refresh token is required."})
	}
	tokens, err := services.Of(a.g).Sessions.Refresh(ctx, presented, endpoint.Client(ctx))
	switch {
	case errors.Is(err, session.ErrInvalidGrant):
		return endpoint.Error(http.StatusUnauthorized, "invalid_grant", "The refresh token is invalid or expired.")
	case err != nil:
		return a.fail(ctx, "refresh", err)
	}
	return endpoint.Data(http.StatusOK, authTokenPair(tokens))
}

func (a *authAPI) me(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	_, userID, ok := authSubject(ctx)
	if !ok {
		return endpoint.Unauthorized()
	}
	u, err := a.g.Repos().Users.Get(ctx, userID)
	switch {
	case errors.Is(err, repository.ErrNotFound):
		return endpoint.Unauthorized()
	case err != nil:
		return a.fail(ctx, "me", err)
	}
	status := u.Status
	if status == "" {
		status = model.UserStatusActive
	}
	return endpoint.Data(http.StatusOK, map[string]any{
		"id":             u.ID,
		"email":          u.Email,
		"email_verified": u.EmailVerifiedAt != nil,
		"display_name":   u.DisplayName,
		"status":         status,
		"mfa_enforced":   u.MFAEnforced,
		"orgs":           []any{},
		"roles":          []any{},
	})
}

func (a *authAPI) logout(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	// Fail closed: a token with no session (sid) cannot end one, so no logout is reported.
	tok := endpoint.Token(ctx)
	if tok == nil || authSessionID(tok) == "" {
		return endpoint.Unauthorized()
	}
	if err := services.Of(a.g).Sessions.Logout(ctx, authSessionID(tok)); err != nil {
		return a.fail(ctx, "logout", err)
	}
	return authStatus("logged_out")
}

func (a *authAPI) logoutAll(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	_, userID, ok := authSubject(ctx)
	if !ok {
		return endpoint.Unauthorized()
	}
	if err := services.Of(a.g).Sessions.LogoutAll(ctx, userID, endpoint.Client(ctx)); err != nil {
		return a.fail(ctx, "logout all", err)
	}
	return authStatus("logged_out_all")
}

func (a *authAPI) sessions(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	tok, userID, ok := authSubject(ctx)
	if !ok {
		return endpoint.Unauthorized()
	}
	infos, err := a.g.Sessions().List(ctx, userID, authSessionID(tok))
	if err != nil {
		return a.fail(ctx, "list sessions", err)
	}
	out := make([]map[string]any, 0, len(infos))
	for _, s := range infos {
		out = append(out, map[string]any{
			"id":           s.ID,
			"current":      s.Current,
			"ip":           s.IP,
			"user_agent":   s.UserAgent,
			"created_at":   s.CreatedAt.UTC().Format(authDateAtom),
			"last_used_at": s.LastUsedAt.UTC().Format(authDateAtom),
		})
	}
	return endpoint.Data(http.StatusOK, map[string]any{"sessions": out})
}

func (a *authAPI) revokeSession(ctx context.Context, in *endpoint.Input) endpoint.Result {
	_, userID, ok := authSubject(ctx)
	if !ok {
		return endpoint.Unauthorized()
	}
	sessionID := authTrim(authString(in, "id"))
	if sessionID == "" {
		return endpoint.Unprocessable([]string{"A session id is required."})
	}
	revoked, err := a.g.Sessions().Revoke(ctx, userID, sessionID)
	switch {
	case err != nil:
		return a.fail(ctx, "revoke session", err)
	case !revoked:
		return endpoint.NotFound("Session not found.")
	}
	return authStatus("revoked")
}
