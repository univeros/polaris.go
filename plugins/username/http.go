package username

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/univeros/polaris-go/endpoint"
	"github.com/univeros/polaris-go/identity"
	"github.com/univeros/polaris-go/mfa"
	"github.com/univeros/polaris-go/repository"
)

// Route names.
const (
	RouteSignIn = "polaris.username.sign-in"
	RouteUpdate = "polaris.username.update"
)

// nobody is the address an unknown username is looked up as: it cannot exist, so the login costs
// the same dummy verify as an unknown email.
const nobody = "nobody@username.invalid"

func (p *Plugin) fail(ctx context.Context, op string, err error) endpoint.Result {
	p.g.Logger().ErrorContext(ctx, "polaris username: "+op+" failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

// signIn answers POST /username/sign-in through core's password login.
func (p *Plugin) signIn(ctx context.Context, in *endpoint.Input) endpoint.Result {
	identifier, _ := in.Value("username").(string)
	password, _ := in.Value("password").(string)
	if identifier = trim(identifier); identifier == "" || password == "" {
		return endpoint.Problem(http.StatusUnprocessableEntity, "username/invalid_input", "Invalid input", "A username (or email) and a password are required.", nil)
	}
	email, err := p.email(ctx, identifier)
	if err != nil {
		return p.fail(ctx, "sign-in", err)
	}
	res, err := p.g.Identity().Login(ctx, email, password, endpoint.Client(ctx))
	switch {
	case errors.Is(err, identity.ErrEmailNotVerified):
		return endpoint.Problem(http.StatusForbidden, "username/email_unverified", "Email not verified", "Verify your email address before signing in.", nil)
	case errors.Is(err, identity.ErrAccountDisabled):
		return endpoint.Problem(http.StatusForbidden, "username/account_disabled", "Account disabled", "This account is disabled.", nil)
	case errors.Is(err, identity.ErrInvalidCredentials):
		return endpoint.Problem(http.StatusUnauthorized, "username/invalid_credentials", "Invalid credentials", "Invalid username or password.", nil)
	case err != nil:
		return p.fail(ctx, "sign-in", err)
	}
	if res.MFA != nil {
		views := make([]mfa.FactorView, 0, len(res.MFA.Factors))
		for _, f := range res.MFA.Factors {
			views = append(views, mfa.ViewOf(f))
		}
		return endpoint.Data(http.StatusOK, map[string]any{"mfa_required": true, "mfa_token": res.MFA.Ticket, "factors": views})
	}
	return endpoint.Data(http.StatusOK, map[string]any{
		"access_token":  res.Tokens.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    res.Tokens.AccessExpiresIn,
		"refresh_token": res.Tokens.RefreshToken,
		"user":          map[string]any{"id": res.UserID, "email": res.Email, "email_verified": res.EmailVerified},
	})
}

// email is the address identifier signs in with: itself when it is one, the username's owner's
// otherwise, nobody's for an unknown username.
func (p *Plugin) email(ctx context.Context, identifier string) (string, error) {
	if strings.Contains(identifier, "@") {
		return identifier, nil
	}
	userID, err := p.usernames.UserID(ctx, identifier)
	if err != nil || userID == "" {
		return nobody, err
	}
	user, err := p.g.Repos().Users.Get(ctx, userID)
	if errors.Is(err, repository.ErrNotFound) {
		return nobody, nil
	}
	return user.Email, err
}

// update answers PATCH /username.
func (p *Plugin) update(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	name, ok := in.Value("username").(string)
	display, okDisplay := in.Value("display_username").(string)
	if !ok || (in.Value("display_username") != nil && !okDisplay) {
		return invalid([]string{"username is required."})
	}
	rec, err := p.usernames.Set(ctx, tok.Subject(), name, display)
	var bad *InvalidError
	switch {
	case errors.As(err, &bad):
		return invalid(bad.Violations)
	case errors.Is(err, ErrTaken):
		return endpoint.Problem(http.StatusConflict, "username/taken", "Username taken", "The username is taken.", nil)
	case err != nil:
		return p.fail(ctx, "update", err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"username": rec.Username, "display_username": rec.DisplayUsername})
}

func invalid(violations []string) endpoint.Result {
	return endpoint.Problem(http.StatusUnprocessableEntity, "username/invalid", "Invalid username", violations[0], map[string]any{"errors": violations})
}
