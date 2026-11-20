package anonymous

import (
	"context"
	"errors"
	"net/http"

	"github.com/univeros/polaris-go/endpoint"
)

// Route names.
const (
	RouteSignIn  = "polaris.anonymous.sign-in"
	RouteConvert = "polaris.anonymous.convert"
)

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	return map[string]endpoint.Endpoint{
		RouteSignIn:  endpoint.Func(p.signIn),
		RouteConvert: endpoint.Func(p.convert),
	}
}

func (p *Plugin) signIn(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	tokens, user, err := p.guests.SignIn(ctx, endpoint.Client(ctx))
	if err != nil {
		return p.fail(ctx, err)
	}
	return endpoint.Data(http.StatusCreated, map[string]any{
		"access_token":  tokens.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    tokens.AccessExpiresIn,
		"refresh_token": tokens.RefreshToken,
		"user":          map[string]any{"id": user.ID, "email": user.Email, "email_verified": false},
	})
}

func (p *Plugin) convert(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	accessToken := in.String("access_token")
	if accessToken == "" {
		const msg = "access_token is required."
		return endpoint.Problem(http.StatusUnprocessableEntity, "anonymous/invalid_input", "Invalid input", msg, map[string]any{"errors": []string{msg}})
	}
	guestID := tok.Subject()
	userID, err := p.guests.Convert(ctx, guestID, accessToken)
	switch {
	case errors.Is(err, ErrNotAGuest):
		return endpoint.Problem(http.StatusForbidden, "anonymous/not_a_guest", "Not a guest", "Only a guest session can be converted.", nil)
	case errors.Is(err, ErrTokenInvalid):
		return endpoint.Problem(http.StatusUnprocessableEntity, "anonymous/token_invalid", "Invalid token", "The access token is not a live session of another account.", nil)
	case err != nil:
		return p.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"guest_id": guestID, "user_id": userID, "status": "converted"})
}

func (p *Plugin) fail(ctx context.Context, err error) endpoint.Result {
	p.guests.g.Logger.ErrorContext(ctx, "polaris anonymous: operation failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}
