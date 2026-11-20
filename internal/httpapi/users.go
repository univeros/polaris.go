package httpapi

import (
	"context"
	"errors"
	"github.com/univeros/polaris.go/internal/services"
	"net/http"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/session"
	"github.com/univeros/polaris.go/token"
)

// User administration (/users/{id}), switching the active organization and accepting an
// invitation: the routes of the orgs area that act on the caller's account.

func (a orgAPI) readUser(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	user, err := services.Of(a.g).Identity.ReadUser(ctx, tok.Subject(), endpoint.ActorOrganization(tok), in.String("id"))
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, user)
}

func (a orgAPI) updateUser(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	var displayName *string
	if raw := in.Value("display_name"); raw != nil {
		s, ok := raw.(string)
		if !ok {
			return endpoint.Unprocessable([]string{"display_name must be a string."})
		}
		displayName = &s
	}
	user, err := services.Of(a.g).Identity.UpdateProfile(ctx, tok.Subject(), endpoint.ActorOrganization(tok), in.String("id"), displayName)
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, user)
}

func (a orgAPI) deleteUser(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	if err := services.Of(a.g).Identity.EraseUser(ctx, tok.Subject(), endpoint.ActorOrganization(tok), in.String("id")); err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"deleted": true})
}

func (a orgAPI) disableUser(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	if err := a.g.Identity().DisableUser(ctx, tok.Subject(), in.String("id")); err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"status": model.UserStatusDisabled})
}

func (a orgAPI) enableUser(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	if err := a.g.Identity().EnableUser(ctx, tok.Subject(), in.String("id")); err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"status": model.UserStatusActive})
}

func (a orgAPI) switchOrg(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	userID := tok.Subject()
	sessionID, _ := tok.Claim("sid").(string)
	if userID == "" || sessionID == "" {
		return endpoint.Unauthorized()
	}
	orgID := in.String("organization_id")
	if orgID == "" {
		return endpoint.Unprocessable([]string{"An organization_id is required."})
	}
	_, active, err := a.activeOrg(ctx, orgID)
	if err != nil {
		return a.fail(ctx, err)
	}
	if !active {
		// A soft-deleted organization is indistinguishable from an unknown one.
		return endpoint.NotFound(orgMsgOrgNotFound)
	}
	m, err := a.g.Repos().Memberships.ByUserAndOrganization(ctx, userID, orgID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return a.fail(ctx, err)
	}
	if err != nil || m.Status != model.MembershipStatusActive {
		return endpoint.Forbidden("You are not an active member of that organization.")
	}
	access, err := services.Of(a.g).Sessions.SwitchOrganization(ctx, userID, orgID, sessionID)
	if errors.Is(err, session.ErrInvalidGrant) {
		return endpoint.Error(http.StatusUnauthorized, "session_ended", "The session is no longer active.")
	}
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(a.g.Auth().AccessToken.TTL.Seconds()),
		"org":          orgID,
	})
}

func (a orgAPI) acceptInvite(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	secret := in.String("token")
	if secret == "" {
		return endpoint.Unprocessable([]string{"An invitation token is required."})
	}
	orgID, err := services.Of(a.g).Orgs.AcceptInvitation(ctx, tok.Subject(), secret)
	if err != nil {
		return a.fail(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"organization_id": orgID})
}
