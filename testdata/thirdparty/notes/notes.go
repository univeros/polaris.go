// Package notes is a third-party Polaris plugin, built outside the Polaris module: a table, three
// routes, a permission, an erasure listener, a bearer resolver, an MFA factor type and an access
// eraser, using only what the module exports.
package notes

import (
	"context"
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/mfa"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/orgs"
	"github.com/univeros/polaris.go/pipeline"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/session"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

//go:embed api
var api embed.FS

const table = "ext_notes"

// Plugin is the notes plugin.
type Plugin struct{ g *wiring.Graph }

// New returns the plugin.
func New() *Plugin { return &Plugin{} }

var (
	_ wiring.Plugin                 = (*Plugin)(nil)
	_ wiring.SchemaProvider         = (*Plugin)(nil)
	_ wiring.PermissionProvider     = (*Plugin)(nil)
	_ wiring.ManifestProvider       = (*Plugin)(nil)
	_ wiring.Initializer            = (*Plugin)(nil)
	_ wiring.EndpointProvider       = (*Plugin)(nil)
	_ wiring.ListenerProvider       = (*Plugin)(nil)
	_ wiring.BearerResolverProvider = (*Plugin)(nil)
	_ wiring.MFAFactorTypeProvider  = (*Plugin)(nil)
	_ wiring.AccessEraser           = (*Plugin)(nil)
)

func (*Plugin) ID() string { return "notes" }

func (*Plugin) Schema() []schema.Model {
	return []schema.Model{schema.Table(table,
		schema.StringField("id", 36).AsPrimary(),
		schema.StringField("user_id", 36),
		schema.StringField("body", 255),
	)}
}

func (*Plugin) Permissions() map[string]string { return map[string]string{"notes.read": "Read notes"} }

func (*Plugin) Manifest() fs.FS {
	sub, err := fs.Sub(api, "api")
	if err != nil {
		panic(err)
	}
	return sub
}

func (p *Plugin) Init(g *wiring.Graph) error { p.g = g; return nil }

func (p *Plugin) Endpoints(*wiring.Graph) (map[string]endpoint.Endpoint, error) {
	return map[string]endpoint.Endpoint{
		"polaris.notes.sign-in": endpoint.Func(p.signIn),
		"polaris.notes.create":  endpoint.Func(p.create),
		"polaris.notes.whoami":  endpoint.Func(p.whoami),
	}, nil
}

// Listeners erases a deleted user's notes, inside the transaction that deletes the user.
func (p *Plugin) Listeners(g *wiring.Graph) []event.Listener {
	return []event.Listener{func(ctx context.Context, e event.Event) {
		if d, ok := e.(event.UserDeleted); ok {
			_ = p.EraseAccess(ctx, d.UserID)
		}
	}}
}

// EraseAccess implements wiring.AccessEraser.
func (p *Plugin) EraseAccess(ctx context.Context, userID string) error {
	_, err := p.g.DB().Delete(ctx, table, store.Criteria{"user_id": userID})
	return err
}

// BearerResolvers accepts "Bearer note_<user id>" as a delegated credential holding notes.read.
func (p *Plugin) BearerResolvers(*wiring.Graph) []pipeline.BearerResolver {
	return []pipeline.BearerResolver{resolver{}}
}

type resolver struct{}

func (resolver) Resolve(r *http.Request) (*token.Token, error) {
	userID, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer note_")
	if !ok {
		return nil, nil
	}
	return token.NewPrincipal(map[string]any{"sub": userID}).Delegate([]string{"notes.read"}), nil
}

// MFAFactorTypes adds a factor type whose code is always "open sesame".
func (*Plugin) MFAFactorTypes() []mfa.FactorType { return []mfa.FactorType{phrase{}} }

type phrase struct{}

func (phrase) Type() string { return "phrase" }

func (phrase) Verify(_ context.Context, _ model.MFAFactor, code string, purpose mfa.ChallengePurpose) error {
	if code != "open sesame" || purpose != mfa.PurposeLoginMFA && purpose != mfa.PurposeStepUp {
		return mfa.ErrInvalidOTP
	}
	return nil
}

func (p *Plugin) signIn(ctx context.Context, in *endpoint.Input) endpoint.Result {
	var res identity.LoginResult
	res, err := p.g.Identity().Login(ctx, identity.NormalizeEmail(in.String("email")), in.String("password"), endpoint.Client(ctx))
	var pe *identity.PasswordError
	switch {
	case errors.Is(err, identity.ErrInvalidCredentials), errors.Is(err, identity.ErrAccountDisabled), errors.Is(err, identity.ErrEmailNotVerified), errors.As(err, &pe):
		return endpoint.Error(http.StatusUnauthorized, "notes_invalid_credentials", "Invalid email or password.")
	case err != nil:
		return endpoint.Error(http.StatusInternalServerError, "server_error", err.Error())
	}
	if res.MFA != nil {
		views := []mfa.FactorView{}
		for _, f := range res.MFA.Factors {
			views = append(views, mfa.ViewOf(f))
		}
		return endpoint.Data(http.StatusOK, map[string]any{"mfa_required": true, "mfa_token": res.MFA.Ticket, "factors": views})
	}
	return endpoint.Data(http.StatusOK, map[string]any{"access_token": res.Tokens.AccessToken, "user_id": res.UserID})
}

func (p *Plugin) create(ctx context.Context, in *endpoint.Input) endpoint.Result {
	id := repository.NewID()
	row := store.Row{"id": id, "user_id": endpoint.Token(ctx).Subject(), "body": in.String("body")}
	if err := p.g.DB().Insert(ctx, table, row); err != nil {
		return endpoint.Error(http.StatusInternalServerError, "server_error", err.Error())
	}
	return endpoint.Data(http.StatusCreated, map[string]any{"id": id})
}

// whoami reads the caller through every narrow service a plugin is handed.
func (p *Plugin) whoami(ctx context.Context, _ *endpoint.Input) endpoint.Result {
	t := endpoint.Token(ctx)
	var caller authz.Caller = wiring.Caller(t)
	var authority authz.Authority
	authority, err := p.g.Gate().Authority(ctx, caller)
	if err != nil {
		return endpoint.Error(http.StatusInternalServerError, "server_error", err.Error())
	}
	user, err := p.g.Repos().Users.Get(ctx, t.Subject())
	if errors.Is(err, repository.ErrNotFound) {
		return endpoint.Error(http.StatusNotFound, "not_found", "No such user.")
	}
	var sessions []session.Info
	sessions, _ = p.g.Sessions().List(ctx, user.ID, "")
	var members []orgs.Member
	if org := t.Organization(); org != "" {
		if members, err = p.g.Orgs().ListMembers(ctx, org, false); errors.Is(err, orgs.ErrNotFound) {
			members = nil
		}
	}
	factors, _ := p.g.MFA().ConfirmedFactors(ctx, user.ID)
	var core []authz.Permission = p.g.Catalog().Permissions()
	return endpoint.Data(http.StatusOK, map[string]any{
		"email":       user.Email,
		"kind":        string(token.KindOf(t)),
		"can_read":    authority.Allows("notes.read"),
		"superadmin":  authority.IsSuperadmin(),
		"sessions":    len(sessions),
		"members":     len(members),
		"factors":     len(factors),
		"permissions": len(core),
		"key_hash":    p.g.Pepper().Hash("notes", user.ID),
		"owner_role":  authz.RoleOwner,
		"now":         p.g.Clock().Now(),
	})
}
