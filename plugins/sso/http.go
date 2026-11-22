package sso

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/wiring"
)

// Route names.
const (
	RouteSignIn               = "polaris.sso.sign-in"
	RouteCallbackOIDC         = "polaris.sso.callback-oidc"
	RouteCallbackSAML         = "polaris.sso.callback-saml"
	RouteExchange             = "polaris.sso.exchange"
	RouteMetadata             = "polaris.sso.metadata"
	RouteSLORedirect          = "polaris.sso.slo-redirect"
	RouteSLOPost              = "polaris.sso.slo-post"
	RouteLogout               = "polaris.sso.logout"
	RouteProvidersList        = "polaris.sso.providers-list"
	RouteProvidersCreate      = "polaris.sso.providers-create"
	RouteProvidersRead        = "polaris.sso.providers-read"
	RouteProvidersUpdate      = "polaris.sso.providers-update"
	RouteProvidersDelete      = "polaris.sso.providers-delete"
	RouteProvidersTest        = "polaris.sso.providers-test"
	RouteDomainsList          = "polaris.sso.domains-list"
	RouteDomainsAdd           = "polaris.sso.domains-add"
	RouteDomainsVerify        = "polaris.sso.domains-verify"
	RouteDomainsDelete        = "polaris.sso.domains-delete"
	RouteAdminProvidersList   = "polaris.sso.admin-providers-list"
	RouteAdminProvidersDelete = "polaris.sso.admin-providers-delete"
)

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	return map[string]endpoint.Endpoint{
		RouteSignIn:               endpoint.Func(p.signIn),
		RouteCallbackOIDC:         endpoint.Func(p.callbackOIDC),
		RouteCallbackSAML:         endpoint.Func(p.callbackSAML),
		RouteExchange:             endpoint.Func(p.exchange),
		RouteMetadata:             endpoint.Func(p.metadata),
		RouteSLORedirect:          endpoint.Func(p.singleLogout),
		RouteSLOPost:              endpoint.Func(p.singleLogout),
		RouteLogout:               endpoint.Func(p.logout),
		RouteProvidersList:        p.orgRoute(p.listProviders),
		RouteProvidersCreate:      p.orgRoute(p.createProvider),
		RouteProvidersRead:        p.orgRoute(p.readProvider),
		RouteProvidersUpdate:      p.orgRoute(p.updateProvider),
		RouteProvidersDelete:      p.orgRoute(p.deleteProvider),
		RouteProvidersTest:        p.orgRoute(p.testProvider),
		RouteDomainsList:          p.orgRoute(p.listDomains),
		RouteDomainsAdd:           p.orgRoute(p.addDomain),
		RouteDomainsVerify:        p.orgRoute(p.verifyDomain),
		RouteDomainsDelete:        p.orgRoute(p.deleteDomain),
		RouteAdminProvidersList:   endpoint.Func(p.adminList),
		RouteAdminProvidersDelete: endpoint.Func(p.adminDelete),
	}
}

// answer is the problem for a refused step, or a 500 for a failure (logged).
func (p *Plugin) answer(ctx context.Context, err error) endpoint.Result {
	if e, ok := errors.AsType[*Error](err); ok {
		return problem(e)
	}
	p.g.Logger().ErrorContext(ctx, "polaris sso: operation failed", "error", err)
	return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
}

func redirect(location string) endpoint.Result {
	return endpoint.Result{Status: http.StatusFound}.WithHeader("Location", location)
}

// signIn answers POST /sso/sign-in.
func (p *Plugin) signIn(ctx context.Context, in *endpoint.Input) endpoint.Result {
	started, err := p.Start(ctx, in.String("email"), in.String("provider_id"), in.String("redirect_uri"))
	if err != nil {
		return p.answer(ctx, err)
	}
	return endpoint.Data(http.StatusOK, started).WithHeader("Set-Cookie", p.sp.bindingHeader(started))
}

// callbackOIDC answers GET /sso/callback/{providerId}: 302 to the application with the code.
func (p *Plugin) callbackOIDC(ctx context.Context, in *endpoint.Input) endpoint.Result {
	state := in.String("state")
	to, err := p.CompleteOIDC(ctx, in.String("providerId"), in.String("code"), state, p.sp.binding(in.Request, state), in.String("error"), endpoint.Client(ctx))
	if err != nil {
		return p.answer(ctx, err)
	}
	return redirect(to)
}

// callbackSAML answers POST /sso/callback/{providerId} (the POST binding).
func (p *Plugin) callbackSAML(ctx context.Context, in *endpoint.Input) endpoint.Result {
	relay := in.String("RelayState")
	to, err := p.CompleteSAML(ctx, in.String("providerId"), in.String("SAMLResponse"), relay, p.sp.binding(in.Request, relay), endpoint.Client(ctx))
	if err != nil {
		return p.answer(ctx, err)
	}
	return redirect(to)
}

// exchange answers POST /sso/exchange: the login envelope, once.
func (p *Plugin) exchange(ctx context.Context, in *endpoint.Input) endpoint.Result {
	code := in.String("code")
	if code == "" {
		return invalidInput("code is required.")
	}
	data, err := p.Exchange(ctx, code)
	if err != nil {
		return p.answer(ctx, err)
	}
	return endpoint.Data(http.StatusOK, data)
}

// metadata answers GET /sso/metadata/{providerId}: the SP metadata XML.
func (p *Plugin) metadata(ctx context.Context, in *endpoint.Input) endpoint.Result {
	prov, found, err := p.providers.Find(ctx, in.String("providerId"))
	if err != nil {
		return p.answer(ctx, err)
	}
	if !found || prov.Type != TypeSAML {
		return ssoProblem(http.StatusNotFound, ReasonProviderNotFound, "Provider not found", "No SAML provider has this id.")
	}
	xml, err := p.saml.Metadata(prov, p.sp)
	if err != nil {
		return p.answer(ctx, err)
	}
	return endpoint.Result{Status: http.StatusOK, Raw: xml}.WithHeader("Content-Type", "application/samlmetadata+xml")
}

// singleLogout answers GET (redirect binding) and POST /sso/slo/{providerId}: an IdP's
// LogoutRequest ends the user's sessions and is answered with the LogoutResponse redirect; an
// IdP's LogoutResponse ends an application-initiated logout, whose sessions ended already.
func (p *Plugin) singleLogout(ctx context.Context, in *endpoint.Input) endpoint.Result {
	if in.String("SAMLRequest") != "" {
		m := LogoutMessage{SAMLRequest: in.String("SAMLRequest"), RelayState: in.String("RelayState"),
			SigAlg: in.String("SigAlg"), Signature: in.String("Signature"), Redirect: in.Request.Method == http.MethodGet}
		if m.Redirect {
			m.RawQuery = in.Request.URL.RawQuery
		}
		to, err := p.IdPLogout(ctx, in.String("providerId"), m, endpoint.Client(ctx))
		if err != nil {
			return p.answer(ctx, err)
		}
		if to == "" {
			return endpoint.Data(http.StatusOK, map[string]any{"status": "logged_out"})
		}
		return redirect(to)
	}
	if in.String("SAMLResponse") != "" {
		return endpoint.Data(http.StatusOK, map[string]any{"status": "logged_out"})
	}
	return invalidInput("A SAMLRequest or a SAMLResponse is required.")
}

// logout answers POST /sso/logout: the caller's sessions end; url is the IdP's logout.
func (p *Plugin) logout(ctx context.Context, in *endpoint.Input) endpoint.Result {
	tok := endpoint.Token(ctx)
	if tok == nil {
		return endpoint.Unauthorized()
	}
	orgID := in.String("organization_id")
	if orgID == "" {
		orgID = endpoint.ActorOrganization(tok)
	}
	u, err := p.g.Repos().Users.Get(ctx, tok.Subject())
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return p.answer(ctx, err)
	}
	if orgID == "" || err != nil {
		return invalidInput("organization_id is required when the session has no active organization.")
	}
	to, err := p.Logout(ctx, u, orgID, in.String("provider_id"), in.String("post_logout_uri"), endpoint.Client(ctx))
	if err != nil {
		return p.answer(ctx, err)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"status": "logged_out", "url": nullable(to)})
}

// orgRoutes are the organization's self-service routes.
var orgRoutes = []string{RouteProvidersList, RouteProvidersCreate, RouteProvidersRead, RouteProvidersUpdate, RouteProvidersDelete,
	RouteProvidersTest, RouteDomainsList, RouteDomainsAdd, RouteDomainsVerify, RouteDomainsDelete}

type outsideKey struct{}

// activeOrganization orders the organization routes' checks: a caller outside the
// path's organization reads sso/forbidden (not core's org.update 403). Such a request goes on
// without the route's permission requirement, marked so that the endpoint refuses it whatever it
// reads; a caller in the organization goes on unchanged and core enforces org.update.
func activeOrganization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rt, tok := endpoint.Route(ctx), endpoint.Token(ctx)
		if rt == nil || tok == nil || !slices.Contains(orgRoutes, rt.Name) {
			next.ServeHTTP(w, r)
			return
		}
		path := r.URL.EscapedPath()
		orgID, _, _ := strings.Cut(path[strings.LastIndex(path, "/orgs/")+len("/orgs/"):], "/")
		if orgID != "" && !deniesActiveOrg(ctx, tok.Organization(), tok.Claim("roles"), orgID) {
			next.ServeHTTP(w, r)
			return
		}
		refused := *rt
		refused.RequiresPermissions = nil
		ctx = context.WithValue(endpoint.WithRoute(ctx, &refused), outsideKey{}, true)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// deniesActiveOrg: orgID is not the token's active organization and the caller is no superadmin
// (by the authority the authorization step resolved, else the token's roles claim).
func deniesActiveOrg(ctx context.Context, active string, roles any, orgID string) bool {
	if a, ok := wiring.Authority(ctx); ok {
		if a.IsSuperadmin() {
			return false
		}
	} else if list, ok := roles.([]any); ok && slices.Contains(list, any(authz.RoleSuperadmin)) {
		return false
	}
	return orgID != active
}
