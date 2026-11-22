package sso

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

var hostname = regexp.MustCompile(`^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

type orgHandler func(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result

// orgRoute is an /orgs/{id}/sso route: core checked the bearer and org.update; the path's
// organization must be the token's active one (a superadmin excepted).
func (p *Plugin) orgRoute(f orgHandler) endpoint.Endpoint {
	return endpoint.Func(func(ctx context.Context, in *endpoint.Input) endpoint.Result {
		tok := endpoint.Token(ctx)
		if tok == nil {
			return endpoint.Unauthorized()
		}
		orgID := in.String("id")
		if outside, _ := ctx.Value(outsideKey{}).(bool); outside || orgID == "" || deniesActiveOrg(ctx, tok.Organization(), tok.Claim("roles"), orgID) {
			return ssoProblem(http.StatusForbidden, "forbidden", "Forbidden", "That organization is not your active organization.")
		}
		return f(ctx, in, tok, orgID)
	})
}

// recordUser dispatches an organization member's action.
func (p *Plugin) recordUser(ctx context.Context, name string, tok *token.Token, subjectID, orgID string, data map[string]any) {
	p.record(ctx, Event{Name: name, ActorType: audit.ActorUser, ActorID: tok.Subject(), SubjectID: subjectID, OrganizationID: orgID, Data: data}, endpoint.Client(ctx))
}

// provider is the organization's provider {providerId}, or the problem to answer.
func (p *Plugin) provider(ctx context.Context, in *endpoint.Input, orgID string) (Provider, *endpoint.Result) {
	prov, found, err := p.providers.Find(ctx, in.String("providerId"))
	if err != nil {
		r := p.answer(ctx, err)
		return prov, &r
	}
	if !found || prov.OrganizationID != orgID {
		r := ssoProblem(http.StatusNotFound, "not_found", "Not found", "The provider does not exist in this organization.")
		return prov, &r
	}
	return prov, nil
}

// domain is the organization's domain {domainId}, or the problem to answer.
func (p *Plugin) domain(ctx context.Context, in *endpoint.Input, orgID string) (Domain, *endpoint.Result) {
	d, found, err := p.domains.Find(ctx, in.String("domainId"))
	if err != nil {
		r := p.answer(ctx, err)
		return d, &r
	}
	if !found || d.OrganizationID != orgID {
		r := ssoProblem(http.StatusNotFound, "not_found", "Not found", "The domain does not exist in this organization.")
		return d, &r
	}
	return d, nil
}

func providerMaps(list []Provider) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, prov := range list {
		out[i] = prov.Map()
	}
	return out
}

// listProviders answers GET /orgs/{id}/sso/providers: never the secrets.
func (p *Plugin) listProviders(ctx context.Context, _ *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	list, err := p.providers.ForOrganization(ctx, orgID)
	if err != nil {
		return p.answer(ctx, err)
	}
	return endpoint.Data(http.StatusOK, providerMaps(list))
}

// createProvider answers POST /orgs/{id}/sso/providers.
func (p *Plugin) createProvider(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	fields, errs := providerInput(in.All(), nil)
	if len(errs) > 0 {
		return invalidInput(errs[0], errs...)
	}
	fields.OrganizationID, fields.CreatedBy = orgID, tok.Subject()
	prov, err := p.providers.Create(ctx, fields)
	if err != nil {
		return p.answer(ctx, err)
	}
	p.recordUser(ctx, AuditProviderCreated, tok, prov.ID, orgID, map[string]any{"type": prov.Type, "name": prov.Name})
	return endpoint.Data(http.StatusCreated, prov.Map())
}

// readProvider answers GET /orgs/{id}/sso/providers/{providerId}: with the SP side its IdP needs.
func (p *Plugin) readProvider(ctx context.Context, in *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	prov, refused := p.provider(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	out := prov.Map()
	out["sp"] = map[string]any{"entity_id": p.sp.EntityID(prov.ID), "acs_url": p.sp.ACSURL(prov.ID),
		"slo_url": p.sp.SLOURL(prov.ID), "metadata_url": p.sp.MetadataURL(prov.ID)}
	return endpoint.Data(http.StatusOK, out)
}

// updateProvider answers PATCH .../{providerId}: the fields given replace the provider's; an
// absent client_secret keeps the stored one.
func (p *Plugin) updateProvider(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	prov, refused := p.provider(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	fields, errs := providerInput(in.All(), &prov)
	if len(errs) > 0 {
		return invalidInput(errs[0], errs...)
	}
	updated, err := p.providers.Update(ctx, prov, fields)
	if err != nil {
		return p.answer(ctx, err)
	}
	p.recordUser(ctx, AuditProviderUpdated, tok, prov.ID, orgID, map[string]any{"enabled": updated.Enabled})
	return endpoint.Data(http.StatusOK, updated.Map())
}

// deleteProvider answers DELETE .../{providerId}: the provider and its domains.
func (p *Plugin) deleteProvider(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	prov, refused := p.provider(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	if _, err := p.providers.Delete(ctx, prov.ID); err != nil {
		return p.answer(ctx, err)
	}
	p.recordUser(ctx, AuditProviderDeleted, tok, prov.ID, orgID, map[string]any{"type": prov.Type, "name": prov.Name})
	return endpoint.Data(http.StatusOK, map[string]any{"status": "deleted"})
}

// testProvider answers POST .../{providerId}/test: whether the provider is complete and reachable.
func (p *Plugin) testProvider(ctx context.Context, in *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	prov, refused := p.provider(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	var problems []string
	if prov.Type == TypeOIDC {
		problems = p.oidc.Check(ctx, prov)
	} else {
		problems = p.saml.Check(prov, p.sp)
	}
	return endpoint.Data(http.StatusOK, map[string]any{"ok": len(problems) == 0, "problems": nonNil(problems)})
}

// listDomains answers GET /orgs/{id}/sso/domains, with their verification instructions.
func (p *Plugin) listDomains(ctx context.Context, _ *endpoint.Input, _ *token.Token, orgID string) endpoint.Result {
	list, err := p.domains.ForOrganization(ctx, orgID)
	if err != nil {
		return p.answer(ctx, err)
	}
	out := make([]map[string]any, len(list))
	for i, d := range list {
		out[i] = d.Map()
	}
	return endpoint.Data(http.StatusOK, out)
}

// addDomain answers POST /orgs/{id}/sso/domains: claims a domain for a provider.
func (p *Plugin) addDomain(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	name := strings.ToLower(trimBlank(in.String("domain")))
	if len(name) > 253 || !hostname.MatchString(name) {
		return invalidInput("domain must be a hostname (example.com).")
	}
	prov, found, err := p.providers.Find(ctx, in.String("provider_id"))
	if err != nil {
		return p.answer(ctx, err)
	}
	if !found || prov.OrganizationID != orgID {
		return invalidInput("provider_id must be one of the organization's providers.")
	}
	conflict := ssoProblem(http.StatusConflict, "conflict", "Conflict", "The domain is already claimed.")
	if _, taken, err := p.domains.FindByName(ctx, name); err != nil || taken {
		if err != nil {
			return p.answer(ctx, err)
		}
		return conflict
	}
	d, err := p.domains.Add(ctx, orgID, prov.ID, name)
	if errors.Is(err, store.ErrDuplicate) {
		return conflict // a concurrent claim won
	}
	if err != nil {
		return p.answer(ctx, err)
	}
	p.recordUser(ctx, AuditDomainAdded, tok, d.ID, orgID, map[string]any{"domain": name, "provider_id": prov.ID})
	return endpoint.Data(http.StatusCreated, d.Map())
}

// verifyDomain answers POST .../domains/{domainId}/verify: the DNS record or the well-known file.
func (p *Plugin) verifyDomain(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	d, refused := p.domain(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	if d.VerifiedAt == nil {
		method := p.verifier.Verify(ctx, d.Domain, d.Token)
		if method == "" {
			return ssoProblem(http.StatusUnprocessableEntity, "domain_unverified", "Domain unverified", "Neither the DNS record nor the well-known file carries the token yet.")
		}
		var err error
		if d, err = p.domains.MarkVerified(ctx, d); err != nil {
			return p.answer(ctx, err)
		}
		p.recordUser(ctx, AuditDomainVerified, tok, d.ID, orgID, map[string]any{"domain": d.Domain, "method": method})
	}
	return endpoint.Data(http.StatusOK, d.Map())
}

// deleteDomain answers DELETE .../domains/{domainId}.
func (p *Plugin) deleteDomain(ctx context.Context, in *endpoint.Input, tok *token.Token, orgID string) endpoint.Result {
	d, refused := p.domain(ctx, in, orgID)
	if refused != nil {
		return *refused
	}
	if _, err := p.domains.Delete(ctx, d.ID); err != nil {
		return p.answer(ctx, err)
	}
	p.recordUser(ctx, AuditDomainDeleted, tok, d.ID, orgID, map[string]any{"domain": d.Domain})
	return endpoint.Data(http.StatusOK, map[string]any{"status": "deleted"})
}

// adminList answers GET /admin/sso/providers: oldest first, cursor-paginated, never the secrets;
// an organization-scoped operator sees their organization's. Needs read.
func (p *Plugin) adminList(ctx context.Context, in *endpoint.Input) endpoint.Result {
	orgID := in.String("organization_id")
	if op, ok := admin.Operator(ctx); ok && orgID == "" && op.Scope != admin.ScopeInstance {
		orgID = op.Scope
	}
	if _, refusal, ok := admin.Authorize(ctx, admin.Read, orgID); !ok {
		return refusal
	}
	limit, ok := positiveInt(in.Value("limit"), DefaultLimit)
	if !ok {
		return admin.Invalid("limit must be a positive integer.")
	}
	page, next, err := p.providers.List(ctx, orgID, in.String("cursor"), limit)
	if err != nil {
		return p.answer(ctx, err)
	}
	return endpoint.JSON(http.StatusOK, map[string]any{"data": providerMaps(page), "next_cursor": nullable(next)})
}

// adminDelete answers DELETE /admin/sso/providers/{id}: the provider and its domains. Needs own.
func (p *Plugin) adminDelete(ctx context.Context, in *endpoint.Input) endpoint.Result {
	prov, found, err := p.providers.Find(ctx, in.String("id"))
	if err != nil {
		return p.answer(ctx, err)
	}
	op, refusal, ok := admin.Authorize(ctx, admin.Own, prov.OrganizationID)
	if !ok {
		return refusal
	}
	if !found {
		return admin.NotFound("The provider does not exist.")
	}
	if _, err := p.providers.Delete(ctx, prov.ID); err != nil {
		return p.answer(ctx, err)
	}
	actorType := audit.ActorAdmin
	if op.Type == admin.TypeAPIKey {
		actorType = audit.ActorAPIKey
	}
	p.record(ctx, Event{Name: AuditProviderDeleted, ActorType: actorType, ActorID: op.ID, SubjectID: prov.ID, OrganizationID: prov.OrganizationID,
		Data: map[string]any{"type": prov.Type, "name": prov.Name, "actor_role": string(op.Role)}}, endpoint.Client(ctx))
	return endpoint.Data(http.StatusOK, map[string]any{"status": "deleted"})
}

// positiveInt reads a limit: a decimal integer of at least 1 (a query value of digits only, or a
// JSON integer), clamped to MaxLimit; def when absent or "". Signs, spaces, fractions and
// exponents are refused.
func positiveInt(v any, def int) (int, bool) {
	var s string
	switch v := v.(type) {
	case nil:
		return def, true
	case string:
		s = v
	case json.Number:
		s = v.String()
	default:
		return 0, false
	}
	if s == "" {
		return def, true
	}
	if strings.Trim(s, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, false
	}
	return min(n, MaxLimit), true
}
