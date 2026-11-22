package httpapi_test

import (
	"net/http"
	"testing"

	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/repository"
)

// Replays the OrgSwitchEndpointTest fixtures: POST /auth/switch-org re-scopes the session's access token to the
// chosen organization (its org and roles claims), the re-scoping survives a refresh, and only an
// active member may switch in.
func TestOrgSwitchEndpoint(t *testing.T) {
	const founder = "founder@example.com"
	orgRun(t, "OrgSwitchEndpointTest", map[string]func(*orgCase){
		"testSwitchReScopesTheAccessTokenToTheChosenOrg": func(o *orgCase) {
			access := o.login(founder).access
			claims := orgClaims(o.t, access)
			o.equal(claims["org"], nil, "org right after login")
			o.equal(claims["roles"], []string{}, "roles right after login")

			acme := o.createOrg("Acme", access)
			globex := o.createOrg("Globex", access)

			switched := o.data(o.c.Post("/auth/switch-org", map[string]any{"organization_id": acme}, contracttest.Bearer(access)))
			o.equal(switched["org"], acme, "org")
			acmeClaims := orgClaims(o.t, switched["access_token"].(string))
			o.equal(acmeClaims["org"], acme, "org claim")
			o.equal(acmeClaims["roles"], []string{"owner"}, "roles claim")

			toGlobex := o.data(o.c.Post("/auth/switch-org", map[string]any{"organization_id": globex}, contracttest.Bearer(access)))
			o.equal(orgClaims(o.t, toGlobex["access_token"].(string))["org"], globex, "org claim")
		},
		"testSwitchedOrgPersistsThroughRefresh": func(o *orgCase) {
			session := o.login(founder)
			acme := o.createOrg("Acme", session.access)
			o.status(o.c.Post("/auth/switch-org", map[string]any{"organization_id": acme}, contracttest.Bearer(session.access)), http.StatusOK)

			// The session's organization context moved, so a refresh resolves the same org and roles.
			refreshed := o.data(o.c.Post("/auth/token/refresh", map[string]any{"refresh_token": session.refresh}))
			claims := orgClaims(o.t, refreshed["access_token"].(string))
			o.equal(claims["org"], acme, "org claim")
			o.equal(claims["roles"], []string{"owner"}, "roles claim")
		},
		"testCannotSwitchToAnOrgYouDoNotBelongTo": func(o *orgCase) {
			acme := o.createOrg("Acme", o.login(founder).access)
			outsider := o.login("outsider@example.com").access

			resp := o.c.Post("/auth/switch-org", map[string]any{"organization_id": acme}, contracttest.Bearer(outsider))
			o.status(resp, http.StatusForbidden)
			o.equal(o.errorCode(resp), "forbidden", "error")
		},
		"testUnknownOrgIsRejected": func(o *orgCase) {
			access := o.login(founder).access
			o.status(o.c.Post("/auth/switch-org", map[string]any{"organization_id": repository.NewID()}, contracttest.Bearer(access)), http.StatusNotFound)
		},
		"testOrganizationIdIsRequired": func(o *orgCase) {
			access := o.login(founder).access
			o.status(o.c.Post("/auth/switch-org", nil, contracttest.Bearer(access)), http.StatusUnprocessableEntity)
		},
		"testRequiresAuthentication": func(o *orgCase) {
			o.status(o.c.Post("/auth/switch-org", map[string]any{"organization_id": repository.NewID()}), http.StatusUnauthorized)
		},
	})
}
