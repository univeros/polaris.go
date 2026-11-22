package httpapi_test

import (
	"net/http"
	"slices"
	"testing"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/internal/contracttest"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
)

// Replays the OrganizationEndpointsTest fixtures: creating an organization makes the verified caller its owner
// (role templates cloned per organization), slugs are unique and auto-derived, the create is
// all-or-nothing, and the list returns only the caller's organizations.
func TestOrganizationEndpoints(t *testing.T) {
	const email = "founder@example.com"
	orgRun(t, "OrganizationEndpointsTest", map[string]func(*orgCase){
		"testCreateMakesTheCallerTheOwnerWithClonedRoles": func(o *orgCase) {
			access := o.login(email).access
			userID := o.userID(email)

			resp := o.c.Post("/orgs", map[string]any{"name": "Acme Inc"}, contracttest.Bearer(access))
			o.status(resp, http.StatusCreated)
			data := o.data(resp)
			o.equal(data["name"], "Acme Inc", "name")
			o.equal(data["slug"], "acme-inc", "slug is auto-derived from the name")
			o.equal(data["role"], "owner", "role")
			org, _ := data["id"].(string)
			if org == "" {
				o.t.Fatal("no organization id")
			}

			o.equal(o.count("auth_organizations", store.Criteria{"id": org, "created_by": userID, "status": "active"}), 1, "organization row")
			o.equal(o.count("auth_roles", store.Criteria{"organization_id": org, "is_system": false}), 3, "cloned roles")
			ownerRole := o.roleID(org, "owner")
			o.equal(o.count("auth_roles", store.Criteria{"organization_id": org, "slug": "superadmin"}), 0, "superadmin is never cloned")
			o.equal(o.count("auth_role_permissions", store.Criteria{"role_id": ownerRole}), 10, "owner permissions")

			membership := o.idFrom("auth_memberships", store.Criteria{"organization_id": org, "user_id": userID, "status": "active"})
			o.equal(o.count("auth_membership_roles", store.Criteria{"membership_id": membership, "role_id": ownerRole}), 1, "owner membership")

			created := orgEventsOf[event.OrganizationCreated](o.srv)
			if len(created) != 1 || created[0].OrganizationID != org || created[0].OwnerUserID != userID {
				o.t.Fatalf("org.created events: %+v", created)
			}
		},
		"testSlugMustBeUnique": func(o *orgCase) {
			access := o.login(email).access
			o.status(o.c.Post("/orgs", map[string]any{"name": "Acme"}, contracttest.Bearer(access)), http.StatusCreated)

			conflict := o.c.Post("/orgs", map[string]any{"name": "Another", "slug": "acme"}, contracttest.Bearer(access))
			o.status(conflict, http.StatusConflict)
			o.equal(o.errorCode(conflict), "conflict", "error")
		},
		"testCreateFailsClosedOnConflictLeavingNoPartialState": func(o *orgCase) {
			access := o.login(email).access
			o.status(o.c.Post("/orgs", map[string]any{"name": "Acme"}, contracttest.Bearer(access)), http.StatusCreated)
			roles, memberships := o.count("auth_roles", nil), o.count("auth_memberships", nil)

			o.status(o.c.Post("/orgs", map[string]any{"name": "Acme"}, contracttest.Bearer(access)), http.StatusConflict)

			o.equal(o.count("auth_roles", nil), roles, "roles")
			o.equal(o.count("auth_memberships", nil), memberships, "memberships")
			o.equal(o.count("auth_organizations", nil), 1, "organizations")
		},
		"testNameIsRequiredAndUnderivableSlugIsRejected": func(o *orgCase) {
			access := o.login(email).access
			for _, body := range []map[string]any{{"name": "  "}, {"name": "###"}, {"name": "Acme", "slug": "Not Valid"}} {
				o.status(o.c.Post("/orgs", body, contracttest.Bearer(access)), http.StatusUnprocessableEntity)
			}
		},
		"testCreateRequiresAuthentication": func(o *orgCase) {
			o.status(o.c.Post("/orgs", map[string]any{"name": "Acme"}), http.StatusUnauthorized)
		},
		"testCreateRequiresAVerifiedEmail": func(o *orgCase) {
			// A registered but unverified user, with a token minted directly (login itself enforces
			// nothing here, but the claim must be false).
			o.c.Post("/auth/register", map[string]any{"email": "unverified@example.com", "password": orgPassword})
			userID := o.userID("unverified@example.com")
			issued, err := o.srv.Graph().Sessions().Issue(o.ctx, token.SessionPrincipal{UserID: userID}, token.ClientContext{})
			o.must(err)

			resp := o.c.Post("/orgs", map[string]any{"name": "Acme"}, contracttest.Bearer(issued.AccessToken))
			o.status(resp, http.StatusForbidden)
			o.equal(o.errorCode(resp), "email_unverified", "error")
		},
		"testListReturnsOnlyTheCallersOrganizations": func(o *orgCase) {
			access := o.login(email).access
			o.createOrg("Acme", access)
			o.createOrg("Globex", access)

			list := orgMaps(o.json(o.c.Get("/orgs", contracttest.Bearer(access)))["data"])
			var slugs []string
			for _, org := range list {
				slugs = append(slugs, org["slug"].(string))
			}
			if len(list) != 2 || !slices.Contains(slugs, "acme") || !slices.Contains(slugs, "globex") {
				o.t.Fatalf("organizations: %v", slugs)
			}

			other := o.login("other@example.com").access
			o.equal(len(orgMaps(o.json(o.c.Get("/orgs", contracttest.Bearer(other)))["data"])), 0, "another user's organizations")
		},
		"testListRequiresAuthentication": func(o *orgCase) {
			o.status(o.c.Get("/orgs"), http.StatusUnauthorized)
		},
	})
}

// Replays the AuthorizationEnforcementTest fixtures: GET /orgs/{id} (gated on org.read) reads the active
// organization only; superadmins read any.
func TestAuthorizationEnforcement(t *testing.T) {
	const founder = "founder@example.com"
	orgRun(t, "AuthorizationEnforcementTest", map[string]func(*orgCase){
		"testMemberCanReadTheirActiveOrganization": func(o *orgCase) {
			access := o.login(founder).access
			org := o.createOrg("Acme", access)
			scoped := o.switchOrg(access, org)

			resp := o.c.Get("/orgs/"+org, contracttest.Bearer(scoped))
			o.status(resp, http.StatusOK)
			o.equal(o.data(resp)["id"], org, "id")
		},
		"testCannotReadAnOrganizationOutsideTheActiveOne": func(o *orgCase) {
			access := o.login(founder).access
			acme := o.createOrg("Acme", access)
			globex := o.createOrg("Globex", access) // the caller owns this one too…
			scoped := o.switchOrg(access, acme)

			// …but the active organization is Acme.
			resp := o.c.Get("/orgs/"+globex, contracttest.Bearer(scoped))
			o.status(resp, http.StatusForbidden)
			o.equal(o.errorCode(resp), "forbidden", "error")
		},
		"testCannotReadWithoutAnActiveOrg": func(o *orgCase) {
			access := o.login(founder).access
			org := o.createOrg("Acme", access)
			// The login token carries no active organization, so no org.read.
			o.status(o.c.Get("/orgs/"+org, contracttest.Bearer(access)), http.StatusForbidden)
		},
		"testUnauthenticatedIsRejected": func(o *orgCase) {
			o.status(o.c.Get("/orgs/01910000-0000-7000-8000-0000000000aa"), http.StatusUnauthorized)
		},
		"testSuperadminCanReadAnyOrganization": func(o *orgCase) {
			acme := o.createOrg("Acme", o.login(founder).access)

			operator := o.login("operator@example.com").access
			own := o.createOrg("Operations", operator)
			o.grantSuperadmin(o.userID("operator@example.com"))

			scoped := o.switchOrg(operator, own)
			o.equal(orgClaims(o.t, scoped)["roles"], []string{"superadmin"}, "roles claim")

			resp := o.c.Get("/orgs/"+acme, contracttest.Bearer(scoped))
			o.status(resp, http.StatusOK)
			o.equal(o.data(resp)["id"], acme, "id")
		},
	})
}
