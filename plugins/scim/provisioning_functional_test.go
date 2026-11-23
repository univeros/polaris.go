package scim_test

import (
	"reflect"
	"slices"
	"testing"

	"github.com/univeros/polaris.go/plugins/scim"
)

func TestScimProvisioning(t *testing.T) {
	t.Run("testADirectoryProvisionsUsersAndGroups", func(t *testing.T) {
		f := newFlow(t, "ScimProvisioningTest", "testADirectoryProvisionsUsersAndGroups")
		ada := f.login("ada@acme.example")
		acme, owner := f.organization("Acme Rockets", ada)
		connection, token := f.connection(acme, owner, "Okta")
		_, otherToken := f.connection(acme, owner, "Entra")
		b := "/scim/v2/" + connection
		get := func(path string) map[string]any { return doc(t, f.scim("GET", b+path, nil, token)) }
		same := func(got, want any, what string) {
			t.Helper()
			check(t, reflect.DeepEqual(got, want), "%s: %v, want %v", what, got, want)
		}

		scimError(t, f.scim("GET", b+"/Users", nil, ""), 401, "")
		scimError(t, f.scim("GET", b+"/Users", nil, "pst_nope"), 401, "")
		scimError(t, f.scim("GET", b+"/Users", nil, otherToken), 401, "")
		check(t, f.scim("GET", b+"/ServiceProviderConfig", nil, token).Header.Get("Content-Type") == scim.ContentType, "content type")
		same(get("/Schemas")["totalResults"], 2.0, "schemas")
		same(column(items(get("/ResourceTypes")["Resources"]), "id"), []any{"User", "Group"}, "resource types")

		scimError(t, f.scim("POST", b+"/Users", map[string]any{"userName": "not an email"}, token), 400, "invalidValue")
		bob := doc(t, f.scim("POST", b+"/Users", map[string]any{"schemas": []string{scim.UserSchema}, "userName": "Bob@Acme.example",
			"externalId": "okta-bob", "name": map[string]any{"givenName": "Bob", "familyName": "Builder"},
			"emails": []any{map[string]any{"value": "bob@acme.example", "primary": true}}, "active": true}, token))
		bobID := bob["id"].(string)
		same([]any{bob["userName"], bob["displayName"], bob["externalId"], bob["active"], column(items(bob["groups"]), "display")},
			[]any{"bob@acme.example", "Bob Builder", "okta-bob", true, []any{"Member"}}, "bob")
		same(bob["meta"].(map[string]any)["location"], base+"/scim/v2/"+connection+"/Users/"+bobID, "location")
		scimError(t, f.scim("POST", b+"/Users", map[string]any{"userName": "bob@acme.example"}, token), 409, "uniqueness")
		scimError(t, f.scim("GET", b+"/Users?filter=userName%20pr", nil, token), 400, "invalidFilter")
		found := get("/Users" + q(`userName eq "bob@acme.example"`))
		same([]any{found["totalResults"], found["itemsPerPage"], column(items(found["Resources"]), "id")}, []any{1.0, 1.0, []any{bobID}}, "found")
		same(get("/Users")["totalResults"], 2.0, "ada and bob")
		same(get("/Users?startIndex=2&count=1")["itemsPerPage"], 1.0, "paged")
		same(get("/Users/" + bobID)["id"], bobID, "read")
		scimError(t, f.scim("GET", b+"/Users/nope", nil, token), 404, "")

		patched := doc(t, f.scim("PATCH", b+"/Users/"+bobID, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{
			map[string]any{"op": "replace", "path": "active", "value": false},
			map[string]any{"op": "replace", "value": map[string]any{"displayName": "Robert"}},
		}}, token))
		same([]any{patched["active"], patched["displayName"]}, []any{false, "Robert"}, "patched")
		scimError(t, f.scim("PATCH", b+"/Users/"+bobID, map[string]any{"Operations": []any{}}, token), 400, "invalidSyntax")
		replaced := doc(t, f.scim("PUT", b+"/Users/"+bobID, map[string]any{"userName": "bob@acme.example", "displayName": "Bob", "active": true, "externalId": "okta-bob-2"}, token))
		same([]any{replaced["active"], replaced["displayName"], replaced["externalId"]}, []any{true, "Bob", "okta-bob-2"}, "replaced")

		group := doc(t, f.scim("POST", b+"/Groups", map[string]any{"schemas": []string{scim.GroupSchema}, "displayName": "Engineering",
			"externalId": "okta-eng", "members": []any{map[string]any{"value": bobID}}}, token))
		groupID := group["id"].(string)
		same([]any{group["displayName"], group["externalId"], column(items(group["members"]), "value")}, []any{"Engineering", "okta-eng", []any{bobID}}, "group")
		check(t, slices.Contains(column(items(get("/Users/" + bobID)["groups"]), "display"), any("Engineering")), "bob is in engineering")
		scimError(t, f.scim("POST", b+"/Groups", map[string]any{"displayName": "Engineering"}, token), 409, "uniqueness")
		same(get("/Groups" + q(`displayName eq "Engineering"`))["totalResults"], 1.0, "group filter")
		same(get("/Groups")["totalResults"], 4.0, "owner, admin, member and engineering")
		adaID := items(get("/Users" + q(`userName eq "ada@acme.example"`))["Resources"])[0]["id"].(string)
		patchedGroup := doc(t, f.scim("PATCH", b+"/Groups/"+groupID, map[string]any{"schemas": []string{scim.PatchSchema}, "Operations": []any{
			map[string]any{"op": "add", "path": "members", "value": []any{map[string]any{"value": adaID}}},
			map[string]any{"op": "remove", "path": `members[value eq "` + bobID + `"]`},
		}}, token))
		same(column(items(patchedGroup["members"]), "value"), []any{adaID}, "patched group")
		replacedGroup := doc(t, f.scim("PUT", b+"/Groups/"+groupID, map[string]any{"displayName": "Platform", "members": []any{map[string]any{"value": bobID}}}, token))
		same([]any{replacedGroup["displayName"], column(items(replacedGroup["members"]), "value")}, []any{"Platform", []any{bobID}}, "replaced group")
		memberRole := items(get("/Groups" + q(`displayName eq "Member"`))["Resources"])[0]["id"].(string)
		scimError(t, f.scim("PUT", b+"/Groups/"+memberRole, map[string]any{"displayName": "Renamed"}, token), 403, "mutability")
		scimError(t, f.scim("DELETE", b+"/Groups/"+memberRole, nil, token), 403, "mutability")
		status(t, f.scim("DELETE", b+"/Groups/"+groupID, nil, token), 204)
		scimError(t, f.scim("GET", b+"/Groups/"+groupID, nil, token), 404, "")

		status(t, f.scim("DELETE", b+"/Users/"+bobID, nil, token), 204)
		scimError(t, f.scim("GET", b+"/Users/"+bobID, nil, token), 404, "")
		status(t, f.c.Post("/auth/login", map[string]any{"email": "bob@acme.example", "password": password}), 401)
		same(get("/Users")["totalResults"], 1.0, "ada stays: her membership predates the connection")
		state := data(t, f.c.Get("/orgs/"+acme+"/scim/connections/"+connection, bearer(owner)))
		same(state["sync"], map[string]any{"users": 0.0, "groups": 0.0, "provisioned_members": 0.0}, "sync")
		check(t, state["last_sync_at"] != nil, "last sync")
		names := f.auditNames(scim.AuditUserCreated, scim.AuditUserUpdated, scim.AuditUserDeactivated, scim.AuditUserReactivated, scim.AuditUserDeleted,
			scim.AuditGroupCreated, scim.AuditGroupUpdated, scim.AuditGroupDeleted, scim.AuditRequestRejected)
		same(names, []any{scim.AuditUserDeleted /* bob: nobody proved the mailbox */, scim.AuditGroupDeleted, scim.AuditRequestRejected, scim.AuditRequestRejected,
			scim.AuditGroupUpdated, scim.AuditGroupUpdated, scim.AuditRequestRejected, scim.AuditGroupCreated, scim.AuditUserReactivated,
			scim.AuditRequestRejected, scim.AuditUserDeactivated, scim.AuditRequestRejected, scim.AuditRequestRejected, scim.AuditUserCreated,
			scim.AuditRequestRejected}, "audit")
	})
}
