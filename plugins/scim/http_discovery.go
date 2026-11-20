package scim

import (
	"context"
	"net/http"

	"github.com/univeros/polaris-go/endpoint"
)

// serviceProviderConfig answers what this server supports: filtering and PATCH, bearer tokens; no
// bulk, sorting or ETags.
func (p *Plugin) serviceProviderConfig(_ context.Context, _ *endpoint.Input, conn Connection) endpoint.Result {
	return scim(http.StatusOK, map[string]any{
		"schemas":        []string{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch":          map[string]any{"supported": true},
		"bulk":           map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":         map[string]any{"supported": true, "maxResults": MaxCount},
		"changePassword": map[string]any{"supported": false},
		"sort":           map[string]any{"supported": false},
		"etag":           map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{{"type": "oauthbearertoken", "name": "Bearer token",
			"description": "The connection token as Authorization: Bearer", "primary": true}},
		"meta": map[string]any{"resourceType": "ServiceProviderConfig", "location": p.location(conn) + "/ServiceProviderConfig"},
	})
}

// resourceTypes answers Users and Groups.
func (p *Plugin) resourceTypes(_ context.Context, _ *endpoint.Input, conn Connection) endpoint.Result {
	location := p.location(conn)
	resourceType := func(id, endpoint, schema string) map[string]any {
		return map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"}, "id": id, "name": id,
			"endpoint": endpoint, "schema": schema,
			"meta": map[string]any{"resourceType": "ResourceType", "location": location + "/ResourceTypes/" + id}}
	}
	return listResponse(page{total: 2, resources: []map[string]any{
		resourceType(KindUser, "/Users", UserSchema), resourceType(KindGroup, "/Groups", GroupSchema),
	}}, 1)
}

// schemas answers the User and Group schemas: the attributes this server maps.
func (p *Plugin) schemas(_ context.Context, _ *endpoint.Input, conn Connection) endpoint.Result {
	location := p.location(conn) + "/Schemas/"
	complexAttribute := func(name string, multi bool, mutability string, subs ...map[string]any) map[string]any {
		return map[string]any{"name": name, "type": "complex", "multiValued": multi, "required": false,
			"mutability": mutability, "returned": "default", "subAttributes": subs}
	}
	return listResponse(page{total: 2, resources: []map[string]any{
		{
			"id": UserSchema, "name": "User", "description": "A member of the organization",
			"attributes": []map[string]any{
				attribute("userName", "string", true, "server", "The member's email address"),
				attribute("displayName", "string", false, "none", ""),
				attribute("externalId", "string", false, "none", ""),
				attribute("active", "boolean", false, "none", ""),
				complexAttribute("name", false, "readWrite", attribute("formatted", "string", false, "none", ""),
					attribute("givenName", "string", false, "none", ""), attribute("familyName", "string", false, "none", "")),
				complexAttribute("emails", true, "readWrite", attribute("value", "string", false, "none", ""),
					attribute("primary", "boolean", false, "none", "")),
				complexAttribute("groups", true, "readOnly", attribute("value", "string", false, "none", ""),
					attribute("display", "string", false, "none", "")),
			},
			"meta": map[string]any{"resourceType": "Schema", "location": location + UserSchema},
		},
		{
			"id": GroupSchema, "name": "Group", "description": "A role of the organization",
			"attributes": []map[string]any{
				attribute("displayName", "string", true, "server", ""),
				attribute("externalId", "string", false, "none", ""),
				complexAttribute("members", true, "readWrite", attribute("value", "string", false, "none", ""),
					attribute("display", "string", false, "none", "")),
			},
			"meta": map[string]any{"resourceType": "Schema", "location": location + GroupSchema},
		},
	}}, 1)
}

func attribute(name, typ string, required bool, uniqueness, description string) map[string]any {
	return map[string]any{"name": name, "type": typ, "multiValued": false, "required": required, "caseExact": false,
		"mutability": "readWrite", "returned": "default", "uniqueness": uniqueness, "description": description}
}
