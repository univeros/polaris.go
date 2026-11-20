package apikeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// Route names.
const (
	RouteList   = "polaris.api-keys.list"
	RouteCreate = "polaris.api-keys.create"
	RouteRead   = "polaris.api-keys.read"
	RouteUpdate = "polaris.api-keys.update"
	RouteDelete = "polaris.api-keys.delete"
	RouteRotate = "polaris.api-keys.rotate"
	RouteVerify = "polaris.api-keys.verify"
)

// OrganizationPermission is what a member needs to manage an organization's keys.
const OrganizationPermission = authz.OrgUpdate

func (p *Plugin) endpoints() map[string]endpoint.Endpoint {
	authed := func(f func(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result) endpoint.Endpoint {
		return endpoint.Func(func(ctx context.Context, in *endpoint.Input) endpoint.Result {
			tok := endpoint.Token(ctx)
			if tok == nil {
				return endpoint.Unauthorized()
			}
			return f(ctx, in, tok)
		})
	}
	return map[string]endpoint.Endpoint{
		RouteList:   authed(p.list),
		RouteCreate: authed(p.create),
		RouteRead:   authed(p.read),
		RouteUpdate: authed(p.update),
		RouteDelete: authed(p.delete),
		RouteRotate: authed(p.rotate),
		RouteVerify: authed(p.verify),
	}
}

// refuse answers a refused operation as its problem document, any other error as a 500.
func (p *Plugin) refuse(ctx context.Context, err error) endpoint.Result {
	e, ok := asError(err)
	if !ok {
		p.g.Logger().ErrorContext(ctx, "polaris api-keys: operation failed", "error", err)
		return endpoint.Error(http.StatusInternalServerError, "server_error", "The server could not complete the request.")
	}
	switch e.Kind {
	case KindNotFound:
		return endpoint.Problem(http.StatusNotFound, "api-keys/not_found", "Not found", e.Detail, nil)
	case KindForbidden:
		return endpoint.Problem(http.StatusForbidden, "api-keys/forbidden", "Forbidden", e.Detail, nil)
	case KindTooMany:
		return endpoint.Problem(http.StatusConflict, "api-keys/too_many", "Too many keys", e.Detail, nil)
	case KindPermissionNotHeld:
		return endpoint.Problem(http.StatusForbidden, "api-keys/permission_not_held", "Permission not held", e.Detail, nil)
	}
	return endpoint.Problem(http.StatusUnprocessableEntity, "api-keys/invalid_input", "Invalid input", e.Detail, map[string]any{"errors": []string{e.Detail}})
}

func invalidInput(detail string) endpoint.Result {
	return endpoint.Problem(http.StatusUnprocessableEntity, "api-keys/invalid_input", "Invalid input", detail, map[string]any{"errors": []string{"invalid input"}})
}

// owner is who the keys a request is about belong to: the caller, or the organization
// organization_id names when it is the caller's active organization and they may update it.
func (p *Plugin) owner(ctx context.Context, in *endpoint.Input, tok *token.Token) (ownerType, ownerID, orgID string, err error) {
	named := strings.TrimSpace(in.String("organization_id"))
	if named == "" {
		return OwnerUser, tok.Subject(), tok.Organization(), nil
	}
	if named == tok.Organization() {
		allowed, err := p.g.Gate().Allows(ctx, wiring.Caller(tok), OrganizationPermission)
		if err != nil || allowed {
			return OwnerOrganization, named, named, err
		}
	}
	return "", "", "", &Error{Kind: KindForbidden, Detail: "Managing an organization's keys needs it as your active organization and the org.update permission in it."}
}

// manageable is the key {id} names when the caller may manage it: their own, or their active
// organization's when they may update it. Anything else does not exist.
func (p *Plugin) manageable(ctx context.Context, in *endpoint.Input, tok *token.Token) (Key, error) {
	missing := &Error{Kind: KindNotFound, Detail: "The key does not exist."}
	key, ok, err := p.keys.Find(ctx, in.String("id"))
	if err != nil {
		return Key{}, err
	}
	if !ok || key.RevokedAt != nil {
		return Key{}, missing
	}
	if key.OwnerType == OwnerUser && key.OwnerID == tok.Subject() {
		return key, nil
	}
	if key.OwnerType == OwnerOrganization && key.OwnerID == tok.Organization() {
		allowed, err := p.g.Gate().Allows(ctx, wiring.Caller(tok), OrganizationPermission)
		if err != nil || allowed {
			return key, err
		}
	}
	return Key{}, missing
}

// held is what the caller holds in the key's organization, which bounds the key's permissions;
// that organization must be the caller's active one.
func (p *Plugin) held(ctx context.Context, tok *token.Token, orgID string) ([]string, error) {
	if orgID != tok.Organization() {
		return nil, &Error{Kind: KindForbidden, Detail: "The key acts in another organization than your active one; switch to it to change its permissions."}
	}
	a, err := p.g.Gate().Authority(ctx, wiring.Caller(tok))
	return a.Scope, err
}

func (p *Plugin) dispatch(ctx context.Context, name string, tok *token.Token, key Key, data map[string]any) {
	c := endpoint.Client(ctx)
	p.g.Events().Dispatch(ctx, Event{Name: name, ActorID: tok.Subject(), KeyID: key.ID, OwnerType: key.OwnerType,
		OwnerID: key.OwnerID, OrganizationID: key.OrganizationID, Data: data, IP: c.IP, UserAgent: c.UserAgent})
}

// list answers GET /api-keys.
func (p *Plugin) list(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	ownerType, ownerID, _, err := p.owner(ctx, in, tok)
	if err != nil {
		return p.refuse(ctx, err)
	}
	keys, err := p.keys.ForOwner(ctx, ownerType, ownerID)
	if err != nil {
		return p.refuse(ctx, err)
	}
	now := p.keys.now()
	data := make([]any, len(keys))
	for i, k := range keys {
		data[i] = k.Map(now)
	}
	return endpoint.Data(http.StatusOK, data)
}

// create answers POST /api-keys: the secret is in this response only.
func (p *Plugin) create(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	perms, okP := permissionsOf(in.Value("permissions"), true)
	limit, okL := rateLimitOf(in.Value("rate_limit"))
	meta, errM := metadataOf(in.Value("metadata"))
	expires, okE := timeOf(in.Value("expires_at"))
	if !okP || !okL || errors.Is(errM, errMalformed) || !okE {
		return invalidInput("permissions is a list, rate_limit an object with window and max, metadata an object, expires_at a date.")
	}
	ownerType, ownerID, orgID, err := p.owner(ctx, in, tok)
	if err != nil {
		return p.refuse(ctx, err)
	}
	held, err := p.held(ctx, tok, orgID)
	if err != nil {
		return p.refuse(ctx, err)
	}
	if errM != nil {
		return p.refuse(ctx, errM)
	}
	env, _ := in.Value("environment").(string)
	issued, err := p.keys.Create(ctx, CreateParams{
		OwnerType: ownerType, OwnerID: ownerID, OrganizationID: orgID, CreatedBy: tok.Subject(), Name: scalar(in.Value("name")),
		Permissions: perms, Held: held, Environment: env, RateLimit: limit, ExpiresAt: expires, Metadata: meta,
	})
	if err != nil {
		return p.refuse(ctx, err)
	}
	key := issued.Key
	p.dispatch(ctx, AuditCreated, tok, key, map[string]any{"name": key.Name, "permissions": list(key.Permissions), "expires_at": atom(key.ExpiresAt)})
	data := key.Map(p.keys.now())
	data["key"] = issued.Secret
	return endpoint.Data(http.StatusCreated, data)
}

// read answers GET /api-keys/{id}.
func (p *Plugin) read(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	key, err := p.manageable(ctx, in, tok)
	if err != nil {
		return p.refuse(ctx, err)
	}
	return endpoint.Data(http.StatusOK, key.Map(p.keys.now()))
}

// update answers PATCH /api-keys/{id}: a field left out keeps its value; rate_limit and
// expires_at null clear them.
func (p *Plugin) update(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	var params UpdateParams
	ok := true
	if v := in.Value("name"); v != nil {
		name, isString := v.(string)
		params.Name, ok = &name, isString
	}
	if v := in.Value("permissions"); v != nil && ok {
		params.Permissions, ok = permissionsOf(v, false)
	}
	if in.Has("rate_limit") && ok {
		params.RateLimit, ok = rateLimitOf(in.Value("rate_limit"))
		params.ClearRateLimit = params.RateLimit == nil
	}
	if in.Has("expires_at") && ok {
		params.ExpiresAt, ok = timeOf(in.Value("expires_at"))
		params.ClearExpiry = params.ExpiresAt == nil
	}
	var errM error
	if v := in.Value("metadata"); v != nil && ok {
		params.Metadata, errM = metadataOf(v)
		ok = !errors.Is(errM, errMalformed)
	}
	if !ok {
		return invalidInput("name is a string, permissions a list, rate_limit an object with window and max or null, metadata an object, expires_at a date or null.")
	}
	key, err := p.manageable(ctx, in, tok)
	if err == nil {
		err = errM
	}
	if err != nil {
		return p.refuse(ctx, err)
	}
	if params.Permissions != nil {
		if params.Held, err = p.held(ctx, tok, key.OrganizationID); err != nil {
			return p.refuse(ctx, err)
		}
	}
	key, changes, err := p.keys.Update(ctx, key, params)
	if err != nil {
		return p.refuse(ctx, err)
	}
	if len(changes) > 0 {
		p.dispatch(ctx, AuditUpdated, tok, key, map[string]any{"changes": changes})
	}
	return endpoint.Data(http.StatusOK, key.Map(p.keys.now()))
}

// delete answers DELETE /api-keys/{id}: the key stops at once.
func (p *Plugin) delete(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	key, err := p.manageable(ctx, in, tok)
	if err == nil {
		key, err = p.keys.Revoke(ctx, key)
	}
	if err != nil {
		return p.refuse(ctx, err)
	}
	p.dispatch(ctx, AuditRevoked, tok, key, map[string]any{"name": key.Name})
	return endpoint.Data(http.StatusOK, map[string]any{"status": StatusRevoked})
}

// rotate answers POST /api-keys/{id}/rotate: a successor with a new secret; the key named answers
// until the grace window ends.
func (p *Plugin) rotate(ctx context.Context, in *endpoint.Input, tok *token.Token) endpoint.Result {
	key, err := p.manageable(ctx, in, tok)
	if err != nil {
		return p.refuse(ctx, err)
	}
	if key.CreatedBy != tok.Subject() {
		// The successor acts as the creator: another admin rotates it only within what they hold.
		held, err := p.held(ctx, tok, key.OrganizationID)
		if err != nil {
			return p.refuse(ctx, err)
		}
		for _, perm := range key.Permissions {
			if !slices.Contains(held, perm) {
				return p.refuse(ctx, &Error{Kind: KindPermissionNotHeld, Detail: fmt.Sprintf("The key holds %q, which you do not; its creator rotates it.", perm)})
			}
		}
	}
	key, issued, err := p.keys.Rotate(ctx, key)
	if err != nil {
		return p.refuse(ctx, err)
	}
	p.dispatch(ctx, AuditRotated, tok, key, map[string]any{"successor": issued.Key.ID, "grace_until": atom(key.GraceUntil)})
	data := issued.Key.Map(p.keys.now())
	data["key"] = issued.Secret
	return endpoint.Data(http.StatusCreated, data)
}

// verify answers POST /api-keys/verify: whether a key authenticates now, and as whom.
func (p *Plugin) verify(ctx context.Context, in *endpoint.Input, _ *token.Token) endpoint.Result {
	secret, _ := in.Value("key").(string)
	if secret == "" {
		return endpoint.Problem(http.StatusUnprocessableEntity, "api-keys/invalid_input", "Invalid input", "key is required.", map[string]any{"errors": []string{"key is required"}})
	}
	key, ok, err := p.keys.Authenticate(ctx, secret)
	if err != nil {
		return p.refuse(ctx, err)
	}
	if !ok {
		return endpoint.Data(http.StatusOK, map[string]any{"valid": false})
	}
	return endpoint.Data(http.StatusOK, map[string]any{
		"valid": true, "id": key.ID, "name": key.Name, "owner_type": key.OwnerType, "owner_id": key.OwnerID,
		"organization_id": null(key.OrganizationID), "subject": key.Subject(), "permissions": list(key.Permissions),
		"rate_limit": rateLimitValue(key.RateLimit), "metadata": metadata(key.Metadata),
		"status": key.Status(p.keys.now()), "expires_at": atom(key.ExpiresAt),
	})
}

// scalar reads a value as PHP's (string) cast of a scalar.
func scalar(v any) string {
	switch v := v.(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case bool:
		if v {
			return "1"
		}
	}
	return ""
}

// permissionsOf reads a permission list: absent is empty when allowNil (create); a non-string item
// becomes "?", which the key service refuses as an unknown permission, as upstream.
func permissionsOf(v any, allowNil bool) ([]string, bool) {
	switch v := v.(type) {
	case nil:
		return []string{}, allowNil
	case map[string]any:
		if len(v) == 0 {
			return []string{}, true
		}
		return []string{"?"}, true
	case []any:
		out := make([]string, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				s = "?"
			}
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// rateLimitOf reads {window, max}: nil clears; an object with missing or non-integer members
// becomes a zero limit, which the key service refuses with its message.
func rateLimitOf(v any) (*RateLimit, bool) {
	switch v := v.(type) {
	case nil:
		return nil, true
	case map[string]any:
		return &RateLimit{Window: integer(v["window"]), Max: integer(v["max"])}, true
	case []any:
		return &RateLimit{}, true
	}
	return nil, false
}

func integer(v any) int {
	n, ok := v.(json.Number)
	if !ok {
		return 0
	}
	i, err := n.Int64()
	if err != nil {
		return 0
	}
	return int(i)
}

// errMalformed marks an input of the wrong JSON type.
var errMalformed = errors.New("apikeys: malformed input")

// metadataOf reads an object; an empty list is an empty object, a non-empty one is refused.
func metadataOf(v any) (map[string]any, error) {
	switch v := v.(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		return v, nil
	case []any:
		if len(v) == 0 {
			return map[string]any{}, nil
		}
		return nil, invalid("metadata must be an object.")
	}
	return nil, errMalformed
}

var timeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02"}

// timeOf reads an ISO-8601 datetime; nil for none, ok false when not a date.
func timeOf(v any) (*time.Time, bool) {
	if v == nil || v == "" {
		return nil, true
	}
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return &t, true
		}
	}
	return nil, false
}
