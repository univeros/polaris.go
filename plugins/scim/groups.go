package scim

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// builtInRoles are the roles every organization starts with: listed and given members, never
// renamed or deleted through SCIM.
var builtInRoles = []string{"owner", "admin", "member"}

var (
	nonSlug      = regexp.MustCompile(`[^a-zA-Z0-9]+`)
	memberFilter = regexp.MustCompile(`(?i)members\[value[\t\n\v\f\r ]+eq[\t\n\v\f\r ]+"([^"]+)"\]`)
)

// listGroups pages the organization's roles matching f, by id.
func (d *directory) listGroups(ctx context.Context, conn Connection, f filter, startIndex, count int, location string) (page, error) {
	roles, err := d.repos.Roles.Find(ctx, store.Criteria{"organization_id": conn.OrganizationID}, store.Query{OrderBy: []store.Order{{Column: "id"}}})
	if err != nil {
		return page{}, err
	}
	var matches []map[string]any
	for _, role := range roles {
		res, err := d.groupResource(ctx, conn, role, location)
		if err != nil {
			return page{}, err
		}
		ext, _ := res["externalId"].(string)
		if f.matches(map[string][]string{"id": {role.ID}, "displayname": {role.Name}, "externalid": {ext}}) {
			matches = append(matches, res)
		}
	}
	return paginate(matches, startIndex, count), nil
}

// findGroup is the organization's role id names.
func (d *directory) findGroup(ctx context.Context, conn Connection, id string) (model.Role, error) {
	role, err := d.repos.Roles.FindOne(ctx, store.Criteria{"id": id, "organization_id": conn.OrganizationID})
	if errors.Is(err, repository.ErrNotFound) {
		return role, notFound("Group")
	}
	return role, err
}

// createGroup creates a custom role (no permissions until an organization admin grants some) with
// its members, atomically.
func (d *directory) createGroup(ctx context.Context, conn Connection, body map[string]any) (model.Role, error) {
	name, err := groupName(body["displayName"])
	if err != nil {
		return model.Role{}, err
	}
	members, err := membersOf(body)
	if err != nil {
		return model.Role{}, err
	}
	taken := conflict("A group with this displayName exists.")
	orgID := conn.OrganizationID
	now := d.now()
	description := "Provisioned by SCIM"
	role := model.Role{ID: repository.NewID(), OrganizationID: &orgID, Name: name, Slug: slug(name), Description: &description,
		CreatedAt: now, UpdatedAt: now}
	err = d.db.Tx(ctx, func(ctx context.Context) error {
		if _, err := d.repos.Roles.ByOrganizationAndSlug(ctx, &orgID, role.Slug); err == nil {
			return taken
		} else if !errors.Is(err, repository.ErrNotFound) {
			return err
		}
		if err := d.repos.Roles.Insert(ctx, role); err != nil {
			return err
		}
		if err := d.resources.setExternalID(ctx, conn, KindGroup, role.ID, externalIDOf(body)); err != nil {
			return err
		}
		return d.setMembers(ctx, conn, role.ID, members)
	})
	if errors.Is(err, store.ErrDuplicate) {
		err = taken
	}
	return role, err
}

// replaceGroup is PUT: the name (custom roles only) and the whole member list.
func (d *directory) replaceGroup(ctx context.Context, conn Connection, role model.Role, body map[string]any) (model.Role, error) {
	name, err := groupName(body["displayName"])
	if err != nil {
		return role, err
	}
	members, err := membersOf(body)
	if err != nil {
		return role, err
	}
	err = d.keepOwner(ctx, conn, func(ctx context.Context) error {
		if err := d.rename(ctx, role, name); err != nil {
			return err
		}
		if err := d.resources.setExternalID(ctx, conn, KindGroup, role.ID, externalIDOf(body)); err != nil {
			return err
		}
		return d.setMembers(ctx, conn, role.ID, members)
	})
	if err != nil {
		return role, err
	}
	return d.findGroup(ctx, conn, role.ID)
}

// patchGroup applies PatchOp operations on displayName, externalId and members (add, replace,
// remove with a value list or members[value eq "id"]), atomically, never leaving the organization
// without an active owner.
func (d *directory) patchGroup(ctx context.Context, conn Connection, role model.Role, ops []operation) (model.Role, error) {
	err := d.keepOwner(ctx, conn, func(ctx context.Context) error {
		for _, op := range ops {
			if err := d.applyGroupOp(ctx, conn, &role, op); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return role, err
	}
	return d.findGroup(ctx, conn, role.ID)
}

func (d *directory) applyGroupOp(ctx context.Context, conn Connection, role *model.Role, op operation) error {
	if v, ok := op.scalar("displayName").(string); ok {
		name, err := groupName(v)
		if err != nil {
			return err
		}
		if err := d.rename(ctx, *role, name); err != nil {
			return err
		}
		role.Name = name
	}
	if v, ok := op.scalar("externalId").(string); ok {
		if err := d.resources.setExternalID(ctx, conn, KindGroup, role.ID, trimBlank(v)); err != nil {
			return err
		}
	}
	path := strings.ToLower(stripURN(op.path))
	value, _ := op.value.(map[string]any)
	switch {
	case path == "members" || (op.path == "" && value["members"] != nil):
		raw := op.value
		if op.path == "" {
			raw = value["members"]
		}
		ids, err := memberIDs(raw)
		if err != nil {
			return err
		}
		switch op.op {
		case "add":
			return d.addMembers(ctx, conn, role.ID, ids)
		case "replace":
			return d.setMembers(ctx, conn, role.ID, ids)
		}
		return d.removeMembers(ctx, conn, role.ID, ids)
	case op.path != "" && strings.HasPrefix(path, "members["):
		m := memberFilter.FindStringSubmatch(op.path)
		if op.op != "remove" || m == nil {
			return invalid(`Only members[value eq "id"] is supported on remove.`, TypeInvalidPath)
		}
		return d.removeMembers(ctx, conn, role.ID, []string{m[1]})
	}
	return nil
}

// deleteGroup deletes a custom role with its links.
func (d *directory) deleteGroup(ctx context.Context, conn Connection, role model.Role) error {
	if slices.Contains(builtInRoles, role.Slug) {
		return immutable("A built-in role cannot be deleted.")
	}
	return d.db.Tx(ctx, func(ctx context.Context) error {
		for _, table := range []string{"auth_membership_roles", "auth_role_permissions"} {
			if _, err := d.db.Delete(ctx, table, store.Criteria{"role_id": role.ID}); err != nil {
				return err
			}
		}
		if err := d.repos.Roles.Delete(ctx, role); err != nil {
			return err
		}
		return d.resources.forget(ctx, conn, KindGroup, role.ID)
	})
}

// groupResource is the SCIM Group of a role.
func (d *directory) groupResource(ctx context.Context, conn Connection, role model.Role, location string) (map[string]any, error) {
	links, err := d.repos.MembershipRoles.ListByRole(ctx, role.ID)
	if err != nil {
		return nil, err
	}
	members := []map[string]any{}
	for _, link := range links {
		m, err := d.repos.Memberships.FindOne(ctx, store.Criteria{"id": link.MembershipID, "organization_id": conn.OrganizationID})
		if errors.Is(err, repository.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		user, err := d.repos.Users.Get(ctx, m.UserID)
		if errors.Is(err, repository.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		members = append(members, map[string]any{"value": user.ID, "display": user.Email, "$ref": location + "/Users/" + user.ID})
	}
	slices.SortFunc(members, func(a, b map[string]any) int { return strings.Compare(a["value"].(string), b["value"].(string)) })
	res := map[string]any{
		"schemas":     []string{GroupSchema},
		"id":          role.ID,
		"displayName": role.Name,
		"members":     members,
		"meta": map[string]any{"resourceType": KindGroup, "created": timestamp(role.CreatedAt), "lastModified": timestamp(role.UpdatedAt),
			"location": location + "/Groups/" + role.ID},
	}
	ext, err := d.resources.externalID(ctx, conn, KindGroup, role.ID)
	if ext != "" {
		res["externalId"] = ext
	}
	return res, err
}

func (d *directory) rename(ctx context.Context, role model.Role, name string) error {
	if name == role.Name {
		return nil
	}
	if slices.Contains(builtInRoles, role.Slug) {
		return immutable("A built-in role cannot be renamed.")
	}
	next := role
	next.Name, next.UpdatedAt = name, d.now()
	return d.repos.Roles.Update(ctx, role, next)
}

func (d *directory) setMembers(ctx context.Context, conn Connection, roleID string, userIDs []string) error {
	if _, err := d.db.Delete(ctx, "auth_membership_roles", store.Criteria{"role_id": roleID}); err != nil {
		return err
	}
	return d.addMembers(ctx, conn, roleID, userIDs)
}

func (d *directory) addMembers(ctx context.Context, conn Connection, roleID string, userIDs []string) error {
	for _, userID := range userIDs {
		m, found, err := d.membership(ctx, conn, userID)
		if err != nil {
			return err
		}
		if !found {
			return invalid("Member "+userID+" is not in the organization.", TypeInvalidValue)
		}
		_, err = d.repos.MembershipRoles.Get(ctx, m.ID, roleID)
		if err == nil {
			continue
		}
		if !errors.Is(err, repository.ErrNotFound) {
			return err
		}
		if err := d.repos.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: m.ID, RoleID: roleID}); err != nil {
			return err
		}
	}
	return nil
}

func (d *directory) removeMembers(ctx context.Context, conn Connection, roleID string, userIDs []string) error {
	for _, userID := range userIDs {
		m, found, err := d.membership(ctx, conn, userID)
		if err != nil {
			return err
		}
		if found {
			if _, err := d.db.Delete(ctx, "auth_membership_roles", store.Criteria{"membership_id": m.ID, "role_id": roleID}); err != nil {
				return err
			}
		}
	}
	return nil
}

// membersOf is the members of a POST or PUT body; absent or null is none.
func membersOf(body map[string]any) ([]string, error) {
	if body["members"] == nil {
		return nil, nil
	}
	return memberIDs(body["members"])
}

// memberIDs reads a members list (RFC 7643 §4.2): a JSON list of {"value": id} objects.
func memberIDs(raw any) ([]string, error) {
	bad := invalid(`members must be a list of {"value": id}.`, TypeInvalidValue)
	list, ok := raw.([]any)
	if !ok {
		return nil, bad
	}
	ids := make([]string, 0, len(list))
	for _, item := range list {
		m, _ := item.(map[string]any)
		id, _ := m["value"].(string)
		if id == "" {
			return nil, bad
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func groupName(raw any) (string, error) {
	name, _ := raw.(string)
	name = trimBlank(name)
	if name == "" || utf8.RuneCountInString(name) > 120 {
		return "", invalid("displayName must be 1 to 120 characters.", TypeInvalidValue)
	}
	return name, nil
}

// slug is a group's role slug: runs of anything but ASCII letters and digits become "-", trimmed,
// lower-cased, at most 64 bytes; "group" when nothing is left.
func slug(name string) string {
	s := strings.ToLower(strings.Trim(nonSlug.ReplaceAllString(name, "-"), "-"))
	if s == "" {
		return "group"
	}
	return s[:min(len(s), 64)]
}
