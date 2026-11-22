package scim

import (
	"context"
	"errors"
	"github.com/univeros/polaris.go/wiring"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/manifest"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// Schema URNs of the resources.
const (
	UserSchema  = "urn:ietf:params:scim:schemas:core:2.0:User"
	GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
)

// defaultRole is the role slug a provisioned member gets; actor names the directory in core's
// user administration events.
const (
	defaultRole = "member"
	actor       = "scim"
)

// directory projects SCIM Users onto the members of a connection's organization and SCIM Groups
// onto its roles. Ids are Polaris's, so a person keeps one id across connections.
type directory struct {
	db        store.Adapter
	repos     *repository.Repos
	identity  wiring.Identity
	orgs      wiring.Orgs
	domains   func() any // the sso plugin, when registered: a VerifiedDomains
	resources *resources
	events    event.Dispatcher
	clock     clock.Clock
}

func (d *directory) now() time.Time { return d.clock.Now().UTC().Truncate(time.Second) }

// page is one page of a list: the total matched and the resources from startIndex (1-based).
type page struct {
	total     int
	resources []map[string]any
}

func paginate(matches []map[string]any, startIndex, count int) page {
	from := min(startIndex-1, len(matches))
	to := min(from+count, len(matches))
	return page{total: len(matches), resources: matches[from:to]}
}

// listUsers pages the organization's members matching f, by id.
func (d *directory) listUsers(ctx context.Context, conn Connection, f filter, startIndex, count int, location string) (page, error) {
	// ponytail: every member is loaded and filtered in memory; a store-side filter comes with the
	// first organization above a few thousand members.
	memberships, err := d.repos.Memberships.ListByOrganization(ctx, conn.OrganizationID)
	if err != nil {
		return page{}, err
	}
	var matches []map[string]any
	for _, m := range memberships {
		user, err := d.repos.Users.Get(ctx, m.UserID)
		if errors.Is(err, repository.ErrNotFound) {
			continue
		}
		if err != nil {
			return page{}, err
		}
		res, err := d.userResource(ctx, conn, user, location)
		if err != nil {
			return page{}, err
		}
		if f.matches(flatUser(res)) {
			matches = append(matches, res)
		}
	}
	slices.SortFunc(matches, func(a, b map[string]any) int { return strings.Compare(a["id"].(string), b["id"].(string)) })
	return paginate(matches, startIndex, count), nil
}

// findUser is the user id names when they are a member of the connection's organization.
func (d *directory) findUser(ctx context.Context, conn Connection, id string) (model.User, error) {
	user, err := d.repos.Users.Get(ctx, id)
	if errors.Is(err, repository.ErrNotFound) {
		return model.User{}, notFound("User")
	}
	if err != nil {
		return model.User{}, err
	}
	_, found, err := d.membership(ctx, conn, id)
	if err == nil && !found {
		err = notFound("User")
	}
	return user, err
}

// createUser provisions a member: a new user (verified, no password) owned by the connection, or
// the account the email already has when its domain is one the organization verified, joined to
// the organization with the member role (its profile left as it is). Any other existing account
// is a uniqueness conflict: a directory never takes over another organization's user.
func (d *directory) createUser(ctx context.Context, conn Connection, body map[string]any) (model.User, error) {
	email, err := emailOf(body)
	if err != nil {
		return model.User{}, err
	}
	active, err := activeOf(body)
	if err != nil {
		return model.User{}, err
	}
	taken := conflict("A member with this userName exists.")
	user, err := d.repos.Users.ByEmail(ctx, email)
	exists := err == nil
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		return model.User{}, err
	}
	if exists {
		_, member, err := d.membership(ctx, conn, user.ID)
		if err == nil && member {
			err = taken
		}
		if err != nil {
			return model.User{}, err
		}
		linkable, err := d.mayLink(ctx, conn, email)
		if err != nil {
			return model.User{}, err
		}
		if !linkable {
			return model.User{}, conflict("Another account uses this userName.")
		}
	}
	now := d.now()
	joined := false
	err = d.db.Tx(ctx, func(ctx context.Context) error {
		if !exists {
			next := model.User{ID: repository.NewID(), Email: email, DisplayName: displayNameOf(body), EmailVerifiedAt: &now,
				Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
			if err := d.identity.InsertUser(ctx, next); err != nil {
				return err
			}
			user = next
			if err := d.resources.setNameParts(ctx, conn, user.ID, namePartsOf(body)); err != nil {
				return err
			}
		}
		var err error
		if joined, err = d.join(ctx, conn, user.ID, now); err != nil {
			return err
		}
		return d.resources.setExternalID(ctx, conn, KindUser, user.ID, externalIDOf(body))
	})
	if errors.Is(err, store.ErrDuplicate) {
		return model.User{}, taken // a concurrent provisioning of the same person won
	}
	if err != nil {
		return model.User{}, err
	}
	if joined {
		d.events.Dispatch(ctx, event.MemberJoined{OrganizationID: conn.OrganizationID, UserID: user.ID, Email: user.Email})
	}
	if !active {
		if err := d.setMembershipActive(ctx, conn, user, false); err != nil {
			return model.User{}, err
		}
	}
	return d.repos.Users.Get(ctx, user.ID)
}

// replaceUser is PUT: the mapped attributes are replaced, the rest ignored.
func (d *directory) replaceUser(ctx context.Context, conn Connection, user model.User, body map[string]any) (model.User, error) {
	email, err := emailOf(body)
	if err != nil {
		return model.User{}, err
	}
	active, err := activeOf(body)
	if err != nil {
		return model.User{}, err
	}
	ext := externalIDOf(body)
	parts := namePartsOf(body)
	return d.writeUser(ctx, conn, user, userChange{email: &email, displayName: displayNameOf(body), setName: true, parts: &parts,
		externalID: &ext, active: active, setActive: true})
}

// patchUser applies PatchOp operations on active, userName, displayName, name.* and externalId;
// the last operation touching an attribute wins, and nothing is written when one is refused.
func (d *directory) patchUser(ctx context.Context, conn Connection, user model.User, ops []operation) (model.User, error) {
	var c userChange
	for _, op := range ops {
		if v := op.scalar("active"); v != nil {
			active, ok := v.(bool)
			if !ok {
				return model.User{}, errActive
			}
			c.active, c.setActive = active, true
		}
		if v, ok := op.scalar("userName").(string); ok {
			email, err := validEmail(v)
			if err != nil {
				return model.User{}, err
			}
			c.email = &email
		}
		for _, attribute := range []string{"displayName", "name.formatted"} {
			if v := op.scalar(attribute); v != nil {
				s, _ := v.(string)
				c.displayName, c.setName = nonBlank(s), true
			}
		}
		given, okG := op.scalar("name.givenName").(string)
		family, okF := op.scalar("name.familyName").(string)
		if okG || okF {
			if c.parts == nil { // a part not in the request keeps what the directory sent before
				stored, err := d.resources.nameParts(ctx, conn, user.ID)
				if err != nil {
					return model.User{}, err
				}
				c.parts = &stored
			}
			if okG {
				c.parts.given = namePart(given)
			}
			if okF {
				c.parts.family = namePart(family)
			}
			name := trimBlank(c.parts.given + " " + c.parts.family)
			c.displayName, c.setName = &name, true
		}
		v := op.scalar("externalId")
		if v != nil || (op.op == "remove" && op.path != "" && stripURN(op.path) == "externalId") {
			s, _ := v.(string)
			c.externalID = &s
		}
	}
	return d.writeUser(ctx, conn, user, c)
}

// userChange is what a PUT or a PATCH changes; nil and false leave a field as it is.
type userChange struct {
	email       *string
	displayName *string
	setName     bool
	parts       *nameParts // name.givenName and name.familyName
	externalID  *string    // "" forgets it
	active      bool
	setActive   bool
}

func (d *directory) writeUser(ctx context.Context, conn Connection, user model.User, c userChange) (model.User, error) {
	owned, err := d.owns(ctx, conn, user)
	if err != nil {
		return model.User{}, err
	}
	if !owned {
		// Not this directory's account: its email and name are the user's own.
		if c.email != nil && *c.email != user.Email {
			return model.User{}, immutable("userName is managed by the account's owner, not by this directory.")
		}
		c.email, c.setName, c.parts = nil, false, nil
	}
	err = d.db.Tx(ctx, func(ctx context.Context) error {
		next := user
		if c.email != nil && *c.email != user.Email {
			other, err := d.repos.Users.ByEmail(ctx, *c.email)
			if err == nil && other.ID != user.ID {
				return conflict("Another account uses this userName.")
			}
			if err != nil && !errors.Is(err, repository.ErrNotFound) {
				return err
			}
			next.Email = *c.email
		}
		if c.setName {
			next.DisplayName = c.displayName
		}
		next.UpdatedAt = d.now()
		if err := d.repos.Users.Update(ctx, user, next); err != nil {
			return err
		}
		if c.parts != nil {
			if err := d.resources.setNameParts(ctx, conn, user.ID, *c.parts); err != nil {
				return err
			}
		}
		if c.externalID == nil {
			return nil
		}
		return d.resources.setExternalID(ctx, conn, KindUser, user.ID, *c.externalID)
	})
	if errors.Is(err, store.ErrDuplicate) {
		err = conflict("Another account uses this userName.")
	}
	if err != nil {
		return model.User{}, err
	}
	if c.setActive {
		if err := d.setMembershipActive(ctx, conn, user, c.active); err != nil {
			return model.User{}, err
		}
	}
	return d.repos.Users.Get(ctx, user.ID)
}

// deleteUser deprovisions as the connection says. An account the connection owns is anonymised
// (DeprovisionDelete) or disabled (DeprovisionDeactivate, its membership removed); any other
// account only leaves the organization: its membership is suspended (ending the organization's
// sessions, never its last active owner) and then removed. It returns "deleted" or "deactivated".
func (d *directory) deleteUser(ctx context.Context, conn Connection, user model.User) (string, error) {
	owned, err := d.owns(ctx, conn, user)
	if err != nil {
		return "", err
	}
	outcome := "deactivated"
	if conn.Deprovision == DeprovisionDelete {
		outcome = "deleted"
	}
	if !owned {
		if err := d.setMembershipActive(ctx, conn, user, false); err != nil {
			return "", err
		}
		return outcome, d.leave(ctx, conn, user.ID)
	}
	if conn.Deprovision == DeprovisionDelete {
		if err := d.identity.AnonymizeUser(ctx, actor, user.ID); err != nil {
			return "", err
		}
		return outcome, d.db.Tx(ctx, func(ctx context.Context) error {
			return errors.Join(d.resources.forget(ctx, conn, KindUser, user.ID), d.resources.forgetMembership(ctx, conn, user.ID))
		})
	}
	if err := d.leave(ctx, conn, user.ID); err != nil {
		return "", err
	}
	return outcome, d.identity.DisableUser(ctx, actor, user.ID)
}

// leave removes userID's membership (and role links) and what the connection remembers of them,
// keeping the organization's last active owner.
func (d *directory) leave(ctx context.Context, conn Connection, userID string) error {
	return d.keepOwner(ctx, conn, func(ctx context.Context) error {
		m, found, err := d.membership(ctx, conn, userID)
		if err != nil {
			return err
		}
		if found {
			if _, err := d.db.Delete(ctx, "auth_membership_roles", store.Criteria{"membership_id": m.ID}); err != nil {
				return err
			}
			if err := d.repos.Memberships.Delete(ctx, m); err != nil {
				return err
			}
		}
		return errors.Join(d.resources.forgetMembership(ctx, conn, userID), d.resources.forget(ctx, conn, KindUser, userID))
	})
}

// userResource is the SCIM User of a member.
func (d *directory) userResource(ctx context.Context, conn Connection, user model.User, location string) (map[string]any, error) {
	groups := []map[string]any{}
	m, found, err := d.membership(ctx, conn, user.ID)
	if err != nil {
		return nil, err
	}
	if found {
		links, err := d.repos.MembershipRoles.ListByMembership(ctx, m.ID)
		if err != nil {
			return nil, err
		}
		for _, link := range links {
			role, err := d.repos.Roles.Get(ctx, link.RoleID)
			if errors.Is(err, repository.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			groups = append(groups, map[string]any{"value": role.ID, "display": role.Name, "$ref": location + "/Groups/" + role.ID})
		}
	}
	slices.SortFunc(groups, func(a, b map[string]any) int { return strings.Compare(a["value"].(string), b["value"].(string)) })
	var name any
	if user.DisplayName != nil {
		name = *user.DisplayName
	}
	parts, err := d.resources.nameParts(ctx, conn, user.ID)
	if err != nil {
		return nil, err
	}
	nameAttribute := map[string]any{"formatted": name}
	if parts.given != "" {
		nameAttribute["givenName"] = parts.given
	}
	if parts.family != "" {
		nameAttribute["familyName"] = parts.family
	}
	res := map[string]any{
		"schemas":     []string{UserSchema},
		"id":          user.ID,
		"userName":    user.Email,
		"displayName": name,
		"name":        nameAttribute,
		"emails":      []map[string]any{{"value": user.Email, "primary": true}},
		"active":      user.Status != model.UserStatusDisabled && found && m.Status == model.MembershipStatusActive,
		"groups":      groups,
		"meta": map[string]any{"resourceType": KindUser, "created": timestamp(user.CreatedAt), "lastModified": timestamp(user.UpdatedAt),
			"location": location + "/Users/" + user.ID},
	}
	ext, err := d.resources.externalID(ctx, conn, KindUser, user.ID)
	if ext != "" {
		res["externalId"] = ext
	}
	return res, err
}

// flatUser is what a filter compares on a User.
func flatUser(res map[string]any) map[string][]string {
	name, _ := res["displayName"].(string)
	ext, _ := res["externalId"].(string)
	email := res["userName"].(string)
	active := "false"
	if res["active"] == true {
		active = "true"
	}
	return map[string][]string{"id": {res["id"].(string)}, "username": {email}, "emails": {email},
		"displayname": {name}, "externalid": {ext}, "active": {active}}
}

func (d *directory) membership(ctx context.Context, conn Connection, userID string) (model.Membership, bool, error) {
	m, err := d.repos.Memberships.ByUserAndOrganization(ctx, userID, conn.OrganizationID)
	if errors.Is(err, repository.ErrNotFound) {
		return m, false, nil
	}
	return m, err == nil, err
}

// join makes the user an active member with the member role, recording that conn created the
// membership; false when they were a member already.
func (d *directory) join(ctx context.Context, conn Connection, userID string, now time.Time) (bool, error) {
	if _, found, err := d.membership(ctx, conn, userID); err != nil || found {
		return false, err
	}
	m := model.Membership{ID: repository.NewID(), UserID: userID, OrganizationID: conn.OrganizationID,
		Status: model.MembershipStatusActive, JoinedAt: &now, CreatedAt: now, UpdatedAt: now}
	if err := d.repos.Memberships.Insert(ctx, m); err != nil {
		return false, err
	}
	orgID := conn.OrganizationID
	role, err := d.repos.Roles.ByOrganizationAndSlug(ctx, &orgID, defaultRole)
	switch {
	case err == nil:
		if err := d.repos.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: m.ID, RoleID: role.ID}); err != nil {
			return false, err
		}
	case !errors.Is(err, repository.ErrNotFound):
		return false, err
	}
	return true, d.resources.recordMembership(ctx, conn, userID, now)
}

// emailOf is the member's email: userName, else the primary (or last) of emails.
func emailOf(body map[string]any) (string, error) {
	userName, _ := body["userName"].(string)
	if trimBlank(userName) == "" {
		entries, _ := body["emails"].([]any)
		for _, entry := range entries {
			e, _ := entry.(map[string]any)
			if v, ok := e["value"].(string); ok {
				userName = v
				if e["primary"] == true {
					break
				}
			}
		}
	}
	return validEmail(userName)
}

func validEmail(value string) (string, error) {
	email := identity.NormalizeEmail(value)
	if email == "" || len(email) > 320 || !manifest.IsEmail(email) {
		return "", invalid("userName must be the member's email address.", TypeInvalidValue)
	}
	return email, nil
}

// displayNameOf is displayName, else name.formatted, else name.givenName and familyName; nil when
// blank; at most 120 bytes (cut on a character boundary).
func displayNameOf(body map[string]any) *string {
	name, _ := body["displayName"].(string)
	if trimBlank(name) == "" {
		parts, _ := body["name"].(map[string]any)
		formatted, _ := parts["formatted"].(string)
		given, _ := parts["givenName"].(string)
		family, _ := parts["familyName"].(string)
		name = formatted
		if trimBlank(formatted) == "" {
			name = given + " " + family
		}
	}
	return nonBlank(namePart(name))
}

// namePartsOf is name.givenName and name.familyName of a User body.
func namePartsOf(body map[string]any) nameParts {
	parts, _ := body["name"].(map[string]any)
	given, _ := parts["givenName"].(string)
	family, _ := parts["familyName"].(string)
	return nameParts{given: namePart(given), family: namePart(family)}
}

// namePart is s without blank edges, at most 120 bytes (cut on a character boundary).
func namePart(s string) string {
	s = trimBlank(s)
	if len(s) <= 120 {
		return s
	}
	cut := 120
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func externalIDOf(body map[string]any) string {
	v, _ := body["externalId"].(string)
	return trimBlank(v)
}

func nonBlank(s string) *string {
	s = trimBlank(s)
	if s == "" {
		return nil
	}
	return &s
}

var errActive = invalid("active must be a JSON boolean (true or false).", TypeInvalidValue)

// activeOf is a POST or PUT body's active (RFC 7643 §4.1.1): a JSON boolean, true when absent or
// null.
func activeOf(body map[string]any) (bool, error) {
	switch v := body["active"].(type) {
	case nil:
		return true, nil
	case bool:
		return v, nil
	}
	return false, errActive
}

// trimBlank strips surrounding spaces, tabs, newlines, carriage returns, NUL and vertical tabs
// (not the other Unicode spaces strings.TrimSpace strips). It trims what is stored or compared
// with stored values (names, external ids, a connection's name, ids, cursors), so values written
// by earlier releases keep matching.
func trimBlank(s string) string { return strings.Trim(s, " \t\n\r\x00\x0b") }
