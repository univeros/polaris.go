package audit

import (
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
)

// The catalog's core names: the events Polaris itself records.
const (
	UserSignedUp                = "user.signed_up"
	UserEmailVerified           = "user.email_verified"
	UserLocked                  = "user.locked"
	UserDisabled                = "user.disabled"
	UserEnabled                 = "user.enabled"
	UserDeleted                 = "user.deleted"
	SessionSignedIn             = "session.signed_in"
	SessionSignInFailed         = "session.sign_in_failed"
	SessionRotated              = "session.rotated"
	SessionReuseDetected        = "session.reuse_detected"
	SessionRevokedAll           = "session.revoked_all"
	SessionOrganizationSwitched = "session.organization_switched"
	PasswordChanged             = "password.changed"
	PasswordResetRequested      = "password.reset_requested"
	MFAEnabled                  = "mfa.enabled"
	MFADisabled                 = "mfa.disabled"
	MFAChallengePassed          = "mfa.challenge_passed"
	MFAChallengeFailed          = "mfa.challenge_failed"
	MFAStepUpCompleted          = "mfa.step_up_completed"
	MFACodeSent                 = "mfa.code_sent"
	MFABackupCodesRegenerated   = "mfa.backup_codes_regenerated"
	MFABackupCodeUsed           = "mfa.backup_code_used"
	OrgCreated                  = "org.created"
	OrgUpdated                  = "org.updated"
	OrgDeleted                  = "org.deleted"
	OrgRoleCreated              = "org.role_created"
	OrgRoleUpdated              = "org.role_updated"
	OrgRoleDeleted              = "org.role_deleted"
	OrgMemberInvited            = "org.member_invited"
	OrgMemberJoined             = "org.member_joined"
	OrgMemberRolesChanged       = "org.member_roles_changed"
	OrgMemberStatusChanged      = "org.member_status_changed"
	OrgMemberRemoved            = "org.member_removed"
	AuditPruned                 = "audit.pruned"
)

// coreNames is the catalog's core, in the fixed order the catalog lists it.
var coreNames = []Type{
	{UserSignedUp, "A user registered"},
	{UserEmailVerified, "A user verified their email address"},
	{UserLocked, "A user was locked after repeated failed sign-ins"},
	{UserDisabled, "An administrator disabled a user"},
	{UserEnabled, "An administrator enabled a user"},
	{UserDeleted, "An administrator deleted a user"},
	{SessionSignedIn, "A user signed in"},
	{SessionSignInFailed, "A sign-in failed"},
	{SessionRotated, "A session rotated its refresh token"},
	{SessionReuseDetected, "A refresh token was reused; the session family was revoked"},
	{SessionRevokedAll, "Every session of a user was revoked"},
	{SessionOrganizationSwitched, "A session switched its active organization"},
	{PasswordChanged, "A password was changed"},
	{PasswordResetRequested, "A password reset was requested"},
	{MFAEnabled, "An MFA factor was enrolled"},
	{MFADisabled, "An MFA factor was removed"},
	{MFAChallengePassed, "An MFA challenge was passed"},
	{MFAChallengeFailed, "An MFA challenge failed"},
	{MFAStepUpCompleted, "A step-up authentication completed"},
	{MFACodeSent, "A one-time code was sent"},
	{MFABackupCodesRegenerated, "The recovery codes were regenerated"},
	{MFABackupCodeUsed, "A recovery code was used"},
	{OrgCreated, "An organization was created"},
	{OrgUpdated, "An organization was updated"},
	{OrgDeleted, "An organization was deleted"},
	{OrgRoleCreated, "A role was created"},
	{OrgRoleUpdated, "A role was updated"},
	{OrgRoleDeleted, "A role was deleted"},
	{OrgMemberInvited, "A member was invited"},
	{OrgMemberJoined, "A member joined"},
	{OrgMemberRolesChanged, "A member's roles changed"},
	{OrgMemberStatusChanged, "A member's status changed"},
	{OrgMemberRemoved, "A member was removed"},
	{AuditPruned, "The retention policy pruned events (a hash-chain checkpoint)"},
}

// ErrUnknownName is returned when an event's name is not in the catalog.
var ErrUnknownName = errors.New("audit: name not in the catalog")

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Type is one catalog entry.
type Type struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// NameProvider is implemented by a plugin that emits audit events of its own (api-keys): the
// audit plugin adds its names to the catalog at startup, whatever the registration order.
type NameProvider interface {
	AuditNames() map[string]string
}

// Catalog is the closed list of event names the store accepts: core's, then each extension in
// order (names of one extension sorted). It is immutable.
type Catalog struct {
	types []Type
	index map[string]bool
}

// NewCatalog returns core's catalog extended with each map of name => description. A name must
// read namespace.past_tense and must not redefine a core name.
func NewCatalog(extensions ...map[string]string) (*Catalog, error) {
	c := &Catalog{types: slices.Clone(coreNames), index: map[string]bool{}}
	core := map[string]bool{}
	for _, t := range coreNames {
		c.index[t.Name], core[t.Name] = true, true
	}
	var errs []error
	for _, ext := range extensions {
		for _, name := range slices.Sorted(maps.Keys(ext)) {
			switch {
			case !namePattern.MatchString(name):
				errs = append(errs, fmt.Errorf("audit: %q is not a valid audit event name (namespace.past_tense)", name))
			case core[name]:
				errs = append(errs, fmt.Errorf("audit: %q is a core audit event and cannot be redefined", name))
			case !c.index[name]:
				c.index[name] = true
				c.types = append(c.types, Type{name, ext[name]})
			}
		}
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return c, nil
}

// Has reports whether name is in the catalog.
func (c *Catalog) Has(name string) bool { return c.index[name] }

// Check returns an error wrapping ErrUnknownName when name is not in the catalog.
func (c *Catalog) Check(name string) error {
	if !c.Has(name) {
		return fmt.Errorf("%w: %q; register it with Config.Names or a NameProvider plugin", ErrUnknownName, name)
	}
	return nil
}

// Types returns every entry, core first.
func (c *Catalog) Types() []Type { return slices.Clone(c.types) }

// Names returns every name, core first.
func (c *Catalog) Names() []string {
	out := make([]string, len(c.types))
	for i, t := range c.types {
		out[i] = t.Name
	}
	return out
}
