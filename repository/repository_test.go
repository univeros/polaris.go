package repository

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/sqlstore"
)

var now = time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC)

func ptr[T any](v T) *T { return &v }

// backends runs fn on memstore and on a fresh SQLite database (foreign keys on), both holding core's
// schema.
func backends(t *testing.T, fn func(t *testing.T, r *Repos)) {
	t.Helper()
	t.Run("memory", func(t *testing.T) { fn(t, New(memstore.New(schema.Core()...))) })
	t.Run("sqlite", func(t *testing.T) { fn(t, New(openSQLite(t))) })
}

func openSQLite(t *testing.T) *sqlstore.Store {
	t.Helper()
	ctx := context.Background()
	s, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "p.db")+"?_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.DB().Close() })
	if err := s.CreateSchema(ctx, schema.Core()); err != nil {
		t.Fatal(err)
	}
	return s
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Every field set, so a round trip exercises every column.
func fullUser() model.User {
	return model.User{
		ID: NewID(), Email: "ada@example.com", EmailVerifiedAt: ptr(now), PasswordHash: ptr("$argon2id$x"),
		DisplayName: ptr("Ada"), Status: model.UserStatusLocked, MFAEnforced: true, FailedLoginCount: 3,
		FailedLoginAt: ptr(now.Add(time.Minute)), LockedUntil: ptr(now.Add(time.Hour)), LastLoginAt: ptr(now),
		CreatedAt: now, UpdatedAt: now.Add(time.Second),
	}
}

func fullRefreshToken(userID string) model.RefreshToken {
	return model.RefreshToken{
		ID: NewID(), UserID: userID, OrganizationID: ptr(NewID()), FamilyID: NewID(), ParentID: ptr(NewID()),
		TokenHash: NewID(), UserAgent: ptr("curl/8"), IP: ptr("203.0.113.7"), MFA: true, AMR: ptr("pwd otp"),
		AuthTime: ptr(now.Unix()), ExpiresAt: now.AddDate(0, 0, 30), LastUsedAt: ptr(now), RevokedAt: ptr(now),
		RevokedReason: ptr(model.RevokedLogout), CreatedAt: now,
	}
}

func fullFactor(userID string) model.MFAFactor {
	return model.MFAFactor{
		ID: NewID(), UserID: userID, Type: model.FactorSMS, Label: ptr("phone"), SecretEncrypted: ptr("enc"),
		PhoneE164: ptr("+15551234567"), Email: ptr("a@example.com"), IsDefault: true, ConfirmedAt: ptr(now),
		LastUsedAt: ptr(now), CreatedAt: now, UpdatedAt: now,
	}
}

func fullChallenge(userID string) model.OTPChallenge {
	return model.OTPChallenge{
		ID: NewID(), UserID: userID, FactorID: ptr(NewID()), Purpose: "login_mfa", Channel: model.ChannelSMS,
		CodeHash: ptr(NewID()), Destination: ptr("+15551234567"), Attempts: 1, MaxAttempts: 3,
		ExpiresAt: now.Add(5 * time.Minute), ConsumedAt: ptr(now), IP: ptr("::1"), CreatedAt: now,
	}
}

func fullRole(orgID *string) model.Role {
	return model.Role{
		ID: NewID(), OrganizationID: orgID, Name: "Owner", Slug: "owner", Description: ptr("Full control"),
		IsSystem: true, CreatedAt: now, UpdatedAt: now,
	}
}

func fullMembership(userID, orgID string) model.Membership {
	return model.Membership{
		ID: NewID(), UserID: userID, OrganizationID: orgID, Status: model.MembershipStatusActive,
		InvitedBy: ptr(NewID()), JoinedAt: ptr(now), CreatedAt: now, UpdatedAt: now,
	}
}

func fullInvitation(orgID string) model.Invitation {
	return model.Invitation{
		ID: NewID(), OrganizationID: orgID, Email: "invitee@example.com", RoleIDs: []string{NewID(), NewID()},
		TokenHash: NewID(), InvitedBy: NewID(), ExpiresAt: now.AddDate(0, 0, 7), AcceptedAt: ptr(now), CreatedAt: now,
	}
}

// roundTrip inserts m and reads it back by key, which must give m again.
func roundTrip[T any](t *testing.T, tbl Table[T], m T, get func() (T, error)) {
	t.Helper()
	must(t, tbl.Insert(context.Background(), m))
	got, err := get()
	must(t, err)
	if !reflect.DeepEqual(got, m) {
		t.Errorf("%s round trip:\n got %+v\nwant %+v", tbl.name, got, m)
	}
}

func TestEveryModelRoundTrips(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		u := fullUser()
		roundTrip(t, r.Users.Table, u, func() (model.User, error) { return r.Users.Get(ctx, u.ID) })
		ev := model.EmailVerification{ID: NewID(), UserID: u.ID, Email: u.Email, TokenHash: NewID(), ExpiresAt: now, ConsumedAt: ptr(now), IP: ptr("::1"), CreatedAt: now}
		roundTrip(t, r.EmailVerifications.Table, ev, func() (model.EmailVerification, error) { return r.EmailVerifications.Get(ctx, ev.ID) })
		pr := model.PasswordReset{ID: NewID(), UserID: u.ID, Email: u.Email, TokenHash: NewID(), ExpiresAt: now, ConsumedAt: ptr(now), IP: ptr("::1"), CreatedAt: now}
		roundTrip(t, r.PasswordResets.Table, pr, func() (model.PasswordReset, error) { return r.PasswordResets.Get(ctx, pr.ID) })
		rt := fullRefreshToken(u.ID)
		roundTrip(t, r.RefreshTokens.Table, rt, func() (model.RefreshToken, error) { return r.RefreshTokens.Get(ctx, rt.ID) })
		entry := model.AuditLogEntry{ID: NewID(), ActorUserID: ptr(u.ID), OrganizationID: ptr(NewID()), Event: "user.login", IP: ptr("::1"), UserAgent: ptr("ua"), Metadata: json.RawMessage(`{"factor_id":"f","channel":"sms"}`), CreatedAt: now}
		roundTrip(t, r.AuditLog.Table, entry, func() (model.AuditLogEntry, error) { return r.AuditLog.Get(ctx, entry.ID) })
		f := fullFactor(u.ID)
		roundTrip(t, r.MFAFactors.Table, f, func() (model.MFAFactor, error) { return r.MFAFactors.Get(ctx, f.ID) })
		c := fullChallenge(u.ID)
		roundTrip(t, r.OTPChallenges.Table, c, func() (model.OTPChallenge, error) { return r.OTPChallenges.Get(ctx, c.ID) })
		rc := model.RecoveryCode{ID: NewID(), UserID: u.ID, CodeHash: NewID(), UsedAt: ptr(now), CreatedAt: now}
		roundTrip(t, r.RecoveryCodes.Table, rc, func() (model.RecoveryCode, error) { return r.RecoveryCodes.Get(ctx, rc.ID) })
		o := model.Organization{ID: NewID(), Name: "Acme", Slug: "acme", Status: model.OrganizationStatusSuspended, CreatedBy: u.ID, CreatedAt: now, UpdatedAt: now}
		roundTrip(t, r.Organizations.Table, o, func() (model.Organization, error) { return r.Organizations.Get(ctx, o.ID) })
		m := fullMembership(u.ID, o.ID)
		roundTrip(t, r.Memberships.Table, m, func() (model.Membership, error) { return r.Memberships.Get(ctx, m.ID) })
		role := fullRole(ptr(o.ID))
		roundTrip(t, r.Roles.Table, role, func() (model.Role, error) { return r.Roles.Get(ctx, role.ID) })
		mr := model.MembershipRole{MembershipID: m.ID, RoleID: role.ID}
		roundTrip(t, r.MembershipRoles.Table, mr, func() (model.MembershipRole, error) { return r.MembershipRoles.Get(ctx, m.ID, role.ID) })
		p := model.Permission{ID: NewID(), Key: "org.manage", Description: "Manage"}
		roundTrip(t, r.Permissions.Table, p, func() (model.Permission, error) { return r.Permissions.Get(ctx, p.ID) })
		rp := model.RolePermission{RoleID: role.ID, PermissionID: p.ID}
		roundTrip(t, r.RolePermissions.Table, rp, func() (model.RolePermission, error) { return r.RolePermissions.Get(ctx, role.ID, p.ID) })
		inv := fullInvitation(o.ID)
		roundTrip(t, r.Invitations.Table, inv, func() (model.Invitation, error) { return r.Invitations.Get(ctx, inv.ID) })
	})
}

// Each repository writes exactly the columns of its schema.Core() table.
func TestRowsCoverTheSchemaColumns(t *testing.T) {
	r := New(memstore.New())
	columns := map[string][]string{
		"auth_users": cols(r.Users.toRow(model.User{})), "auth_email_verifications": cols(r.EmailVerifications.toRow(model.EmailVerification{})),
		"auth_password_resets": cols(r.PasswordResets.toRow(model.PasswordReset{})), "auth_refresh_tokens": cols(r.RefreshTokens.toRow(model.RefreshToken{})),
		"auth_audit_log": cols(r.AuditLog.toRow(model.AuditLogEntry{})), "auth_mfa_factors": cols(r.MFAFactors.toRow(model.MFAFactor{})),
		"auth_otp_challenges": cols(r.OTPChallenges.toRow(model.OTPChallenge{})), "auth_recovery_codes": cols(r.RecoveryCodes.toRow(model.RecoveryCode{})),
		"auth_organizations": cols(r.Organizations.toRow(model.Organization{})), "auth_memberships": cols(r.Memberships.toRow(model.Membership{})),
		"auth_membership_roles": cols(r.MembershipRoles.toRow(model.MembershipRole{})), "auth_roles": cols(r.Roles.toRow(model.Role{})),
		"auth_role_permissions": cols(r.RolePermissions.toRow(model.RolePermission{})), "auth_permissions": cols(r.Permissions.toRow(model.Permission{})),
		"auth_invitations": cols(r.Invitations.toRow(model.Invitation{})),
	}
	for _, m := range schema.Core() {
		var want []string
		for _, f := range m.Fields {
			want = append(want, f.Column)
		}
		slices.Sort(want)
		if got := columns[m.Table]; !slices.Equal(got, want) {
			t.Errorf("%s: writes %v, schema has %v", m.Table, got, want)
		}
	}
}

func cols(r store.Row) []string { return slices.Sorted(maps.Keys(r)) }

func TestZeroValuesWriteTheColumnDefaults(t *testing.T) {
	r := New(memstore.New())
	if got := r.Users.toRow(model.User{})["status"]; got != model.UserStatusActive {
		t.Errorf("user status = %v", got)
	}
	if got := r.Organizations.toRow(model.Organization{})["status"]; got != model.OrganizationStatusActive {
		t.Errorf("organization status = %v", got)
	}
	if got := r.Memberships.toRow(model.Membership{})["status"]; got != model.MembershipStatusInvited {
		t.Errorf("membership status = %v", got)
	}
	if got := r.OTPChallenges.toRow(model.OTPChallenge{})["max_attempts"]; got != model.DefaultMaxAttempts {
		t.Errorf("max_attempts = %v", got)
	}
	if got := r.Invitations.toRow(model.Invitation{})["role_ids"]; got != "[]" {
		t.Errorf("role_ids = %v", got)
	}
	if got := r.AuditLog.toRow(model.AuditLogEntry{})["metadata"]; got != "[]" {
		t.Errorf("metadata = %v", got)
	}
	got := r.Users.toRow(model.User{CreatedAt: time.Date(2026, 6, 7, 12, 0, 0, 999, time.FixedZone("CEST", 7200))})["created_at"]
	if got != time.Date(2026, 6, 7, 10, 0, 0, 0, time.UTC) {
		t.Errorf("created_at = %v; datetimes are written in UTC to the second", got)
	}
}

// spy records the Update calls that reach the adapter.
type spy struct {
	store.Adapter
	updates []store.Data
	keys    []store.Criteria
}

func (s *spy) Update(ctx context.Context, table string, c store.Criteria, d store.Data) (int64, error) {
	s.updates = append(s.updates, d)
	s.keys = append(s.keys, c)
	return s.Adapter.Update(ctx, table, c, d)
}

func TestUpdateWritesOnlyChangedColumns(t *testing.T) {
	ctx := context.Background()
	db := &spy{Adapter: memstore.New(schema.Core()...)}
	r := New(db)
	u := fullUser()
	must(t, r.Users.Insert(ctx, u))

	must(t, r.Users.Update(ctx, u, u))
	if len(db.updates) != 0 {
		t.Fatalf("an unchanged model issued %v", db.updates)
	}
	next := u
	next.DisplayName = nil
	next.Status = model.UserStatusActive
	next.UpdatedAt = u.UpdatedAt.In(time.FixedZone("CEST", 7200)) // same instant: unchanged
	next.LastLoginAt = ptr(now.Add(time.Hour))
	must(t, r.Users.Update(ctx, u, next))
	want := store.Data{"display_name": nil, "status": model.UserStatusActive, "last_login_at": now.Add(time.Hour)}
	if len(db.updates) != 1 || !reflect.DeepEqual(db.updates[0], want) || !reflect.DeepEqual(db.keys[0], store.Criteria{"id": u.ID}) {
		t.Fatalf("updates = %v keyed %v, want %v", db.updates, db.keys, want)
	}
	got, err := r.Users.Get(ctx, u.ID)
	must(t, err)
	next.UpdatedAt = u.UpdatedAt
	if !reflect.DeepEqual(got, next) {
		t.Errorf("after update:\n got %+v\nwant %+v", got, next)
	}
}

func TestLookupsReportNotFound(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		if _, err := r.Users.Get(ctx, NewID()); !errors.Is(err, ErrNotFound) {
			t.Errorf("Users.Get: %v", err)
		}
		if _, err := r.MembershipRoles.Get(ctx, "m", "r"); !errors.Is(err, ErrNotFound) {
			t.Errorf("MembershipRoles.Get: %v", err)
		}
		if _, err := r.MembershipRoles.Table.Get(ctx, "x"); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Get on a composite key: %v", err)
		}
		if err := r.Users.Delete(ctx, model.User{ID: NewID()}); err != nil {
			t.Errorf("deleting a missing row: %v", err)
		}
	})
}

func TestDuplicatesWrapErrDuplicate(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		first, second := fullUser(), fullUser()
		second.Email = "grace@example.com"
		must(t, r.Users.Insert(ctx, first))
		must(t, r.Users.Insert(ctx, second))
		dup := fullUser()
		if err := r.Users.Insert(ctx, dup); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("insert: %v", err)
		}
		next := second
		next.Email = first.Email
		if err := r.Users.Update(ctx, second, next); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("update: %v", err)
		}
	})
}

// failing is an adapter whose every call fails.
type failing struct{ store.Adapter }

var errDown = errors.New("database down")

func (failing) FindOne(context.Context, string, store.Criteria) (store.Row, error) {
	return nil, errDown
}
func (failing) FindMany(context.Context, string, store.Criteria, store.Query) ([]store.Row, error) {
	return nil, errDown
}
func (failing) Count(context.Context, string, store.Criteria) (int64, error)  { return 0, errDown }
func (failing) Delete(context.Context, string, store.Criteria) (int64, error) { return 0, errDown }
func (failing) Update(context.Context, string, store.Criteria, store.Data) (int64, error) {
	return 0, errDown
}

func TestAdapterErrorsPropagate(t *testing.T) {
	ctx := context.Background()
	r := New(failing{})
	checks := map[string]error{}
	_, checks["get"] = r.Users.Get(ctx, "x")
	_, checks["list"] = r.Permissions.List(ctx)
	_, checks["count"] = r.Users.Count(ctx, nil)
	checks["delete"] = r.Users.Delete(ctx, model.User{})
	checks["update"] = r.Users.Update(ctx, model.User{}, model.User{Email: "x"})
	_, checks["claim"] = r.RecoveryCodes.ClaimUse(ctx, "x", now)
	_, checks["prune"] = r.OTPChallenges.Prune(ctx, now)
	_, checks["prune tokens"] = r.RefreshTokens.Prune(ctx, now)
	for name, err := range checks {
		if !errors.Is(err, errDown) {
			t.Errorf("%s: %v, want the adapter error", name, err)
		}
	}
}

func TestUnreadableRowsFail(t *testing.T) {
	ctx := context.Background()
	db := memstore.New()
	r := New(db)
	must(t, db.Insert(ctx, "auth_users", store.Row{"id": "u", "created_at": "not a time", "updated_at": now}))
	if _, err := r.Users.Get(ctx, "u"); err == nil || errors.Is(err, ErrNotFound) {
		t.Errorf("bad datetime: %v", err)
	}
	must(t, db.Insert(ctx, "auth_invitations", store.Row{"id": "i", "role_ids": "{", "expires_at": now, "created_at": now}))
	if _, err := r.Invitations.Find(ctx, nil, store.Query{}); err == nil {
		t.Error("bad JSON accepted")
	}
}
