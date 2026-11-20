package repository

// Ports of PHP tests/Persistence/{AuthEntities,MfaEntities,OrgMembership,Invitation,
// RolesPermissions,TransientTokenEntities}PersistenceTest. The schema assertions of those tests
// (tables, columns, indexes, keys) are covered by sqlstore's Diff tests; here are the round trips,
// unique indexes and cascades.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

func TestUserRoundTrips(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		u := model.User{ID: NewID(), Email: "ada@example.com", DisplayName: ptr("Ada"), FailedLoginCount: 2, FailedLoginAt: ptr(now), CreatedAt: now, UpdatedAt: now}
		must(t, r.Users.Insert(ctx, u))
		found, err := r.Users.ByEmail(ctx, "ada@example.com")
		must(t, err)
		if found.ID != u.ID || *found.DisplayName != "Ada" || found.Status != model.UserStatusActive || found.MFAEnforced ||
			found.FailedLoginCount != 2 || found.FailedLoginAt == nil || found.EmailVerifiedAt != nil || found.PasswordHash != nil || !found.CreatedAt.Equal(now) {
			t.Errorf("found %+v", found)
		}
	})
}

func TestRefreshTokenRoundTrips(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		hash := strings.Repeat("a", 64)
		tok := model.RefreshToken{ID: NewID(), UserID: NewID(), FamilyID: NewID(), TokenHash: hash, ExpiresAt: now.AddDate(0, 0, 30), CreatedAt: now}
		must(t, r.RefreshTokens.Insert(ctx, tok))
		found, err := r.RefreshTokens.ByTokenHash(ctx, hash)
		must(t, err)
		if found.ID != tok.ID || found.UserID != tok.UserID || found.FamilyID != tok.FamilyID || found.OrganizationID != nil ||
			found.ParentID != nil || found.RevokedAt != nil || found.RevokedReason != nil || !found.ExpiresAt.Equal(tok.ExpiresAt) {
			t.Errorf("found %+v", found)
		}
	})
}

func TestMFAFactorRoundTrips(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		f := model.MFAFactor{ID: NewID(), UserID: NewID(), Type: model.FactorTOTP, Label: ptr("iPhone Authenticator"), SecretEncrypted: ptr(strings.Repeat("x", 200)), IsDefault: true, ConfirmedAt: ptr(now), CreatedAt: now, UpdatedAt: now}
		must(t, r.MFAFactors.Insert(ctx, f))
		found, err := r.MFAFactors.FindOne(ctx, store.Criteria{"id": f.ID})
		must(t, err)
		if found.UserID != f.UserID || found.Type != model.FactorTOTP || *found.Label != "iPhone Authenticator" ||
			*found.SecretEncrypted != strings.Repeat("x", 200) || !found.IsDefault || found.ConfirmedAt == nil || found.PhoneE164 != nil {
			t.Errorf("found %+v", found)
		}
	})
}

func TestOTPChallengeRoundTrips(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		hash := strings.Repeat("b", 64)
		c := model.OTPChallenge{ID: NewID(), UserID: NewID(), Purpose: "login_mfa", Channel: model.ChannelSMS, CodeHash: &hash, Destination: ptr("+15551234567"), ExpiresAt: now.Add(5 * time.Minute), CreatedAt: now}
		must(t, r.OTPChallenges.Insert(ctx, c))
		found, err := r.OTPChallenges.FindOne(ctx, store.Criteria{"code_hash": hash})
		must(t, err)
		if found.UserID != c.UserID || found.Purpose != "login_mfa" || found.Channel != model.ChannelSMS || found.Attempts != 0 ||
			found.MaxAttempts != 5 || found.FactorID != nil || found.ConsumedAt != nil || !found.ExpiresAt.Equal(c.ExpiresAt) {
			t.Errorf("found %+v", found)
		}
	})
}

func TestRecoveryCodeRoundTrips(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		c := model.RecoveryCode{ID: NewID(), UserID: NewID(), CodeHash: strings.Repeat("c", 64), CreatedAt: now}
		must(t, r.RecoveryCodes.Insert(ctx, c))
		found, err := r.RecoveryCodes.FindOne(ctx, store.Criteria{"code_hash": c.CodeHash})
		must(t, err)
		if found.UserID != c.UserID || found.UsedAt != nil || !found.CreatedAt.Equal(now) {
			t.Errorf("found %+v", found)
		}
	})
}

func TestOrganizationRoundTrips(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		o := model.Organization{ID: NewID(), Name: "Acme Inc", Slug: "acme", Status: model.OrganizationStatusActive, CreatedBy: NewID(), CreatedAt: now, UpdatedAt: now}
		must(t, r.Organizations.Insert(ctx, o))
		found, err := r.Organizations.BySlug(ctx, "acme")
		must(t, err)
		if found.Name != "Acme Inc" || found.Status != model.OrganizationStatusActive || found.CreatedBy != o.CreatedBy {
			t.Errorf("found %+v", found)
		}
	})
}

func TestMembershipRoundTripsAndTheUserOrgPairIsUnique(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		m := fullMembership(NewID(), NewID())
		must(t, r.Memberships.Insert(ctx, m))
		found, err := r.Memberships.Get(ctx, m.ID)
		must(t, err)
		if found.UserID != m.UserID || found.OrganizationID != m.OrganizationID || found.Status != model.MembershipStatusActive ||
			*found.InvitedBy != *m.InvitedBy || found.JoinedAt == nil {
			t.Errorf("found %+v", found)
		}
		dup := model.Membership{ID: NewID(), UserID: m.UserID, OrganizationID: m.OrganizationID, CreatedAt: now, UpdatedAt: now}
		if err := r.Memberships.Insert(ctx, dup); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("a second membership for the same user/org pair: %v, want ErrDuplicate", err)
		}
	})
}

func TestInvitationRoundTripsAndTheTokenHashIsUnique(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		inv := model.Invitation{ID: NewID(), OrganizationID: NewID(), Email: "invitee@example.com", RoleIDs: []string{NewID(), NewID()}, TokenHash: NewID(), InvitedBy: NewID(), ExpiresAt: now.AddDate(0, 0, 7), CreatedAt: now}
		must(t, r.Invitations.Insert(ctx, inv))
		found, err := r.Invitations.ByTokenHash(ctx, inv.TokenHash)
		must(t, err)
		if found.Email != inv.Email || found.OrganizationID != inv.OrganizationID || found.InvitedBy != inv.InvitedBy ||
			!slices.Equal(found.RoleIDs, inv.RoleIDs) || found.AcceptedAt != nil || found.ExpiresAt.Format(store.TimeLayout) != "2026-06-14 10:00:00" {
			t.Errorf("found %+v", found)
		}
		again := inv
		again.ID = NewID()
		if err := r.Invitations.Insert(ctx, again); !errors.Is(err, store.ErrDuplicate) {
			t.Errorf("two invitations sharing a token hash: %v, want ErrDuplicate", err)
		}
	})
}

func TestTransientTokensRoundTrip(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		v := model.EmailVerification{ID: NewID(), UserID: NewID(), Email: "ada@example.com", TokenHash: strings.Repeat("a", 64), ExpiresAt: now.Add(24 * time.Hour), IP: ptr("203.0.113.7"), CreatedAt: now}
		must(t, r.EmailVerifications.Insert(ctx, v))
		found, err := r.EmailVerifications.ByTokenHash(ctx, v.TokenHash)
		must(t, err)
		if found.ID != v.ID || found.Email != v.Email || *found.IP != "203.0.113.7" || found.ConsumedAt != nil {
			t.Errorf("verification %+v", found)
		}
		p := model.PasswordReset{ID: NewID(), UserID: NewID(), Email: "grace@example.com", TokenHash: strings.Repeat("b", 64), ExpiresAt: now.Add(time.Hour), ConsumedAt: ptr(now.Add(5 * time.Minute)), CreatedAt: now}
		must(t, r.PasswordResets.Insert(ctx, p))
		reset, err := r.PasswordResets.ByTokenHash(ctx, p.TokenHash)
		must(t, err)
		if reset.ID != p.ID || reset.Email != p.Email || reset.IP != nil || reset.ConsumedAt == nil {
			t.Errorf("reset %+v", reset)
		}
	})
}

func TestRolesAndPermissionsRoundTrip(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		role := fullRole(ptr(NewID()))
		must(t, r.Roles.Insert(ctx, role))
		system := model.Role{ID: NewID(), Name: "Super Admin", Slug: "superadmin", IsSystem: true, CreatedAt: now, UpdatedAt: now}
		must(t, r.Roles.Insert(ctx, system))
		found, err := r.Roles.Get(ctx, system.ID)
		must(t, err)
		if found.OrganizationID != nil || found.Description != nil || !found.IsSystem {
			t.Errorf("system role %+v", found)
		}
		p := model.Permission{ID: NewID(), Key: "test.permission", Description: "A custom, non-catalog permission"}
		must(t, r.Permissions.Insert(ctx, p))
		if got, err := r.Permissions.ByKey(ctx, "test.permission"); err != nil || got != p {
			t.Errorf("permission %+v, %v", got, err)
		}
		grant := model.RolePermission{RoleID: role.ID, PermissionID: p.ID}
		must(t, r.RolePermissions.Insert(ctx, grant))
		if got, err := r.RolePermissions.Get(ctx, role.ID, p.ID); err != nil || got != grant {
			t.Errorf("grant %+v, %v", got, err)
		}
	})
}

// The FK cascades: the database's on SQL, memstore's own (it applies the schema's ON DELETE).
func TestDeletesCascadeToGrants(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		seed := func(t *testing.T) (model.Role, model.Permission, model.Membership) {
			role := fullRole(ptr(NewID()))
			p := model.Permission{ID: NewID(), Key: NewID(), Description: "d"}
			m := fullMembership(NewID(), NewID())
			must(t, r.Roles.Insert(ctx, role))
			must(t, r.Permissions.Insert(ctx, p))
			must(t, r.Memberships.Insert(ctx, m))
			must(t, r.RolePermissions.Insert(ctx, model.RolePermission{RoleID: role.ID, PermissionID: p.ID}))
			must(t, r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: m.ID, RoleID: role.ID}))
			return role, p, m
		}
		count := func(t *testing.T, n int, err error, want int, what string) {
			t.Helper()
			if err != nil || n != want {
				t.Errorf("%s: %d, %v; want %d", what, n, err, want)
			}
		}
		t.Run("role", func(t *testing.T) {
			role, p, m := seed(t)
			must(t, r.Roles.Delete(ctx, role))
			grants, err := r.RolePermissions.ListByRole(ctx, role.ID)
			count(t, len(grants), err, 0, "role grants")
			links, err := r.MembershipRoles.ListByMembership(ctx, m.ID)
			count(t, len(links), err, 0, "membership links")
			_, err = r.Permissions.Get(ctx, p.ID)
			must(t, err)
			_, err = r.Memberships.Get(ctx, m.ID)
			must(t, err)
		})
		t.Run("permission", func(t *testing.T) {
			role, p, _ := seed(t)
			must(t, r.Permissions.Delete(ctx, p))
			grants, err := r.RolePermissions.ListByRole(ctx, role.ID)
			count(t, len(grants), err, 0, "role grants")
			_, err = r.Roles.Get(ctx, role.ID)
			must(t, err)
		})
		t.Run("membership", func(t *testing.T) {
			role, _, m := seed(t)
			must(t, r.Memberships.Delete(ctx, m))
			links, err := r.MembershipRoles.ListByRole(ctx, role.ID)
			count(t, len(links), err, 0, "membership links")
			_, err = r.Roles.Get(ctx, role.ID)
			must(t, err)
		})
	})
}
