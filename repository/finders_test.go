package repository

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/store"
)

func ids[T any](t *testing.T, items []T, err error, id func(T) string) []string {
	t.Helper()
	must(t, err)
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = id(it)
	}
	return out
}

func sameSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, g := range got {
		seen[g]++
	}
	for _, w := range want {
		seen[w]--
		if seen[w] < 0 {
			return false
		}
	}
	return true
}

func TestRefreshTokenFindersAndRotation(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		userID, orgID, family := NewID(), NewID(), NewID()
		root := model.RefreshToken{ID: NewID(), UserID: userID, OrganizationID: &orgID, FamilyID: family, TokenHash: NewID(), ExpiresAt: now.Add(time.Hour), RevokedAt: ptr(now), RevokedReason: ptr(model.RevokedRotated), CreatedAt: now}
		live := model.RefreshToken{ID: NewID(), UserID: userID, FamilyID: family, ParentID: &root.ID, TokenHash: NewID(), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
		other := model.RefreshToken{ID: NewID(), UserID: NewID(), FamilyID: NewID(), TokenHash: NewID(), ExpiresAt: now.Add(-time.Hour), CreatedAt: now}
		for _, tok := range []model.RefreshToken{root, live, other} {
			must(t, r.RefreshTokens.Insert(ctx, tok))
		}
		id := func(t model.RefreshToken) string { return t.ID }
		list, err := r.RefreshTokens.ListByUser(ctx, userID)
		if got := ids(t, list, err, id); !sameSet(got, []string{root.ID, live.ID}) {
			t.Errorf("ListByUser = %v", got)
		}
		list, err = r.RefreshTokens.ListByUserAndOrganization(ctx, userID, orgID)
		if got := ids(t, list, err, id); !sameSet(got, []string{root.ID}) {
			t.Errorf("ListByUserAndOrganization = %v", got)
		}
		list, err = r.RefreshTokens.ListByFamily(ctx, family)
		if got := ids(t, list, err, id); !sameSet(got, []string{root.ID, live.ID}) {
			t.Errorf("ListByFamily = %v", got)
		}
		if got, err := r.RefreshTokens.ActiveInFamily(ctx, family); err != nil || got.ID != live.ID {
			t.Errorf("ActiveInFamily = %v, %v", got.ID, err)
		}
		if got, err := r.RefreshTokens.FamilyRoot(ctx, family); err != nil || got.ID != root.ID {
			t.Errorf("FamilyRoot = %v, %v", got.ID, err)
		}

		later := now.Add(time.Minute)
		first, err := r.RefreshTokens.ClaimRotation(ctx, live.ID, later)
		must(t, err)
		second, err := r.RefreshTokens.ClaimRotation(ctx, live.ID, later)
		must(t, err)
		if !first || second {
			t.Errorf("rotation claims = %v %v, want true false: a second rotation loses", first, second)
		}
		rotated, err := r.RefreshTokens.Get(ctx, live.ID)
		must(t, err)
		if !rotated.RevokedAt.Equal(later) || !rotated.LastUsedAt.Equal(later) || *rotated.RevokedReason != model.RevokedRotated {
			t.Errorf("rotated = %+v", rotated)
		}
		if _, err := r.RefreshTokens.ActiveInFamily(ctx, family); !errors.Is(err, ErrNotFound) {
			t.Errorf("no live token left: %v", err)
		}

		// Prune: other expired an hour ago; root and live were revoked at now / later.
		n, err := r.RefreshTokens.Prune(ctx, now.Add(30*time.Second))
		must(t, err)
		left, _ := r.RefreshTokens.Count(ctx, nil)
		if n != 2 || left != 1 {
			t.Errorf("pruned %d, left %d; want 2, 1", n, left)
		}
	})
}

func TestOneTimeTokenFindersAndPrune(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		userID := NewID()
		pending := model.PasswordReset{ID: NewID(), UserID: userID, Email: "a@x.io", TokenHash: NewID(), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
		consumed := model.PasswordReset{ID: NewID(), UserID: userID, Email: "a@x.io", TokenHash: NewID(), ExpiresAt: now.Add(time.Hour), ConsumedAt: ptr(now), CreatedAt: now}
		expired := model.PasswordReset{ID: NewID(), UserID: NewID(), Email: "b@x.io", TokenHash: NewID(), ExpiresAt: now.Add(-time.Hour), CreatedAt: now}
		for _, p := range []model.PasswordReset{pending, consumed, expired} {
			must(t, r.PasswordResets.Insert(ctx, p))
		}
		list, err := r.PasswordResets.ListByUser(ctx, userID)
		if got := ids(t, list, err, func(p model.PasswordReset) string { return p.ID }); !sameSet(got, []string{pending.ID, consumed.ID}) {
			t.Errorf("ListByUser = %v", got)
		}
		n, err := r.PasswordResets.Prune(ctx, now)
		must(t, err)
		if n != 2 {
			t.Errorf("pruned %d, want 2", n)
		}
		n, err = r.PasswordResets.DeleteByUser(ctx, userID)
		must(t, err)
		if left, _ := r.PasswordResets.Count(ctx, nil); n != 1 || left != 0 {
			t.Errorf("DeleteByUser removed %d, left %d", n, left)
		}

		v := model.EmailVerification{ID: NewID(), UserID: userID, Email: "a@x.io", TokenHash: NewID(), ExpiresAt: now.Add(time.Hour), CreatedAt: now}
		must(t, r.EmailVerifications.Insert(ctx, v))
		if n, err := r.EmailVerifications.DeleteByUser(ctx, userID); err != nil || n != 1 {
			t.Errorf("verifications DeleteByUser = %d, %v", n, err)
		}
	})
}

func TestMFAFindersAndClaims(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		userID := NewID()
		totp := fullFactor(userID)
		totp.Type = model.FactorTOTP
		sms := fullFactor(userID)
		must(t, r.MFAFactors.Insert(ctx, totp))
		must(t, r.MFAFactors.Insert(ctx, sms))
		fid := func(f model.MFAFactor) string { return f.ID }
		list, err := r.MFAFactors.ListByUser(ctx, userID)
		if got := ids(t, list, err, fid); !sameSet(got, []string{totp.ID, sms.ID}) {
			t.Errorf("ListByUser = %v", got)
		}
		list, err = r.MFAFactors.ListByUserAndType(ctx, userID, model.FactorTOTP)
		if got := ids(t, list, err, fid); !sameSet(got, []string{totp.ID}) {
			t.Errorf("ListByUserAndType = %v", got)
		}

		c := fullChallenge(userID)
		c.FactorID, c.Attempts, c.MaxAttempts, c.ConsumedAt = &sms.ID, 0, 2, nil
		must(t, r.OTPChallenges.Insert(ctx, c))
		list2, err := r.OTPChallenges.ListForFactor(ctx, userID, sms.ID, "login_mfa")
		if got := ids(t, list2, err, func(c model.OTPChallenge) string { return c.ID }); !sameSet(got, []string{c.ID}) {
			t.Errorf("ListForFactor = %v", got)
		}
		var spent []bool
		for range 3 {
			ok, err := r.OTPChallenges.SpendAttempt(ctx, c.ID, c.MaxAttempts)
			must(t, err)
			spent = append(spent, ok)
		}
		if spent[0] != true || spent[1] != true || spent[2] != false {
			t.Errorf("spends = %v, want true true false: the budget is enforced by the database", spent)
		}
		first, err := r.OTPChallenges.ClaimConsumption(ctx, c.ID, now)
		must(t, err)
		second, err := r.OTPChallenges.ClaimConsumption(ctx, c.ID, now)
		must(t, err)
		if !first || second {
			t.Errorf("consumption claims = %v %v", first, second)
		}
		got, err := r.OTPChallenges.Get(ctx, c.ID)
		must(t, err)
		if got.Attempts != 2 || got.ConsumedAt == nil {
			t.Errorf("challenge = %+v", got)
		}
		if n, err := r.OTPChallenges.Prune(ctx, now); err != nil || n != 1 {
			t.Errorf("Prune = %d, %v", n, err)
		}
		must(t, r.OTPChallenges.Insert(ctx, fullChallenge(userID)))
		if n, err := r.OTPChallenges.DeleteByUser(ctx, userID); err != nil || n != 1 {
			t.Errorf("challenges DeleteByUser = %d, %v", n, err)
		}
		if n, err := r.MFAFactors.DeleteByUser(ctx, userID); err != nil || n != 2 {
			t.Errorf("factors DeleteByUser = %d, %v", n, err)
		}

		unused := model.RecoveryCode{ID: NewID(), UserID: userID, CodeHash: NewID(), CreatedAt: now}
		used := model.RecoveryCode{ID: NewID(), UserID: userID, CodeHash: NewID(), UsedAt: ptr(now), CreatedAt: now}
		must(t, r.RecoveryCodes.Insert(ctx, unused))
		must(t, r.RecoveryCodes.Insert(ctx, used))
		codes, err := r.RecoveryCodes.ListUnusedByUser(ctx, userID)
		if got := ids(t, codes, err, func(c model.RecoveryCode) string { return c.ID }); !sameSet(got, []string{unused.ID}) {
			t.Errorf("ListUnusedByUser = %v", got)
		}
		a, err := r.RecoveryCodes.ClaimUse(ctx, unused.ID, now)
		must(t, err)
		b, err := r.RecoveryCodes.ClaimUse(ctx, unused.ID, now)
		must(t, err)
		if !a || b {
			t.Errorf("code claims = %v %v", a, b)
		}
	})
}

func TestOrganizationFinders(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		ctx := context.Background()
		userID, orgA, orgB := NewID(), NewID(), NewID()
		active := fullMembership(userID, orgA)
		suspended := fullMembership(userID, orgB)
		suspended.Status = model.MembershipStatusSuspended
		peer := fullMembership(NewID(), orgA)
		for _, m := range []model.Membership{active, suspended, peer} {
			must(t, r.Memberships.Insert(ctx, m))
		}
		mid := func(m model.Membership) string { return m.ID }
		if got, err := r.Memberships.ByUserAndOrganization(ctx, userID, orgB); err != nil || got.ID != suspended.ID {
			t.Errorf("ByUserAndOrganization = %v, %v", got.ID, err)
		}
		list, err := r.Memberships.ListByUser(ctx, userID)
		if got := ids(t, list, err, mid); !sameSet(got, []string{active.ID, suspended.ID}) {
			t.Errorf("ListByUser = %v", got)
		}
		list, err = r.Memberships.ListActiveByUser(ctx, userID)
		if got := ids(t, list, err, mid); !sameSet(got, []string{active.ID}) {
			t.Errorf("ListActiveByUser = %v", got)
		}
		list, err = r.Memberships.ListByOrganization(ctx, orgA)
		if got := ids(t, list, err, mid); !sameSet(got, []string{active.ID, peer.ID}) {
			t.Errorf("ListByOrganization = %v", got)
		}

		system := fullRole(nil)
		owner := fullRole(&orgA)
		admin := fullRole(&orgA)
		admin.Slug = "admin"
		for _, role := range []model.Role{system, owner, admin} {
			must(t, r.Roles.Insert(ctx, role))
		}
		rid := func(r model.Role) string { return r.ID }
		if got, err := r.Roles.ByOrganizationAndSlug(ctx, nil, "owner"); err != nil || got.ID != system.ID {
			t.Errorf("system role = %v, %v", got.ID, err)
		}
		if got, err := r.Roles.ByOrganizationAndSlug(ctx, &orgA, "owner"); err != nil || got.ID != owner.ID {
			t.Errorf("org role = %v, %v", got.ID, err)
		}
		roles, err := r.Roles.ListByOrganization(ctx, orgA)
		if got := ids(t, roles, err, rid); !sameSet(got, []string{owner.ID, admin.ID}) {
			t.Errorf("ListByOrganization = %v", got)
		}
		roles, err = r.Roles.ListBySlug(ctx, "owner")
		if got := ids(t, roles, err, rid); !sameSet(got, []string{system.ID, owner.ID}) {
			t.Errorf("ListBySlug = %v", got)
		}

		must(t, r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: active.ID, RoleID: owner.ID}))
		must(t, r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: active.ID, RoleID: admin.ID}))
		must(t, r.MembershipRoles.Insert(ctx, model.MembershipRole{MembershipID: peer.ID, RoleID: owner.ID}))
		links, err := r.MembershipRoles.ListByMembership(ctx, active.ID)
		if got := ids(t, links, err, func(l model.MembershipRole) string { return l.RoleID }); !sameSet(got, []string{owner.ID, admin.ID}) {
			t.Errorf("ListByMembership = %v", got)
		}
		links, err = r.MembershipRoles.ListByRole(ctx, owner.ID)
		if got := ids(t, links, err, func(l model.MembershipRole) string { return l.MembershipID }); !sameSet(got, []string{active.ID, peer.ID}) {
			t.Errorf("ListByRole = %v", got)
		}
		must(t, r.MembershipRoles.Delete(ctx, model.MembershipRole{MembershipID: active.ID, RoleID: admin.ID}))
		if n, _ := r.MembershipRoles.Count(ctx, store.Criteria{"membership_id": active.ID}); n != 1 {
			t.Errorf("after unlinking: %d links", n)
		}

		p1 := model.Permission{ID: NewID(), Key: "a", Description: "A"}
		p2 := model.Permission{ID: NewID(), Key: "b", Description: "B"}
		must(t, r.Permissions.Insert(ctx, p1))
		must(t, r.Permissions.Insert(ctx, p2))
		perms, err := r.Permissions.List(ctx)
		if got := ids(t, perms, err, func(p model.Permission) string { return p.ID }); !sameSet(got, []string{p1.ID, p2.ID}) {
			t.Errorf("List = %v", got)
		}
		must(t, r.RolePermissions.Insert(ctx, model.RolePermission{RoleID: owner.ID, PermissionID: p1.ID}))
		must(t, r.RolePermissions.Insert(ctx, model.RolePermission{RoleID: owner.ID, PermissionID: p2.ID}))
		grants, err := r.RolePermissions.ListByRole(ctx, owner.ID)
		if got := ids(t, grants, err, func(g model.RolePermission) string { return g.PermissionID }); !sameSet(got, []string{p1.ID, p2.ID}) {
			t.Errorf("grants ListByRole = %v", got)
		}

		i1 := fullInvitation(orgA)
		i2 := fullInvitation(orgA)
		i2.Email = "other@example.com"
		must(t, r.Invitations.Insert(ctx, i1))
		must(t, r.Invitations.Insert(ctx, i2))
		iid := func(i model.Invitation) string { return i.ID }
		invs, err := r.Invitations.ListByOrganization(ctx, orgA)
		if got := ids(t, invs, err, iid); !sameSet(got, []string{i1.ID, i2.ID}) {
			t.Errorf("invitations ListByOrganization = %v", got)
		}
		invs, err = r.Invitations.ListByOrganizationAndEmail(ctx, orgA, "other@example.com")
		if got := ids(t, invs, err, iid); !sameSet(got, []string{i2.ID}) {
			t.Errorf("ListByOrganizationAndEmail = %v", got)
		}
	})
}

func TestReposShareOneTransaction(t *testing.T) {
	backends(t, func(t *testing.T, r *Repos) {
		abort := errors.New("abort")
		err := r.DB.Tx(context.Background(), func(ctx context.Context) error {
			if err := r.Users.Insert(ctx, fullUser()); err != nil {
				return err
			}
			if err := r.Organizations.Insert(ctx, model.Organization{ID: NewID(), Name: "A", Slug: "a", CreatedBy: "u", CreatedAt: now, UpdatedAt: now}); err != nil {
				return err
			}
			return abort
		})
		if !errors.Is(err, abort) {
			t.Fatalf("Tx = %v", err)
		}
		users, _ := r.Users.Count(context.Background(), nil)
		orgs, _ := r.Organizations.Count(context.Background(), nil)
		if users != 0 || orgs != 0 {
			t.Errorf("after rollback: %d users, %d orgs", users, orgs)
		}
	})
}
