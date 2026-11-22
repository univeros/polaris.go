package authz

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// Seed makes sure every catalog permission and every system role template exists in db, with the
// template's grants: auth_permissions by key, auth_roles as global system roles (organization_id
// NULL, is_system), auth_role_permissions. It is idempotent (rows are looked up by their natural
// keys and only inserted when missing) and runs in one transaction. Run it right after creating
// the schema; a role template's grant of a key missing from the catalog is skipped. Roles are
// stamped with clk's time (nil: clock.System).
func Seed(ctx context.Context, db store.Adapter, catalog Catalog, clk clock.Clock) error {
	if clk == nil {
		clk = clock.System{}
	}
	now := clk.Now().UTC()
	r := repository.New(db)
	return db.Tx(ctx, func(ctx context.Context) error {
		ids := map[string]string{}
		for _, p := range catalog.Permissions() {
			id, err := ensurePermission(ctx, r, p)
			if err != nil {
				return err
			}
			ids[p.Key] = id
		}
		for _, t := range catalog.RoleTemplates() {
			roleID, err := ensureSystemRole(ctx, r, t, now)
			if err != nil {
				return err
			}
			for _, key := range t.PermissionKeys {
				pid, ok := ids[key]
				if !ok {
					continue
				}
				added, err := ensureGrant(ctx, r, roleID, pid)
				if err != nil {
					return err
				}
				if added {
					if err := grantToCopies(ctx, r, t.Slug, pid); err != nil {
						return err
					}
				}
			}
		}
		return nil
	})
}

func ensurePermission(ctx context.Context, r *repository.Repos, p Permission) (string, error) {
	found, err := r.Permissions.ByKey(ctx, p.Key)
	if err == nil {
		return found.ID, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return "", fmt.Errorf("authz: seed permission %s: %w", p.Key, err)
	}
	row := model.Permission{ID: repository.NewID(), Key: p.Key, Description: p.Description}
	if err := r.Permissions.Insert(ctx, row); err != nil {
		return "", fmt.Errorf("authz: seed permission %s: %w", p.Key, err)
	}
	return row.ID, nil
}

func ensureSystemRole(ctx context.Context, r *repository.Repos, t RoleTemplate, now time.Time) (string, error) {
	found, err := r.Roles.ByOrganizationAndSlug(ctx, nil, t.Slug)
	if err == nil {
		return found.ID, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return "", fmt.Errorf("authz: seed role %s: %w", t.Slug, err)
	}
	desc := t.Description
	role := model.Role{ID: repository.NewID(), Name: t.Name, Slug: t.Slug, Description: &desc, IsSystem: true, CreatedAt: now, UpdatedAt: now}
	if err := r.Roles.Insert(ctx, role); err != nil {
		return "", fmt.Errorf("authz: seed role %s: %w", t.Slug, err)
	}
	return role.ID, nil
}

// ensureGrant grants permissionID to roleID unless it already holds it, and reports whether it
// added the grant.
func ensureGrant(ctx context.Context, r *repository.Repos, roleID, permissionID string) (bool, error) {
	_, err := r.RolePermissions.Get(ctx, roleID, permissionID)
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return false, fmt.Errorf("authz: seed grant: %w", err)
	}
	if err := r.RolePermissions.Insert(ctx, model.RolePermission{RoleID: roleID, PermissionID: permissionID}); err != nil {
		return false, fmt.Errorf("authz: seed grant: %w", err)
	}
	return true, nil
}

// grantToCopies gives a grant new to the system template slug to every organization's copy of
// it. The template's grants record what was given: a later Seed finds the grant on the template
// and leaves the copies alone, so a tenant's removal from an editable role is kept.
func grantToCopies(ctx context.Context, r *repository.Repos, slug, permissionID string) error {
	roles, err := r.Roles.ListBySlug(ctx, slug)
	if err != nil {
		return fmt.Errorf("authz: seed %s grants: %w", slug, err)
	}
	for _, role := range roles {
		if role.OrganizationID == nil {
			continue
		}
		if _, err := ensureGrant(ctx, r, role.ID, permissionID); err != nil {
			return err
		}
	}
	return nil
}
