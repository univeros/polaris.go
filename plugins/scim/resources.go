package scim

import (
	"context"
	"time"

	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// Resource kinds of polaris_scim_resource.
const (
	KindUser  = "User"
	KindGroup = "Group"
)

// resources keeps the directory's external ids (polaris_scim_resource) and the memberships a
// connection created (polaris_scim_membership_provenance), the only ones it removes.
type resources struct {
	db    store.Adapter
	clock clock.Clock
}

func (r *resources) now() time.Time { return r.clock.Now().UTC().Truncate(time.Second) }

func key(conn Connection, kind, localID string) store.Criteria {
	return store.Criteria{"connection_id": conn.ID, "kind": kind, "local_id": localID}
}

// externalID is the directory's id of a user or role, "" when unknown.
func (r *resources) externalID(ctx context.Context, conn Connection, kind, localID string) (string, error) {
	row, err := r.db.FindOne(ctx, TableResources, key(conn, kind, localID))
	if err != nil || row == nil {
		return "", err
	}
	return row.String("external_id"), nil
}

// setExternalID records (or, for "", forgets) the directory's id of a user or role.
func (r *resources) setExternalID(ctx context.Context, conn Connection, kind, localID, externalID string) error {
	criteria := key(conn, kind, localID)
	if externalID == "" {
		_, err := r.db.Delete(ctx, TableResources, criteria)
		return err
	}
	now := r.now()
	n, err := r.db.Update(ctx, TableResources, criteria, store.Data{"external_id": externalID, "updated_at": now})
	if err != nil || n > 0 {
		return err
	}
	return r.db.Insert(ctx, TableResources, store.Row{"id": repository.NewID(), "connection_id": conn.ID, "kind": kind,
		"local_id": localID, "external_id": externalID, "updated_at": now})
}

func (r *resources) forget(ctx context.Context, conn Connection, kind, localID string) error {
	_, err := r.db.Delete(ctx, TableResources, key(conn, kind, localID))
	if err == nil && kind == KindUser {
		err = r.setNameParts(ctx, conn, localID, nameParts{})
	}
	return err
}

// nameParts are a User's name.givenName and name.familyName ("" when not sent).
type nameParts struct{ given, family string }

// nameParts reads what the directory sent for userID (zero when nothing).
func (r *resources) nameParts(ctx context.Context, conn Connection, userID string) (nameParts, error) {
	row, err := r.db.FindOne(ctx, TableUserNames, store.Criteria{"connection_id": conn.ID, "user_id": userID})
	if err != nil || row == nil {
		return nameParts{}, err
	}
	return nameParts{given: row.String("given_name"), family: row.String("family_name")}, nil
}

// setNameParts records the parts the directory sent for userID; zero parts delete the record.
func (r *resources) setNameParts(ctx context.Context, conn Connection, userID string, p nameParts) error {
	criteria := store.Criteria{"connection_id": conn.ID, "user_id": userID}
	if p == (nameParts{}) {
		_, err := r.db.Delete(ctx, TableUserNames, criteria)
		return err
	}
	data := store.Data{"given_name": nullable(p.given), "family_name": nullable(p.family), "updated_at": r.now()}
	n, err := r.db.Update(ctx, TableUserNames, criteria, data)
	if err != nil || n > 0 {
		return err
	}
	return r.db.Insert(ctx, TableUserNames, store.Row{"id": repository.NewID(), "connection_id": conn.ID, "user_id": userID,
		"given_name": nullable(p.given), "family_name": nullable(p.family), "updated_at": r.now()})
}

func (r *resources) count(ctx context.Context, conn Connection, kind string) (int64, error) {
	return r.db.Count(ctx, TableResources, store.Criteria{"connection_id": conn.ID, "kind": kind})
}

// recordMembership notes that conn created userID's membership, unless one is recorded already.
// now is the membership's creation time, the provenance's created_at (owns compares it with the
// user's).
func (r *resources) recordMembership(ctx context.Context, conn Connection, userID string, now time.Time) error {
	found, err := r.db.FindOne(ctx, TableProvenance, store.Criteria{"organization_id": conn.OrganizationID, "user_id": userID})
	if err != nil || found != nil {
		return err
	}
	return r.db.Insert(ctx, TableProvenance, store.Row{"id": repository.NewID(), "organization_id": conn.OrganizationID,
		"user_id": userID, "connection_id": conn.ID, "created_at": now})
}

func (r *resources) createdMembership(ctx context.Context, conn Connection, userID string) (bool, error) {
	n, err := r.db.Count(ctx, TableProvenance, store.Criteria{"organization_id": conn.OrganizationID, "user_id": userID, "connection_id": conn.ID})
	return n > 0, err
}

func (r *resources) forgetMembership(ctx context.Context, conn Connection, userID string) error {
	_, err := r.db.Delete(ctx, TableProvenance, store.Criteria{"organization_id": conn.OrganizationID, "user_id": userID})
	return err
}

func (r *resources) provisioned(ctx context.Context, conn Connection) (int64, error) {
	return r.db.Count(ctx, TableProvenance, store.Criteria{"connection_id": conn.ID})
}

// sync is a connection's state: what it manages.
func (r *resources) sync(ctx context.Context, conn Connection) (map[string]any, error) {
	users, err := r.count(ctx, conn, KindUser)
	if err != nil {
		return nil, err
	}
	groups, err := r.count(ctx, conn, KindGroup)
	if err != nil {
		return nil, err
	}
	members, err := r.provisioned(ctx, conn)
	if err != nil {
		return nil, err
	}
	return map[string]any{"users": users, "groups": groups, "provisioned_members": members}, nil
}
