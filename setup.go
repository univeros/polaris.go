package polaris

import (
	"context"
	"errors"
	"fmt"
	"github.com/univeros/polaris.go/internal/maintenance"
	"github.com/univeros/polaris.go/internal/services"

	"github.com/univeros/polaris.go/config"
	"github.com/univeros/polaris.go/internal/authz"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
)

// FromEnv builds a Config from the process environment (APP_KEY, AUTH_JWT_PRIVATE_KEY,
// AUTH_JWT_PUBLIC_KEY, AUTH_ISSUER, … — see config.FromEnv) over db, with plugins. Every other port
// takes its default; set fields on the result to replace one.
//
//	cfg, err := polaris.FromEnv(db, apikeys.New(apikeys.Config{}))
func FromEnv(db store.Adapter, plugins ...Plugin) (Config, error) {
	secrets, auth, err := config.FromEnv()
	if err != nil {
		return Config{}, err
	}
	return Config{Secrets: secrets, Auth: auth, DB: db, Plugins: plugins}, nil
}

// Migrate brings the database up to what core and the plugins declare and seeds the permission
// catalog and system roles. On a SQL database it creates the missing tables, adds the columns and
// indexes an existing table lacks and drops the indexes a plugin retired (sqlstore.Store.Migrate);
// it never drops a table or a column and never changes a column's type. Idempotent and safe on
// replicas booting together: run it at every boot. It returns what it changed: the name of each
// table it created, then one "<table>: added column <c>" (or "created index", "dropped index")
// line per change to an existing table.
func (p *Polaris) Migrate(ctx context.Context) ([]string, error) {
	g := p.graph
	changes, err := migrateSchema(ctx, g.DB(), g.Schema())
	if err != nil {
		return nil, err
	}
	if err := authz.Seed(ctx, g.DB(), services.Of(g).Catalog, g.Clock()); err != nil {
		return changes, fmt.Errorf("polaris: migrate: seed permissions: %w", err)
	}
	return changes, nil
}

type schemaMigrator interface {
	Migrate(context.Context, []schema.Model) ([]string, error)
}

// migrateSchema runs the Migrate of db or of an adapter it wraps (Unwrap, as telemetry/otel.Store
// does); an adapter without one may still create its missing tables (CreateMissing).
func migrateSchema(ctx context.Context, db store.Adapter, models []schema.Model) ([]string, error) {
	for a := db; a != nil; {
		if m, ok := a.(schemaMigrator); ok {
			changes, err := m.Migrate(ctx, models)
			if err != nil {
				return nil, fmt.Errorf("polaris: migrate: %w", err)
			}
			return changes, nil
		}
		u, ok := a.(interface{ Unwrap() store.Adapter })
		if !ok {
			break
		}
		a = u.Unwrap()
	}
	if m, ok := db.(interface {
		CreateMissing(context.Context, []schema.Model) ([]string, error)
	}); ok {
		created, err := m.CreateMissing(ctx, models)
		if err != nil {
			return nil, fmt.Errorf("polaris: migrate: %w", err)
		}
		return created, nil
	}
	if db.Dialect() != store.Memory {
		return nil, errors.New("polaris: migrate: the database adapter cannot create tables; export the DDL with `polaris schema:export` and apply it")
	}
	return nil, nil
}

// Prune deletes the expired transient rows Polaris accumulates (refresh tokens past their grace,
// used or expired verification, reset, OTP and invitation rows) and returns how many it deleted per
// table. Schedule it (a cron, a time.Ticker); it is idempotent and safe to run on every replica.
func (p *Polaris) Prune(ctx context.Context) (map[string]int64, error) {
	n, err := maintenance.PruneExpired(ctx, p.graph.DB(), p.graph.Clock().Now(), maintenance.DefaultRefreshGrace)
	if err != nil {
		return n, fmt.Errorf("polaris: prune: %w", err)
	}
	return n, nil
}
