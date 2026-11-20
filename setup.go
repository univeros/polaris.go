package polaris

import (
	"context"
	"errors"
	"fmt"
	"github.com/univeros/polaris.go/internal/maintenance"

	"github.com/univeros/polaris.go/authz"
	"github.com/univeros/polaris.go/config"
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

// Migrate creates every table core and the plugins need that the database lacks (never altering or
// dropping an existing one) and seeds the permission catalog and system roles. Idempotent: run it at
// every boot. It returns the tables it created.
func (p *Polaris) Migrate(ctx context.Context) ([]string, error) {
	g := p.graph
	var created []string
	if m, ok := g.DB().(interface {
		CreateMissing(context.Context, []schema.Model) ([]string, error)
	}); ok {
		var err error
		if created, err = m.CreateMissing(ctx, g.Schema()); err != nil {
			return nil, fmt.Errorf("polaris: migrate: %w", err)
		}
	} else if g.DB().Dialect() != store.Memory {
		return nil, errors.New("polaris: migrate: the database adapter cannot create tables; export the DDL with `polaris schema:export` and apply it")
	}
	if err := authz.Seed(ctx, g.DB(), g.Catalog(), g.Clock()); err != nil {
		return created, fmt.Errorf("polaris: migrate: seed permissions: %w", err)
	}
	return created, nil
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
