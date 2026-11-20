package storetest_test

import (
	"context"
	"testing"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
	"github.com/univeros/polaris.go/store/storetest"
)

func TestRunOnTheReferenceAdapter(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Adapter { return memstore.New(schema.Core()...) })
}

// installing is a memstore that also satisfies storetest.Installer, so Run's install path runs.
type installing struct{ *memstore.Store }

func (i installing) DropSchema(ctx context.Context, models []schema.Model) error {
	for _, m := range models {
		if _, err := i.Delete(ctx, m.Table, nil); err != nil {
			return err
		}
	}
	return nil
}

func (installing) CreateSchema(context.Context, []schema.Model) error { return nil }

func TestRunInstallsTheSchemaOnAnInstaller(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Adapter { return installing{memstore.New(schema.Core()...)} })
}
