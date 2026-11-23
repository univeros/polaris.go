package scim

import (
	"testing"

	"github.com/univeros/polaris.go/model"
)

// The active attribute is the membership's: an account an operator disabled stays disabled whatever
// its directory says.
func TestADirectoryDoesNotUndoAnOperatorsBan(t *testing.T) {
	f := newFixture(t)
	conn := f.connection(f.organization(), DeprovisionDeactivate)
	d, g := f.p.dir, f.srv.Graph()
	bob := must(d.createUser(f.ctx, conn, map[string]any{"userName": "bob@acme.example"}))
	if err := g.Identity().DisableUser(f.ctx, "operator", bob.ID); err != nil {
		t.Fatal(err)
	}
	banned := must(g.Repos().Users.Get(f.ctx, bob.ID))
	for name, got := range map[string]model.User{
		"patch": must(d.patchUser(f.ctx, conn, banned, ops(t, map[string]any{"op": "replace", "path": "active", "value": true}))),
		"put":   must(d.replaceUser(f.ctx, conn, banned, map[string]any{"userName": "bob@acme.example", "active": true})),
	} {
		if got.Status != model.UserStatusDisabled || must(d.active(f.ctx, conn, got)) {
			t.Errorf("%s: %+v", name, got)
		}
	}
}
