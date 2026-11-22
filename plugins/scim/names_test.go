package scim

import (
	"reflect"
	"testing"

	"github.com/univeros/polaris.go/store"
)

func nameOf(t *testing.T, f *fixture, conn Connection, userID string) map[string]any {
	t.Helper()
	res := must(f.p.dir.userResource(f.ctx, conn, must(f.srv.Graph().Repos().Users.Get(f.ctx, userID)), "https://x/scim/v2/"+conn.ID))
	return res["name"].(map[string]any)
}

// RFC 7643 §4.1.1: a directory reads back the name parts it sent, so comparing the resource shows
// no difference; a PATCH of one part keeps the other.
func TestTheDirectoryReadsBackTheNamePartsItSent(t *testing.T) {
	f := newFixture(t)
	conn := f.connection(f.organization(), DeprovisionDelete)
	d := f.p.dir
	u := must(d.createUser(f.ctx, conn, map[string]any{"userName": "ada@example.com", "name": map[string]any{"givenName": "Ada", "familyName": "Lovelace"}}))
	if got := nameOf(t, f, conn, u.ID); !reflect.DeepEqual(got, map[string]any{"formatted": "Ada Lovelace", "givenName": "Ada", "familyName": "Lovelace"}) {
		t.Fatalf("created: %v", got)
	}

	u = must(d.patchUser(f.ctx, conn, u, ops(t, map[string]any{"op": "replace", "path": "name.familyName", "value": "Byron"})))
	if got := nameOf(t, f, conn, u.ID); !reflect.DeepEqual(got, map[string]any{"formatted": "Ada Byron", "givenName": "Ada", "familyName": "Byron"}) {
		t.Fatalf("patched: %v", got)
	}

	u = must(d.replaceUser(f.ctx, conn, u, map[string]any{"userName": "ada@example.com", "displayName": "Countess"}))
	if got := nameOf(t, f, conn, u.ID); !reflect.DeepEqual(got, map[string]any{"formatted": "Countess"}) {
		t.Fatalf("a PUT without parts clears them: %v", got)
	}

	u = must(d.replaceUser(f.ctx, conn, u, map[string]any{"userName": "ada@example.com", "name": map[string]any{"givenName": "Ada"}}))
	if _, err := d.deleteUser(f.ctx, conn, u); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.srv.Graph().DB().Count(f.ctx, TableUserNames, store.Criteria{"connection_id": conn.ID}); n != 0 {
		t.Fatalf("%d name rows outlive the user's deletion", n)
	}
}

func TestADirectoryDoesNotStoreNamePartsOfAnAccountItDoesNotOwn(t *testing.T) {
	f, conn, victim, _ := tenants(t)
	d := f.p.dir
	d.domains = func() any { return verifiedDomains{conn.OrganizationID: "victim.example"} }
	linked := must(d.createUser(f.ctx, conn, map[string]any{"userName": victim.Email, "name": map[string]any{"givenName": "Pwned"}}))
	must(d.replaceUser(f.ctx, conn, linked, map[string]any{"userName": victim.Email, "name": map[string]any{"givenName": "Pwned", "familyName": "Again"}}))
	if got := nameOf(t, f, conn, victim.ID); !reflect.DeepEqual(got, map[string]any{"formatted": nil}) {
		t.Fatalf("the account's name is its own: %v", got)
	}
}
