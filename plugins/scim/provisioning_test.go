package scim

// Decision 74: what a directory may vouch for, how long it holds an account, and who may connect
// one.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/identity"
	"github.com/univeros/polaris.go/internal/services"
	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/token"
)

var browser = token.ClientContext{IP: "203.0.113.7", UserAgent: "ua/1"}

func rename(t *testing.T, to string) []operation {
	return ops(t, map[string]any{"op": "replace", "path": "userName", "value": to})
}

// resetToken asks for a password reset of email and returns the token its mailbox receives.
func (f *fixture) resetToken(email string) string {
	f.t.Helper()
	if err := services.Of(f.srv.Graph()).Identity.ForgotPassword(f.ctx, email, browser); err != nil {
		f.t.Fatal(err)
	}
	var reset event.PasswordResetRequested
	for _, e := range f.srv.Events.All() {
		if r, ok := e.(event.PasswordResetRequested); ok && r.Email == email {
			reset = r
		}
	}
	return reset.ResetToken
}

func (f *fixture) reset(email, tok string) error {
	return services.Of(f.srv.Graph()).Identity.ResetPassword(f.ctx, tok, "correct horse battery staple", browser)
}

// A directory vouches for a mailbox only on a domain its organization verified: anywhere else the
// account it creates is unverified, and an account it owns moves to an address only when that
// leaves nobody's mailbox verified on the directory's word alone.
func TestADirectoryVouchesOnlyForItsOrganizationsDomains(t *testing.T) {
	f := newFixture(t)
	conn := f.connection(f.organization(), DeprovisionDeactivate)
	d := f.p.dir
	d.domains = func() any { return verifiedDomains{conn.OrganizationID: "acme.example"} }

	mallory := must(d.createUser(f.ctx, conn, map[string]any{"userName": "mallory@evil.example"}))
	if mallory.EmailVerifiedAt != nil {
		t.Fatal("the directory verified an address outside its organization's domains")
	}
	bob := must(d.createUser(f.ctx, conn, map[string]any{"userName": "bob@acme.example"}))
	if bob.EmailVerifiedAt == nil {
		t.Fatal("an address on the organization's verified domain is the organization's to vouch for")
	}

	// An unverified account moves, and stays unverified.
	moved := must(d.patchUser(f.ctx, conn, mallory, rename(t, "ceo@globex.example")))
	if moved.Email != "ceo@globex.example" || moved.EmailVerifiedAt != nil {
		t.Fatalf("a rename outside the verified domains: %+v", moved)
	}
	// A verified one moves within the verified domains only, and the tokens sent to the address it
	// left die with the move.
	pending := f.resetToken("bob@acme.example")
	_, err := d.patchUser(f.ctx, conn, bob, rename(t, "bob@elsewhere.example"))
	refused(t, err, 403, "a verified account renamed outside the organization's domains")
	_, err = d.replaceUser(f.ctx, conn, bob, map[string]any{"userName": "bob@elsewhere.example"})
	refused(t, err, 403, "the same by PUT")
	robert := must(d.patchUser(f.ctx, conn, bob, rename(t, "robert@acme.example")))
	if robert.Email != "robert@acme.example" || robert.EmailVerifiedAt == nil {
		t.Fatalf("a rename within the verified domain: %+v", robert)
	}
	if err := f.reset("robert@acme.example", pending); !errors.Is(err, identity.ErrInvalidResetToken) {
		t.Fatalf("a reset token sent to the address the account left: %v", err)
	}
	// Onto the verified domain, the organization vouches.
	if in := must(d.patchUser(f.ctx, conn, moved, rename(t, "ceo@acme.example"))); in.EmailVerifiedAt == nil {
		t.Fatalf("a rename onto the verified domain: %+v", in)
	}
}

// The account a directory created stops being the directory's when the mailbox's owner proves it:
// a directory cannot stage an account under an address it controls and then move it, credentials
// and all, onto someone else's.
func TestTheFirstProofOfTheMailboxEndsADirectorysHoldOnTheAccount(t *testing.T) {
	f := newFixture(t)
	conn := f.connection(f.organization(), DeprovisionDeactivate)
	d := f.p.dir
	d.domains = func() any { return verifiedDomains{conn.OrganizationID: "acme.example"} }
	g := f.srv.Graph()

	mallory := must(d.createUser(f.ctx, conn, map[string]any{"userName": "mallory@evil.example"}))
	if err := f.reset("mallory@evil.example", f.resetToken("mallory@evil.example")); err != nil {
		t.Fatal(err)
	}
	mallory = must(g.Repos().Users.Get(f.ctx, mallory.ID))
	if mallory.EmailVerifiedAt == nil || mallory.PasswordHash == nil {
		t.Fatalf("the reset is the first proof: %+v", mallory)
	}
	_, err := d.patchUser(f.ctx, conn, mallory, rename(t, "ceo@globex.example"))
	refused(t, err, 403, "a rename of an account whose mailbox its owner proved")
	if u := must(g.Repos().Users.Get(f.ctx, mallory.ID)); u.Email != "mallory@evil.example" {
		t.Fatalf("the account moved to %s", u.Email)
	}
	if owned := must(f.p.Provisioned(f.ctx, conn.OrganizationID, mallory)); owned {
		t.Fatal("the organization's identity provider still signs the account in")
	}
	if _, member, _ := d.membership(f.ctx, conn, mallory.ID); !member {
		t.Fatal("the membership goes with the directory's hold; it should stay")
	}

	// On the organization's verified domain the directory keeps the account through a reset.
	bob := must(d.createUser(f.ctx, conn, map[string]any{"userName": "bob@acme.example"}))
	if err := f.reset("bob@acme.example", f.resetToken("bob@acme.example")); err != nil {
		t.Fatal(err)
	}
	if owned := must(d.owns(f.ctx, conn, must(g.Repos().Users.Get(f.ctx, bob.ID)))); !owned {
		t.Fatal("the directory lost an account on its organization's domain")
	}
	// Created before the domain was verified, proven later: kept as well.
	eve := must(d.createUser(f.ctx, conn, map[string]any{"userName": "eve@acme.example"}))
	must(g.DB().Update(f.ctx, "auth_users", map[string]any{"id": eve.ID}, map[string]any{"email_verified_at": nil}))
	if _, first, err := g.Identity().ProveEmail(f.ctx, eve.ID, false); err != nil || !first {
		t.Fatalf("first proof: %v %v", first, err)
	}
	if owned := must(d.owns(f.ctx, conn, must(g.Repos().Users.Get(f.ctx, eve.ID)))); !owned {
		t.Fatal("a first proof on the organization's domain ended the directory's hold")
	}
}

// call is one JSON request to the server: the status and the decoded data.
func (f *fixture) call(method, path, bearer string, body map[string]any) (int, map[string]any) {
	f.t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if d, ok := out["data"].(map[string]any); ok {
		out = d
	}
	return w.Code, out
}

// account registers, verifies and signs in an account over HTTP: its id and access token.
func (f *fixture) account(email string) (string, string) {
	f.t.Helper()
	const pw = "correct horse battery staple"
	f.call(http.MethodPost, "/auth/register", "", map[string]any{"email": email, "password": pw})
	var reg event.UserRegistered
	for _, e := range f.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok && r.Email == email {
			reg = r
		}
	}
	f.call(http.MethodPost, "/auth/email/verify", "", map[string]any{"token": reg.VerificationToken})
	code, body := f.call(http.MethodPost, "/auth/login", "", map[string]any{"email": email, "password": pw})
	access, _ := body["access_token"].(string)
	if code != 200 || access == "" {
		f.t.Fatalf("login %s: %d %v", email, code, body)
	}
	return reg.UserID, access
}

func (f *fixture) switchTo(access, organizationID string) string {
	f.t.Helper()
	code, body := f.call(http.MethodPost, "/auth/switch-org", access, map[string]any{"organization_id": organizationID})
	switched, _ := body["access_token"].(string)
	if code != 200 || switched == "" {
		f.t.Fatalf("switch-org: %d %v", code, body)
	}
	return switched
}

// A directory puts members into any role of its organization, the owners' included, so its token
// goes only to someone who could grant every one of them by hand.
func TestADirectoryIsConnectedOnlyByWhoCouldGrantEveryRole(t *testing.T) {
	f := newFixture(t)
	g := f.srv.Graph()
	_, ownerAccess := f.account("owner@acme.example")
	_, org := f.call(http.MethodPost, "/orgs", ownerAccess, map[string]any{"name": "Acme"})
	acme, _ := org["id"].(string)
	owner := f.switchTo(ownerAccess, acme)

	adminID, adminAccess := f.account("admin@acme.example")
	now := time.Now().UTC().Truncate(time.Second)
	m := model.Membership{ID: repository.NewID(), UserID: adminID, OrganizationID: acme, Status: model.MembershipStatusActive,
		JoinedAt: &now, CreatedAt: now, UpdatedAt: now}
	if err := g.Repos().Memberships.Insert(f.ctx, m); err != nil {
		t.Fatal(err)
	}
	role := must(g.Repos().Roles.ByOrganizationAndSlug(f.ctx, &acme, "admin"))
	if err := g.Repos().MembershipRoles.Insert(f.ctx, model.MembershipRole{MembershipID: m.ID, RoleID: role.ID}); err != nil {
		t.Fatal(err)
	}
	admin := f.switchTo(adminAccess, acme)

	path := "/orgs/" + acme + "/scim/connections"
	if code, body := f.call(http.MethodGet, path, admin, nil); code != 200 {
		t.Fatalf("an administrator reads the connections: %d %v", code, body)
	}
	if code, body := f.call(http.MethodPost, path, admin, map[string]any{"name": "Mine"}); code != 403 {
		t.Fatalf("an administrator obtained a directory token: %d %v", code, body)
	}
	code, created := f.call(http.MethodPost, path, owner, map[string]any{"name": "Okta"})
	id, _ := created["id"].(string)
	if code != 201 || created["token"] == nil {
		t.Fatalf("the owner connects a directory: %d %v", code, created)
	}
	if code, body := f.call(http.MethodPost, path+"/"+id+"/rotate", admin, nil); code != 403 {
		t.Fatalf("an administrator rotated the directory's token to themselves: %d %v", code, body)
	}
	if code, body := f.call(http.MethodPost, path+"/"+id+"/rotate", owner, nil); code != 200 || body["token"] == nil {
		t.Fatalf("the owner rotates: %d %v", code, body)
	}
}

// Deprovisioning an account nobody proved frees its address, whatever the connection's mode (RFC 7644
// §3.6: a deleted User is not a conflict for a new one).
func TestADeprovisionedAccountNobodyProvedFreesItsAddress(t *testing.T) {
	f := newFixture(t)
	orgID := f.organization()
	conn := f.connection(orgID, DeprovisionDeactivate)
	d := f.p.dir
	g := f.srv.Graph()
	id := services.Of(g).Identity
	const email = "sam@globex.example"

	created := must(d.createUser(f.ctx, conn, map[string]any{"userName": email}))
	if outcome := must(d.deleteUser(f.ctx, conn, created)); outcome != "deleted" {
		t.Fatalf("outcome %q", outcome)
	}
	if u, err := g.Repos().Users.ByEmail(f.ctx, email); err == nil {
		t.Fatalf("the address is held by %s (%s)", u.ID, u.Status)
	}
	if _, member, _ := d.membership(f.ctx, conn, created.ID); member {
		t.Fatal("the membership stays")
	}
	again := must(d.createUser(f.ctx, conn, map[string]any{"userName": email})) // the directory itself may create it again
	if again.ID == created.ID {
		t.Fatal("the erased account came back")
	}
	must(d.deleteUser(f.ctx, conn, again))

	// The mailbox's owner registers, verifies and signs in.
	if err := id.Register(f.ctx, email, "correct horse battery staple", "", browser); err != nil {
		t.Fatal(err)
	}
	var reg event.UserRegistered
	for _, e := range f.srv.Events.All() {
		if r, ok := e.(event.UserRegistered); ok && r.Email == email {
			reg = r
		}
	}
	if err := id.VerifyEmail(f.ctx, reg.VerificationToken); err != nil {
		t.Fatalf("the owner cannot verify the address: %v", err)
	}
	if _, err := id.Login(f.ctx, email, "correct horse battery staple", browser); err != nil {
		t.Fatalf("the owner cannot sign in: %v", err)
	}

	// An account the directory does not own is left as it is, its row unwritten.
	f.user("u-linked", "linked@acme.example")
	if err := g.Repos().Memberships.Insert(f.ctx, model.Membership{ID: repository.NewID(), UserID: "u-linked", OrganizationID: orgID,
		Status: model.MembershipStatusActive, CreatedAt: time.Now().UTC().Truncate(time.Second), UpdatedAt: time.Now().UTC().Truncate(time.Second)}); err != nil {
		t.Fatal(err)
	}
	linked := must(g.Repos().Users.Get(f.ctx, "u-linked"))
	must(d.deleteUser(f.ctx, conn, linked))
	if after := must(g.Repos().Users.Get(f.ctx, "u-linked")); !reflect.DeepEqual(after, linked) {
		t.Fatalf("an account the directory does not own: %+v, was %+v", after, linked)
	}

	// On a domain the organization verified the account is proven: deactivating keeps it, disabled.
	d.domains = func() any { return verifiedDomains{orgID: "acme.example"} }
	bob := must(d.createUser(f.ctx, conn, map[string]any{"userName": "bob@acme.example"}))
	if outcome := must(d.deleteUser(f.ctx, conn, bob)); outcome != "deactivated" {
		t.Fatalf("outcome %q", outcome)
	}
	if u := must(g.Repos().Users.Get(f.ctx, bob.ID)); u.Email != "bob@acme.example" || u.Status != model.UserStatusDisabled {
		t.Fatalf("a proven account: %+v", u)
	}
}

// Deprovisioning works on the account as it is when it runs: an account proven since the directory
// read it is not erased, and the last active owner is not either.
func TestErasingADeprovisionedAccountChecksItAgain(t *testing.T) {
	for _, mode := range []string{DeprovisionDeactivate, DeprovisionDelete} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			orgID := f.organization()
			conn := f.connection(orgID, mode)
			d := f.p.dir
			g := f.srv.Graph()
			read := must(d.createUser(f.ctx, conn, map[string]any{"userName": "eve@globex.example"}))
			if _, first, err := g.Identity().ProveEmail(f.ctx, read.ID, false); err != nil || !first {
				t.Fatal(first, err)
			}
			must(d.deleteUser(f.ctx, conn, read)) // read before the proof
			u := must(g.Repos().Users.Get(f.ctx, read.ID))
			if u.Email != "eve@globex.example" || u.Status != model.UserStatusActive || u.EmailVerifiedAt == nil {
				t.Fatalf("the directory reached an account its owner proved: %+v", u)
			}
			if _, member, _ := d.membership(f.ctx, conn, u.ID); member {
				t.Fatal("the membership stays")
			}

			// The only active owner, created by the directory.
			boss := must(d.createUser(f.ctx, conn, map[string]any{"userName": "boss@globex.example"}))
			ownerRole := must(g.Repos().Roles.ByOrganizationAndSlug(f.ctx, &orgID, "owner"))
			must(d.replaceGroup(f.ctx, conn, ownerRole, map[string]any{"displayName": ownerRole.Name, "members": []any{map[string]any{"value": boss.ID}}}))
			_, err := d.deleteUser(f.ctx, conn, boss)
			refused(t, err, 409, "erasing the last active owner")
			if u := must(g.Repos().Users.Get(f.ctx, boss.ID)); u.Email != "boss@globex.example" || u.Status != model.UserStatusActive {
				t.Fatalf("the refused erasure changed the account: %+v", u)
			}
		})
	}
}

// A registration's confirmation ends a directory's hold like any other first proof.
func TestAConfirmedRegistrationEndsADirectorysHold(t *testing.T) {
	f := newFixture(t)
	conn := f.connection(f.organization(), DeprovisionDeactivate)
	d := f.p.dir
	g := f.srv.Graph()
	ada := must(d.createUser(f.ctx, conn, map[string]any{"userName": "ada@globex.example"}))
	if err := g.Identity().SetPassword(f.ctx, ada.ID, "correct horse battery staple"); err != nil { // an operator's
		t.Fatal(err)
	}
	if _, first, err := g.Identity().ProveEmail(f.ctx, ada.ID, true); err != nil || !first {
		t.Fatal(first, err)
	}
	ada = must(g.Repos().Users.Get(f.ctx, ada.ID))
	if ada.PasswordHash == nil {
		t.Fatal("confirming a registration keeps its password")
	}
	if owned := must(d.owns(f.ctx, conn, ada)); owned {
		t.Fatal("the directory still owns the account")
	}
	if held := must(f.p.Provisioned(f.ctx, conn.OrganizationID, ada)); held {
		t.Fatal("the organization's identity provider still signs the account in")
	}
}
