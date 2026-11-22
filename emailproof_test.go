package polaris_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/model"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/token"
	"github.com/univeros/polaris.go/wiring"
)

// accessBeforeProof are the plugin columns naming the user whose rows are ways to act as the
// user: a mailbox's first proof (Identity.ProveEmail) removes them. A plugin table that stores
// such a thing joins the list and implements wiring.AccessEraser.
var accessBeforeProof = []string{
	"polaris_social_account.user_id", "polaris_passkey.user_id", "polaris_api_key.owner_id", "polaris_api_key.created_by",
	"polaris_oauth_consent.user_id", "polaris_oauth_token.user_id", "polaris_oauth_code.user_id",
	"polaris_oauth_device_code.user_id", "polaris_oauth_ciba_request.user_id",
	"polaris_agent.owner_id", "polaris_agent.created_by", "polaris_agent_host.owner_id", "polaris_agent_host.created_by",
	"polaris_passwordless_phone.user_id", "polaris_passwordless_secret.user_id",
}

// unproven is an account nobody proved the mailbox of, holding everything that can act as it: a
// password, a session, an MFA factor and a row in every accessBeforeProof column.
func unproven(t *testing.T, srv *polaristest.Server, email string) (model.User, token.IssuedTokens) {
	t.Helper()
	ctx, g := context.Background(), srv.Graph()
	now := time.Now().UTC().Truncate(time.Second)
	hash := "$argon2id$not-a-real-hash"
	u := model.User{ID: repository.NewID(), Email: email, PasswordHash: &hash, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	ok(t, g.Repos().Users.Insert(ctx, u))
	issued, err := g.Sessions().Issue(ctx, token.SessionPrincipal{UserID: u.ID}, token.ClientContext{})
	ok(t, err)
	ok(t, g.Repos().MFAFactors.Insert(ctx, model.MFAFactor{ID: repository.NewID(), UserID: u.ID, Type: model.FactorTOTP, ConfirmedAt: &now, CreatedAt: now}))
	models := map[string]schema.Model{}
	for _, m := range g.Schema() {
		models[m.Table] = m
	}
	for _, key := range accessBeforeProof {
		table, column, _ := strings.Cut(key, ".")
		extra := store.Row{}
		if column == "owner_id" {
			extra["owner_type"] = "user"
		}
		m, found := models[table]
		if !found {
			t.Fatalf("%s: no such table", key)
		}
		ok(t, g.DB().Insert(ctx, table, sampleRow(m, column, u.ID, extra)))
	}
	return u, issued
}

func accessLeft(t *testing.T, g *wiring.Graph, userID string) (rows, factors int) {
	t.Helper()
	ctx := context.Background()
	for _, key := range accessBeforeProof {
		table, column, _ := strings.Cut(key, ".")
		n, err := g.DB().Count(ctx, table, store.Criteria{column: userID})
		ok(t, err)
		if n != 0 {
			t.Logf("%s: %d row(s)", key, n)
		}
		rows += int(n)
	}
	list, err := g.Repos().MFAFactors.ListByUser(ctx, userID)
	ok(t, err)
	return rows, len(list)
}

// The first proof of a mailbox hands the account to whoever proved it: the password, the factors,
// the sessions and every plugin row that could act as the account go, in one operation.
func TestTheFirstProofOfAMailboxRemovesEveryWayIn(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithPlugins(allPlugins()...))
	ctx, g := context.Background(), srv.Graph()
	u, issued := unproven(t, srv, "claimed@example.com")

	proven, first, err := g.Identity().ProveEmail(ctx, u.ID, false)
	ok(t, err)
	if !first || proven.EmailVerifiedAt == nil || proven.PasswordHash != nil {
		t.Fatalf("first %v, user %+v", first, proven)
	}
	if rows, factors := accessLeft(t, g, u.ID); rows != 0 || factors != 0 {
		t.Errorf("%d plugin row(s) and %d factor(s) outlived the proof", rows, factors)
	}
	if sessions, err := g.Sessions().List(ctx, u.ID, ""); err != nil || len(sessions) != 0 {
		t.Errorf("the session opened before the proof lives: %v %v (%s)", sessions, err, issued.SessionID)
	}

	// What the owner adds afterwards stays: a later proof is not a first one.
	now := time.Now().UTC().Truncate(time.Second)
	ok(t, g.Repos().MFAFactors.Insert(ctx, model.MFAFactor{ID: repository.NewID(), UserID: u.ID, Type: model.FactorTOTP, ConfirmedAt: &now, CreatedAt: now}))
	_, first, err = g.Identity().ProveEmail(ctx, u.ID, false)
	ok(t, err)
	if _, factors := accessLeft(t, g, u.ID); first || factors != 1 {
		t.Errorf("a second proof: first %v, factors %d", first, factors)
	}
}

// The verification message of a registration confirms the registration: an account with a
// password is marked verified and keeps everything; one without a password has nothing to confirm.
func TestConfirmingARegistrationKeepsWhatItsPasswordHolderHas(t *testing.T) {
	srv := polaristest.New(t, polaristest.WithPlugins(allPlugins()...))
	ctx, g := context.Background(), srv.Graph()
	u, _ := unproven(t, srv, "registered@example.com")

	proven, first, err := g.Identity().ProveEmail(ctx, u.ID, true)
	ok(t, err)
	rows, factors := accessLeft(t, g, u.ID)
	sessions, _ := g.Sessions().List(ctx, u.ID, "")
	if !first || proven.EmailVerifiedAt == nil || proven.PasswordHash == nil || rows != len(accessBeforeProof) || factors != 1 || len(sessions) != 1 {
		t.Fatalf("first %v, password kept %v, rows %d, factors %d, sessions %d", first, proven.PasswordHash != nil, rows, factors, len(sessions))
	}

	other, _ := unproven(t, srv, "passwordless@example.com")
	bare := other
	bare.PasswordHash = nil
	ok(t, g.Repos().Users.Update(ctx, other, bare))
	_, first, err = g.Identity().ProveEmail(ctx, other.ID, true)
	ok(t, err)
	if rows, factors := accessLeft(t, g, other.ID); !first || rows != 0 || factors != 0 {
		t.Errorf("no password, nothing to confirm: first %v, rows %d, factors %d", first, rows, factors)
	}
}
