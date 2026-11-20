package username_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/clock"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/model"
	"github.com/univeros/polaris-go/plugins/username"
	"github.com/univeros/polaris-go/repository"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/storetest"
	"github.com/univeros/polaris-go/token"
)

var now = time.Date(2026, 10, 9, 10, 0, 0, 0, time.UTC)

func boot(t *testing.T, cfg username.Config) (*polaris.Polaris, error) {
	t.Helper()
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = "https://issuer.test"
	return polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: strings.Repeat("k", 32), JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: memstore.New(append(schema.Core(), username.Models()...)...), Clock: clock.NewFrozen(now),
		Hasher:  security.Argon2id{Memory: 1024, Time: 1, Threads: 1},
		Plugins: []polaris.Plugin{username.New(cfg)},
	})
}

func mustBoot(t *testing.T, cfg username.Config) *polaris.Polaris {
	t.Helper()
	p, err := boot(t, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func addUser(t *testing.T, p *polaris.Polaris, email string, verified bool) model.User {
	t.Helper()
	hash, err := p.Graph().Hasher().Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	u := model.User{ID: repository.NewID(), Email: email, PasswordHash: &hash, Status: model.UserStatusActive, CreatedAt: now, UpdatedAt: now}
	if verified {
		u.EmailVerifiedAt = &now
	}
	if err := p.Graph().Repos().Users.Insert(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return u
}

type answer struct {
	status int
	body   map[string]any
	ctype  string
}

func call(t *testing.T, p *polaris.Polaris, method, path string, body any, bearer string) answer {
	t.Helper()
	raw, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return answer{w.Code, out, w.Header().Get("Content-Type")}
}

func problem(t *testing.T, a answer, status int, code string) {
	t.Helper()
	if a.status != status || a.body["error"] != code || a.ctype != "application/problem+json" {
		t.Fatalf("want %d %s, got %d %v", status, code, a.status, a.body)
	}
}

func TestPlugin(t *testing.T) {
	t.Run("testEverythingIsWiredThroughTheGraph", func(t *testing.T) {
		p := mustBoot(t, username.Config{})
		g := p.Graph()
		if !slices.ContainsFunc(g.Schema(), func(m schema.Model) bool { return m.Table == username.TableUsernames }) {
			t.Fatal("no table")
		}
		var routes []string
		for _, rt := range g.Manifest().Routes() {
			if slices.Contains(rt.Tags, "username") {
				routes = append(routes, rt.Method+" "+rt.Path+" "+string(rt.Auth)+" "+rt.Name)
			}
		}
		slices.Sort(routes)
		want := []string{"PATCH /username bearer " + username.RouteUpdate, "POST /username/sign-in public " + username.RouteSignIn}
		if !reflect.DeepEqual(routes, want) {
			t.Fatalf("routes %v", routes)
		}
		if username.Of(g) == nil || username.Of(g).ID() != username.ID || username.SentinelRoutes["/username/sign-in"] != "sign_in" {
			t.Fatal("plugin lookup")
		}
	})

	t.Run("testTheRulesComeFromConfiguration", func(t *testing.T) {
		ctx := context.Background()
		def := mustBoot(t, username.Config{}).Graph()
		rules := username.Of(def).Usernames()
		for name, want := range map[string][]string{
			"ada.lovelace": nil,
			"ab":           {"The username must be 3 to 30 characters long."},
			"ada lovelace": {"The username contains characters that are not allowed."},
			"Admin":        {"The username is reserved."},
		} {
			if got := rules.Violations(name); !slices.Equal(got, want) {
				t.Fatalf("%q: %v", name, got)
			}
		}

		usernames := username.Of(mustBoot(t, username.Config{MinLength: 5, MaxLength: 8, Pattern: regexp.MustCompile(`^[a-z]+$`), Reserved: []string{"grace"}}).Graph()).Usernames()
		if rec, err := usernames.Set(ctx, "u1", "admin", ""); err != nil || rec.Username != "admin" {
			t.Fatalf("the configured list replaces the default one: %v %v", rec, err)
		}
		for _, bad := range []string{"abc", "toolongname", "Grace", "ab_cd"} {
			var inv *username.InvalidError
			if _, err := usernames.Set(ctx, "u2", bad, ""); !errors.As(err, &inv) || !errors.Is(err, username.ErrInvalid) || len(inv.Violations) == 0 {
				t.Fatalf("%q: %v", bad, err)
			}
		}
		if _, err := usernames.Set(ctx, "u2", "admin", ""); !errors.Is(err, username.ErrTaken) {
			t.Fatalf("taken: %v", err)
		}
		var inv *username.InvalidError
		if _, err := usernames.Set(ctx, "u1", "admin", "other"); !errors.As(err, &inv) || !slices.Equal(inv.Violations, []string{"The display username must be the username with another case."}) {
			t.Fatalf("display: %v", err)
		}
		if inv.Error() == "" {
			t.Fatal("no message")
		}
	})

	t.Run("testSignInByUsernameOrEmailGoesThroughCoresPasswordPath", func(t *testing.T) {
		ctx := context.Background()
		p := mustBoot(t, username.Config{})
		g := p.Graph()
		ada := addUser(t, p, "ada@example.com", true)
		access, err := g.Sessions().Mint(context.Background(), token.SessionPrincipal{UserID: ada.ID}, "", token.Claims{})
		if err != nil {
			t.Fatal(err)
		}

		if a := call(t, p, http.MethodPatch, "/username", map[string]any{"username": "Ada.L"}, ""); a.status != 401 {
			t.Fatalf("no bearer: %d", a.status)
		}
		set := call(t, p, http.MethodPatch, "/username", map[string]any{"username": "ada.l", "display_username": "Ada.L"}, access)
		if d, _ := set.body["data"].(map[string]any); set.status != 200 || d["username"] != "ada.l" || d["display_username"] != "Ada.L" {
			t.Fatalf("set %v", set)
		}
		problem(t, call(t, p, http.MethodPatch, "/username", map[string]any{"username": "no"}, access), 422, "username_invalid")
		problem(t, call(t, p, http.MethodPatch, "/username", map[string]any{"username": 7}, access), 422, "username_invalid")
		problem(t, call(t, p, http.MethodPatch, "/username", map[string]any{"username": "ada.l", "display_username": 7}, access), 422, "username_invalid")

		for _, id := range []string{"ADA.L", "ada@example.com"} {
			a := call(t, p, http.MethodPost, "/username/sign-in", map[string]any{"username": id, "password": password}, "")
			d, _ := a.body["data"].(map[string]any)
			raw, _ := d["access_token"].(string)
			tok, err := g.Tokens().Parse(raw)
			if a.status != 200 || err != nil || tok.Subject() != ada.ID || !reflect.DeepEqual(tok.Claim("amr"), []any{"pwd"}) {
				t.Fatalf("%s: %v %v", id, a, err)
			}
		}
		unknown := call(t, p, http.MethodPost, "/username/sign-in", map[string]any{"username": "nobody", "password": password}, "")
		wrong := call(t, p, http.MethodPost, "/username/sign-in", map[string]any{"username": "ada.l", "password": "wrong password here"}, "")
		if unknown.status != 401 || wrong.status != 401 || !reflect.DeepEqual(unknown.body, wrong.body) {
			t.Fatal("an unknown username and a wrong password answer the same")
		}
		problem(t, call(t, p, http.MethodPost, "/username/sign-in", map[string]any{"username": "", "password": "x"}, ""), 422, "username_invalid_input")

		email := "ada@example.com"
		if err := g.Repos().MFAFactors.Insert(ctx, model.MFAFactor{ID: repository.NewID(), UserID: ada.ID, Type: "email", Email: &email, IsDefault: true, ConfirmedAt: &now, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
		gated := call(t, p, http.MethodPost, "/username/sign-in", map[string]any{"username": "ada.l", "password": password}, "")
		d, _ := gated.body["data"].(map[string]any)
		if _, has := d["access_token"]; d["mfa_required"] != true || has || len(d["factors"].([]any)) != 1 {
			t.Fatalf("core's MFA gate: %v", gated.body)
		}

		grace := addUser(t, p, "grace@example.com", false)
		if _, err := username.Of(g).Usernames().Set(ctx, grace.ID, "grace", ""); err != nil {
			t.Fatal(err)
		}
		problem(t, call(t, p, http.MethodPost, "/username/sign-in", map[string]any{"username": "grace", "password": password}, ""), 403, "username_email_unverified")
		disabled := grace
		disabled.Status, disabled.EmailVerifiedAt = model.UserStatusDisabled, &now
		if err := g.Repos().Users.Update(ctx, grace, disabled); err != nil {
			t.Fatal(err)
		}
		problem(t, call(t, p, http.MethodPost, "/username/sign-in", map[string]any{"username": "grace", "password": password}, ""), 403, "username_account_disabled")

		// A username whose owner is gone signs in as nobody.
		if err := g.Repos().Users.Delete(ctx, disabled); err != nil {
			t.Fatal(err)
		}
		problem(t, call(t, p, http.MethodPost, "/username/sign-in", map[string]any{"username": "grace", "password": password}, ""), 401, "username_invalid_credentials")
	})

	t.Run("ConfigErrorsFailNew", func(t *testing.T) {
		for _, cfg := range []username.Config{{MinLength: -1}, {MinLength: 10, MaxLength: 5}, {MaxLength: 65}} {
			if _, err := boot(t, cfg); err == nil || !strings.Contains(err.Error(), "username: Config.") {
				t.Fatalf("%+v: %v", cfg, err)
			}
		}
	})
}

// racing lets another user take "grace" right before the first username insert, after the lookup.
type racing struct {
	store.Adapter
	raced bool
}

func (r *racing) Insert(ctx context.Context, table string, row store.Row) error {
	if table == username.TableUsernames && !r.raced {
		r.raced = true
		if err := r.Adapter.Insert(ctx, table, store.Row{"user_id": "u1", "username": "grace", "display_username": "grace", "created_at": now, "updated_at": now}); err != nil {
			return err
		}
	}
	return r.Adapter.Insert(ctx, table, row)
}

// TestUniqueness runs on every storetest backend (memstore, SQLite, PostgreSQL / MySQL when
// configured).
func TestUniqueness(t *testing.T) {
	for _, b := range storetest.Backends() {
		open := func(t *testing.T) store.Adapter { return b.Open(t, append(schema.Core(), username.Models()...)...) }
		t.Run(b.Name, func(t *testing.T) {
			t.Run("testAUsernameIsUniqueWithoutRegardToCase", func(t *testing.T) {
				ctx := context.Background()
				db := open(t)
				u, err := username.NewUsernames(db, clock.NewFrozen(now), username.Config{})
				if err != nil {
					t.Fatal(err)
				}
				ada, err := u.Set(ctx, "u1", "Ada.Lovelace", "")
				if err != nil || ada.Username != "ada.lovelace" || ada.DisplayUsername != "Ada.Lovelace" || !ada.CreatedAt.Equal(now) {
					t.Fatalf("%+v %v", ada, err)
				}
				for _, q := range []string{"ADA.LOVELACE", " ada.lovelace "} {
					if id, _ := u.UserID(ctx, q); id != "u1" {
						t.Fatalf("%q: %q", q, id)
					}
				}
				for _, taken := range []string{"ada.lovelace", "ADA.LOVELACE", "aDa.LoVeLaCe"} {
					if _, err := u.Set(ctx, "u2", taken, ""); !errors.Is(err, username.ErrTaken) {
						t.Fatalf("%q: %v", taken, err)
					}
				}
				if rec, err := u.Set(ctx, "u1", "ADA.lovelace", ""); err != nil || rec.DisplayUsername != "ADA.lovelace" {
					t.Fatalf("the owner changes the case: %+v %v", rec, err)
				}
				err = db.Insert(ctx, username.TableUsernames, store.Row{"user_id": "u3", "username": "ada.lovelace", "display_username": "ADA.LOVELACE", "created_at": now, "updated_at": now})
				if !errors.Is(err, store.ErrDuplicate) {
					t.Fatalf("the unique index must refuse a second row: %v", err)
				}
			})
			t.Run("testTheUniqueIndexDecidesARaceBetweenTheLookupAndTheWrite", func(t *testing.T) {
				ctx := context.Background()
				u, _ := username.NewUsernames(&racing{Adapter: open(t)}, nil, username.Config{})
				if _, err := u.Set(ctx, "u2", "Grace", ""); !errors.Is(err, username.ErrTaken) {
					t.Fatalf("the other writer won: %v", err)
				}
				if id, _ := u.UserID(ctx, "grace"); id != "u1" {
					t.Fatalf("owner %q", id)
				}
			})
		})
	}
}
