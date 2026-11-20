package scim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/plugins/admin"
	"github.com/univeros/polaris.go/plugins/audit"
	"github.com/univeros/polaris.go/polaristest"
	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
)

func TestEmailAndNameOfABody(t *testing.T) {
	for _, c := range []struct {
		body map[string]any
		want string
	}{
		{map[string]any{"userName": " Ada@Example.com "}, "ada@example.com"},
		{map[string]any{"emails": []any{map[string]any{"value": "a@example.com"}, map[string]any{"value": "b@example.com", "primary": true},
			map[string]any{"value": "c@example.com"}}}, "b@example.com"},
		{map[string]any{"userName": " ", "emails": []any{"x", map[string]any{"value": "a@example.com"}, map[string]any{"value": "c@example.com"}}}, "c@example.com"},
	} {
		if got, err := emailOf(c.body); got != c.want || err != nil {
			t.Fatalf("%v: %q %v", c.body, got, err)
		}
	}
	if _, err := emailOf(map[string]any{}); err == nil {
		t.Fatal("no email accepted")
	}
	long := strings.Repeat("é", 70)
	for body, want := range map[string]string{
		`{"displayName": " Ada "}`:                            "Ada",
		`{"name": {"formatted": "Ada L."}}`:                   "Ada L.",
		`{"name": {"givenName": "Ada"}}`:                      "Ada",
		`{"name": {"familyName": "Lovelace"}}`:                "Lovelace",
		`{"displayName": "` + long + `"}`:                     strings.Repeat("é", 60),
		`{"displayName": "` + strings.Repeat("a", 130) + `"}`: strings.Repeat("a", 120),
	} {
		var b map[string]any
		_ = json.Unmarshal([]byte(body), &b)
		if got := displayNameOf(b); got == nil || *got != want {
			t.Fatalf("%s: %v", body, got)
		}
	}
	if displayNameOf(map[string]any{"displayName": " "}) != nil {
		t.Fatal("a blank name")
	}
}

func TestNumbersOfAQuery(t *testing.T) {
	for v, want := range map[any]int{"12": 12, " 3 ": 3, "1e2": 100, "2.9": 2, json.Number("7"): 7, "-4": -4} {
		if got, ok := numeric(v); !ok || got != want {
			t.Fatalf("numeric(%v) = %d %v", v, got, ok)
		}
	}
	for _, v := range []any{"abc", "0x1A", "inf", "", true, nil} {
		if _, ok := numeric(v); ok {
			t.Fatalf("numeric(%v) accepted", v)
		}
	}
	in := func(q string) *endpoint.Input {
		return endpoint.NewInput(httptest.NewRequest(http.MethodGet, "/?"+q, nil), nil)
	}
	if startIndex(in("startIndex=-3")) != 1 || startIndex(in("startIndex=x")) != 1 || count(in("count=500")) != MaxCount ||
		count(in("count=-1")) != 0 || count(in("")) != defaultCount {
		t.Fatal("startIndex / count bounds")
	}
	for v, want := range map[any]int{nil: DefaultLimit, "": DefaultLimit, "5": 5} {
		if got, ok := positiveInt(v, DefaultLimit); !ok || got != want {
			t.Fatalf("positiveInt(%v) = %d", v, got)
		}
	}
	for _, v := range []any{"0", "x", 3.5} {
		if _, ok := positiveInt(v, DefaultLimit); ok {
			t.Fatalf("positiveInt(%v) accepted", v)
		}
	}
}

// ssoStub stands for the sso plugin: its providers table.
type ssoStub struct{}

func (ssoStub) ID() string { return "sso" }
func (ssoStub) Schema() []schema.Model {
	return []schema.Model{schema.Table(ssoProviders, schema.StringField("id", 36).AsPrimary(), schema.StringField("organizationId", 36))}
}

func TestAConnectionPairsWithTheOrganizationsSSOProviders(t *testing.T) {
	ctx := context.Background()
	p := New(Config{})
	srv := polaristest.New(t, polaristest.WithPlugins(audit.New(audit.Config{}), admin.New(admin.Config{}), ssoStub{}, p))
	if err := srv.DB.Insert(ctx, ssoProviders, store.Row{"id": "p1", "organization_id": "org-1"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		provider, org string
		want          bool
	}{{"p1", "org-1", true}, {"p1", "org-2", false}, {"nope", "org-1", false}} {
		if got, err := p.ssoProviderOf(ctx, c.provider, c.org); got != c.want || err != nil {
			t.Fatalf("%v: %v %v", c, got, err)
		}
	}
	if (&Error{Detail: "x"}).Error() != "scim: x" || (Event{Name: AuditUserCreated}).EventName() != AuditUserCreated {
		t.Fatal("strings")
	}
}
