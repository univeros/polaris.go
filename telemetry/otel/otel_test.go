package otel_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	polaris "github.com/univeros/polaris-go"
	"github.com/univeros/polaris-go/cli"
	"github.com/univeros/polaris-go/config"
	"github.com/univeros/polaris-go/event"
	"github.com/univeros/polaris-go/internal/contracttest"
	"github.com/univeros/polaris-go/polaristest"
	"github.com/univeros/polaris-go/schema"
	"github.com/univeros/polaris-go/security"
	"github.com/univeros/polaris-go/store"
	"github.com/univeros/polaris-go/store/memstore"
	"github.com/univeros/polaris-go/store/sqlstore"
	polarisotel "github.com/univeros/polaris-go/telemetry/otel"
)

// providers returns an SDK tracer provider recording into an in-memory exporter and a meter
// provider read by a manual reader.
func providers(t *testing.T) (*tracetest.InMemoryExporter, *sdktrace.TracerProvider, *sdkmetric.ManualReader, *sdkmetric.MeterProvider) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
	})
	return exp, tp, reader, mp
}

func attrs(kvs []attribute.KeyValue) map[string]string {
	m := map[string]string{}
	for _, kv := range kvs {
		m[string(kv.Key)] = kv.Value.String()
	}
	return m
}

func spanNamed(t *testing.T, spans tracetest.SpanStubs, name string) tracetest.SpanStub {
	t.Helper()
	for _, s := range spans {
		if s.Name == name {
			return s
		}
	}
	var names []string
	for _, s := range spans {
		names = append(names, s.Name)
	}
	t.Fatalf("no span %q in %v", name, names)
	return tracetest.SpanStub{}
}

// signIn registers, verifies and logs in a user; it returns the access token.
func signIn(t *testing.T, srv *polaristest.Server, c *contracttest.Client, email, password string) string {
	t.Helper()
	c.Post("/auth/register", map[string]any{"email": email, "password": password})
	sent := srv.Mailer.Sent()
	c.Post("/auth/email/verify", map[string]any{"token": sent[len(sent)-1].Data["token"]})
	login := contracttest.JSON(t, c.Post("/auth/login", map[string]any{"email": email, "password": password}))
	data, ok := login["data"].(map[string]any)
	if !ok {
		t.Fatalf("login: %v", login)
	}
	return data["access_token"].(string)
}

func TestMiddleware(t *testing.T) {
	exp, tp, reader, mp := providers(t)
	key := []byte("0123456789abcdef0123456789abcdef")
	srv := polaristest.New(t)
	c := contracttest.NewClient(t, polarisotel.Middleware(srv.Handler(),
		polarisotel.WithTracerProvider(tp), polarisotel.WithMeterProvider(mp), polarisotel.WithUserIDHash(key)), nil)

	const email, password = "ada@example.com", "correct horse battery staple"
	access := signIn(t, srv, c, email, password)
	me := contracttest.JSON(t, c.Get("/auth/me", contracttest.Bearer(access)))
	userID := me["data"].(map[string]any)["id"].(string)
	c.Get("/no/such/route")

	spans := exp.GetSpans()
	loginSpan := attrs(spanNamed(t, spans, "polaris.auth.login").Attributes)
	if loginSpan["polaris.route"] != "polaris.auth.login" || loginSpan["http.response.status_code"] != "200" {
		t.Errorf("login span attributes: %v", loginSpan)
	}
	if _, ok := loginSpan["polaris.principal.kind"]; ok {
		t.Errorf("login is unauthenticated, got a principal kind: %v", loginSpan)
	}
	meSpan := attrs(spanNamed(t, spans, "polaris.auth.me").Attributes)
	m := hmac.New(sha256.New, key)
	m.Write([]byte(userID))
	if meSpan["polaris.principal.kind"] != "user" || meSpan["enduser.pseudo.id"] != hex.EncodeToString(m.Sum(nil)[:16]) {
		t.Errorf("me span attributes: %v", meSpan)
	}
	if s := spanNamed(t, spans, "GET"); attrs(s.Attributes)["http.response.status_code"] != "404" {
		t.Errorf("unrouted span: %v", attrs(s.Attributes))
	}
	for _, s := range spans {
		for k, v := range attrs(s.Attributes) {
			if strings.Contains(v, email) || strings.Contains(v, access) || strings.Contains(v, password) || v == userID {
				t.Errorf("span %s leaks a secret or identifier in %s=%q", s.Name, k, v)
			}
		}
	}

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	routes := map[string]string{}
	for _, sm := range rm.ScopeMetrics {
		for _, met := range sm.Metrics {
			if met.Name != "http.server.request.duration" {
				continue
			}
			for _, dp := range met.Data.(metricdata.Histogram[float64]).DataPoints {
				a := attrs(dp.Attributes.ToSlice())
				routes[a["polaris.route"]] = a["polaris.principal.kind"]
			}
		}
	}
	if kind, ok := routes["polaris.auth.me"]; !ok || kind != "user" {
		t.Errorf("duration histogram labels: %v", routes)
	}
	if _, ok := routes["polaris.auth.login"]; !ok {
		t.Errorf("duration histogram lacks the login route: %v", routes)
	}
}

func TestMiddlewareOnProtect(t *testing.T) {
	exp, tp, _, mp := providers(t)
	srv := polaristest.New(t)
	mux := http.NewServeMux()
	mux.Handle("/", srv.Handler())
	mux.Handle("GET /hello", srv.Protect(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	})))
	c := contracttest.NewClient(t, polarisotel.Middleware(mux, polarisotel.WithTracerProvider(tp), polarisotel.WithMeterProvider(mp)), nil)
	const email, password = "bob@example.com", "correct horse battery staple"
	c.Get("/hello", contracttest.Bearer(signIn(t, srv, c, email, password)))

	s := attrs(spanNamed(t, exp.GetSpans(), "GET /hello").Attributes)
	if s["polaris.principal.kind"] != "user" || s["http.response.status_code"] != "200" {
		t.Errorf("protected host route span: %v", s)
	}
	if _, ok := s["enduser.pseudo.id"]; ok {
		t.Error("user id recorded without WithUserIDHash")
	}
}

// failingInsert reports a duplicate whose message quotes the value, as drivers do.
type failingInsert struct{ store.Adapter }

func (failingInsert) Insert(context.Context, string, store.Row) error {
	return fmt.Errorf("Key (email)=(ada@example.com) already exists: %w", store.ErrDuplicate)
}

func TestStore(t *testing.T) {
	exp, tp, _, _ := providers(t)
	ctx := context.Background()
	db := polarisotel.Store(failingInsert{memstore.New(schema.Core()...)}, polarisotel.WithTracerProvider(tp))
	if db.Dialect() != store.Memory {
		t.Fatalf("dialect %s", db.Dialect())
	}
	err := db.Tx(ctx, func(ctx context.Context) error {
		if _, err := db.FindMany(ctx, "auth_users", store.Criteria{"email": "ada@example.com"}, store.Query{}); err != nil {
			return err
		}
		if _, err := db.Update(ctx, "auth_users", store.Criteria{"id": "nobody"}, store.Data{"name": "x"}); err != nil {
			return err
		}
		return db.Insert(ctx, "auth_users", store.Row{"email": "ada@example.com"})
	})
	if !errors.Is(err, store.ErrDuplicate) {
		t.Fatalf("Tx: %v", err)
	}
	_, _ = db.FindOne(ctx, "auth_users", store.Criteria{"id": "nobody"})
	_, _ = db.Count(ctx, "auth_users", nil)
	_, _ = db.Delete(ctx, "auth_users", store.Criteria{"id": "nobody"})

	spans := exp.GetSpans()
	tx := spanNamed(t, spans, "tx")
	if tx.Status.Code != codes.Error {
		t.Errorf("tx status %v", tx.Status)
	}
	insert := spanNamed(t, spans, "insert auth_users")
	if insert.Parent.SpanID() != tx.SpanContext.SpanID() {
		t.Error("insert is not a child of the transaction span")
	}
	if a := attrs(insert.Attributes); a["error.type"] != "duplicate" || insert.Status.Description != "" || len(insert.Events) != 0 {
		t.Errorf("insert span: %v %v %v", a, insert.Status, insert.Events)
	}
	want := map[string]map[string]string{
		"find_many auth_users": {"db.response.returned_rows": "0", "db.operation.name": "find_many"},
		"update auth_users":    {"polaris.db.rows_affected": "0"},
		"find_one auth_users":  {"db.response.returned_rows": "0", "db.collection.name": "auth_users"},
		"count auth_users":     {"db.system.name": "memory"},
		"delete auth_users":    {"polaris.db.rows_affected": "0"},
	}
	for name, kv := range want {
		got := attrs(spanNamed(t, spans, name).Attributes)
		for k, v := range kv {
			if got[k] != v {
				t.Errorf("%s: %s=%q, want %q", name, k, got[k], v)
			}
		}
	}
	for _, s := range spans {
		for k, v := range attrs(s.Attributes) {
			if strings.Contains(v, "ada@") || strings.Contains(v, "nobody") {
				t.Errorf("span %s records a value in %s=%q", s.Name, k, v)
			}
		}
	}
}

// TestStoreOverSQL checks a wrapped sqlstore still migrates (CreateMissing) and still serves the
// CLI's schema commands (Unwrap).
func TestStoreOverSQL(t *testing.T) {
	ctx := context.Background()
	raw, err := sqlstore.Open(ctx, store.SQLite, "file:"+filepath.Join(t.TempDir(), "o.db")+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = raw.DB().Close() })
	db := polarisotel.Store(raw)
	if db.(interface{ Unwrap() store.Adapter }).Unwrap() != raw {
		t.Fatal("Unwrap")
	}
	private, public := contracttest.TestRSAKeyPEM()
	auth := config.Defaults()
	auth.Issuer = contracttest.Issuer
	p, err := polaris.New(polaris.Config{
		Secrets: config.Secrets{AppKey: contracttest.AppKey, JWTPrivateKey: private, JWTPublicKey: public},
		Auth:    auth, DB: db, Hasher: security.Argon2id{Memory: 1024, Time: 1, Threads: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created, err := p.Migrate(ctx); err != nil || len(created) == 0 {
		t.Fatalf("Migrate through the wrapper: %v %v", created, err)
	}
	var out, errb strings.Builder
	if code := cli.Run(ctx, p, []string{"schema:diff"}, &out, &errb); code != 0 {
		t.Fatalf("schema:diff over a wrapped store: exit %d\n%s%s", code, out.String(), errb.String())
	}
}

func TestListener(t *testing.T) {
	_, _, reader, mp := providers(t)
	l, err := polarisotel.Listener(polarisotel.WithMeterProvider(mp))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, e := range []event.Event{
		event.UserLoggedIn{UserID: "u"}, event.UserLoggedIn{UserID: "u"},
		event.UserLoginFailed{UserID: "u"},
		event.RefreshReuseDetected{UserID: "u"},
		event.MFAVerifyFailed{UserID: "u"}, event.OTPVerifyFailed{UserID: "u"},
		event.RoleCreated{}, // not an outcome
		named("agent.executed"), named("agent.execution_denied"), named("agent.registered"),
	} {
		l(ctx, e)
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, met := range sm.Metrics {
			if met.Name != polarisotel.MetricAuthOutcomes {
				continue
			}
			for _, dp := range met.Data.(metricdata.Sum[int64]).DataPoints {
				v, _ := dp.Attributes.Value(polarisotel.AttrOutcome)
				got[v.AsString()] = dp.Value
			}
		}
	}
	want := map[string]int64{"login_succeeded": 2, "login_failed": 1, "refresh_reuse": 1, "mfa_failed": 2, "agent_executed": 1, "agent_denied": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("outcomes %v, want %v", got, want)
	}
}

type named string

func (n named) EventName() string { return string(n) }
