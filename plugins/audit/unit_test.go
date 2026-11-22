package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/cache"
	"github.com/univeros/polaris.go/clock"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/security"
	"github.com/univeros/polaris.go/store/memstore"
)

var ctx = context.Background()

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

// spy records what it receives.
type spy struct{ events []Event }

func (s *spy) Write(_ context.Context, events ...Event) error {
	s.events = append(s.events, events...)
	return nil
}

func TestTheCatalogIsClosedAndExtensible(t *testing.T) {
	c, err := NewCatalog()
	if err != nil || !c.Has(UserSignedUp) || c.Has("billing.invoice_paid") || c.Types()[0].Description != "A user registered" {
		t.Fatalf("core catalog: %v", err)
	}
	c, err = NewCatalog(map[string]string{"billing.invoice_paid": "An invoice was paid"})
	if err != nil || !c.Has("billing.invoice_paid") || c.Names()[len(c.Names())-1] != "billing.invoice_paid" || c.Check("billing.invoice_paid") != nil {
		t.Fatalf("extended: %v", err)
	}
	if _, err := NewCatalog(map[string]string{UserSignedUp: "again"}); err == nil || !strings.Contains(err.Error(), "core audit event") {
		t.Fatalf("core names are closed: %v", err)
	}
	if _, err := NewCatalog(map[string]string{"Bad Name": "x"}); err == nil || !strings.Contains(err.Error(), "not a valid audit event name") {
		t.Fatalf("names are namespace.past_tense: %v", err)
	}
	if err := c.Check("nope.nothing"); !errors.Is(err, ErrUnknownName) {
		t.Fatalf("unknown: %v", err)
	}
	if len(coreNames) != 34 {
		t.Fatalf("core has %d names", len(coreNames))
	}
}

func TestSecretsAreRedactedAtAnyDepthAndByMarker(t *testing.T) {
	data := map[string]any{
		"email":       "ada@example.com",
		"password":    "hunter2",
		"reset_token": "abc",
		"nested":      map[string]any{"otp_code": "123456", "kept": 1, "client_secret": "x"},
		"list":        []any{Sensitive{"y"}, map[string]any{"Token": "z"}},
		"answer":      Sensitive{"my dog"},
		"count":       3,
	}
	want := map[string]any{
		"email":       "ada@example.com",
		"password":    Redacted,
		"reset_token": Redacted,
		"nested":      map[string]any{"otp_code": Redacted, "kept": 1, "client_secret": Redacted},
		"list":        []any{Redacted, map[string]any{"Token": Redacted}},
		"answer":      Redacted,
		"count":       3,
	}
	if got := Redact(data); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	if data["password"] != "hunter2" {
		t.Fatal("the input was mutated")
	}
	if s := (Sensitive{"x"}); s.String() != Redacted || s.GoString() != Redacted {
		t.Fatal("Sensitive leaks through fmt")
	}
}

func newRecorder(t *testing.T, sink Sink, extra ...map[string]string) *Recorder {
	t.Helper()
	c, err := NewCatalog(extra...)
	if err != nil {
		t.Fatal(err)
	}
	return NewRecorder(c, sink, clock.NewFrozen(at("2026-09-11T10:00:00Z")), nil)
}

func strp(s string) *string { return &s }

func TestCoreEventsBecomeCataloguedEventsWithActorSubjectAndContext(t *testing.T) {
	s := &spy{}
	r := newRecorder(t, s)
	r.Listen(ctx, event.UserRegistered{UserID: "u1", Email: "ada@example.com", VerificationToken: "verification-token"})
	r.Listen(ctx, event.UserLoggedIn{UserID: "u1", SessionID: "s1", IP: strp("203.0.113.7"), UserAgent: strp("Mozilla/5.0"), AMR: []string{"pwd", "otp"}})
	r.Listen(ctx, event.UserDisabled{UserID: "u1", ActorUserID: "admin1"})
	r.Listen(ctx, event.MemberInvited{OrganizationID: "org1", Email: "newhire@example.test", InvitedBy: "owner1", InviteToken: "invite-token"})
	r.Listen(ctx, unrelated{})
	if len(s.events) != 4 {
		t.Fatalf("%d events", len(s.events))
	}
	up, in, dis, inv := s.events[0], s.events[1], s.events[2], s.events[3]
	if up.Name != UserSignedUp || up.ActorID != "u1" || up.ActorType != ActorUser || up.SubjectID != "u1" || !reflect.DeepEqual(up.Data, map[string]any{"email": "ada@example.com"}) {
		t.Fatalf("signed up %+v", up)
	}
	if up.Map()["occurred_at"] != "2026-09-11T10:00:00Z" {
		t.Fatalf("occurred_at %v", up.Map()["occurred_at"])
	}
	if in.Name != SessionSignedIn || in.SessionID != "s1" || in.IP != "203.0.113.7" || in.UserAgent != "Mozilla/5.0" || !reflect.DeepEqual(in.Data["amr"], []string{"pwd", "otp"}) {
		t.Fatalf("signed in %+v", in)
	}
	if dis.Name != UserDisabled || dis.ActorID != "admin1" || dis.SubjectID != "u1" {
		t.Fatalf("disabled %+v", dis)
	}
	if inv.Name != OrgMemberInvited || inv.ActorID != "owner1" || inv.OrganizationID != "org1" || !reflect.DeepEqual(inv.Data, map[string]any{"email": "newhire@example.test"}) {
		t.Fatalf("invited %+v", inv)
	}
}

func TestEveryCoreEventMapsToACatalogName(t *testing.T) {
	c, _ := NewCatalog()
	one := 1
	until := at("2026-09-11T10:00:00Z")
	events := []event.Event{
		event.UserRegistered{}, event.UserEmailVerified{}, event.UserLoggedIn{}, event.UserLoginFailed{},
		event.UserLocked{Until: &until}, event.PasswordChanged{}, event.PasswordResetRequested{}, event.UserDisabled{},
		event.UserEnabled{}, event.UserDeleted{}, event.TokenRefreshed{}, event.RefreshReuseDetected{},
		event.SessionsRevoked{}, event.OrganizationSwitched{}, event.MFAEnrolled{}, event.MFAFactorRemoved{},
		event.MFAVerified{}, event.MFAVerifyFailed{}, event.OTPVerifyFailed{AttemptsLeft: &one}, event.MFAStepUpCompleted{},
		event.OTPChallengeSent{}, event.MFARecoveryRegenerated{}, event.MFARecoveryUsed{}, event.OrganizationCreated{},
		event.OrganizationUpdated{}, event.OrganizationDeleted{}, event.RoleCreated{}, event.RoleUpdated{},
		event.RoleDeleted{}, event.MemberInvited{}, event.MemberJoined{}, event.MemberRolesChanged{},
		event.MemberStatusChanged{}, event.MemberRemoved{},
	}
	for _, ev := range events {
		e, ok := mapCore(ev)
		if !ok || !c.Has(e.Name) {
			t.Errorf("%s maps to %q", ev.EventName(), e.Name)
		}
	}
}

// unrelated is an event the recorder ignores.
type unrelated struct{}

func (unrelated) EventName() string { return "other.thing" }

// invoicePaid is an Auditable event of another package.
type invoicePaid struct{}

func (invoicePaid) EventName() string { return "billing.invoice_paid" }
func (invoicePaid) AuditEvent(now time.Time) Event {
	return Event{Name: "billing.invoice_paid", OccurredAt: now, ActorType: ActorUser, ActorID: "u1", SubjectID: "u1", OrganizationID: "org1",
		Data: map[string]any{"invoice": "inv-1", "card_token": "tok_x"}}
}

func TestAnAuditableEventOfAnotherPackageIsRecordedAsItDescribesItselfAndRedacted(t *testing.T) {
	s := &spy{}
	newRecorder(t, s, map[string]string{"billing.invoice_paid": "An invoice was paid"}).Listen(ctx, invoicePaid{})
	if len(s.events) != 1 || !reflect.DeepEqual(s.events[0].Data, map[string]any{"invoice": "inv-1", "card_token": Redacted}) {
		t.Fatalf("%+v", s.events)
	}
}

func TestAnUnknownNameIsRejectedBeforeAnySinkSeesIt(t *testing.T) {
	s := &spy{}
	r := newRecorder(t, s)
	if err := r.Record(ctx, Event{Name: "nope.nothing"}); !errors.Is(err, ErrUnknownName) || len(s.events) != 0 {
		t.Fatalf("%v %v", err, s.events)
	}
	r.Listen(ctx, invoicePaid{}) // logged, not written
	if len(s.events) != 0 {
		t.Fatal("an unknown Auditable was written")
	}
	if err := r.Record(ctx, Event{Name: AuditPruned}); err != nil || s.events[0].ActorType != ActorSystem || s.events[0].OccurredAt.IsZero() {
		t.Fatalf("defaults: %v %+v", err, s.events)
	}
}

func signedIn(user string, at time.Time, org string) Event {
	return Event{Name: SessionSignedIn, OccurredAt: at, ActorType: ActorUser, ActorID: user, SubjectID: user, OrganizationID: org}
}

func TestWritesAndReadsNewestFirstWithFiltersAndCursor(t *testing.T) {
	s := NewStore(memstore.New(Models()...), false)
	base := at("2026-09-11T10:00:00Z")
	for i := range 5 {
		e := signedIn("u1", base.Add(time.Duration(i)*time.Minute), "")
		if i%2 == 1 {
			e.Name = UserEmailVerified
		}
		if i == 4 {
			e.OrganizationID = "org1"
		}
		if _, err := s.Write(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Write(ctx, Event{Name: UserDisabled, OccurredAt: base.Add(10 * time.Minute), ActorType: ActorUser, ActorID: "admin1", SubjectID: "u1"}); err != nil {
		t.Fatal(err)
	}
	read := func(q Query) Page {
		t.Helper()
		p, err := s.Read(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	all := read(Query{})
	if len(all.Events) != 6 || all.Events[0].Name != UserDisabled || all.NextCursor != "" {
		t.Fatalf("all %+v", all)
	}
	page := read(Query{Limit: 2})
	if len(page.Events) != 2 || page.NextCursor != page.Events[1].ID {
		t.Fatalf("page %+v", page)
	}
	next := read(Query{Limit: 2, Cursor: page.NextCursor})
	if len(next.Events) != 2 || next.Events[0].ID >= page.Events[1].ID {
		t.Fatalf("next %+v", next)
	}
	for q, want := range map[*Query]int{
		{Names: []string{SessionSignedIn}}:               3,
		{Names: []string{SessionSignedIn, UserDisabled}}: 4,
		{OrganizationID: "org1"}:                         1,
		{ActorID: "admin1"}:                              1,
		{SubjectID: "u1"}:                                6,
		{PrincipalID: "u1"}:                              6,
		{From: base.Add(3 * time.Minute), To: base.Add(5 * time.Minute)}:           2,
		{From: base.Add(3 * time.Minute)}:                                          3,
		{To: base.Add(time.Minute)}:                                                2,
		{PrincipalID: "u1", Limit: 5}:                                              5,
		{From: base.Add(3 * time.Minute), To: base.Add(5 * time.Minute), Limit: 1}: 1,
	} {
		if got := len(read(*q).Events); got != want {
			t.Errorf("%+v: %d events, want %d", *q, got, want)
		}
	}
	if (Query{Limit: 10000}).limit() != MaxLimit || (Query{Limit: -3}).limit() != 1 {
		t.Fatal("limit bounds")
	}
	m := all.Map()
	if m["data"].([]any)[0].(map[string]any)["subject_id"] != "u1" || m["next_cursor"] != nil {
		t.Fatalf("wire %v", m)
	}
	if n, _ := s.Count(ctx); n != 6 {
		t.Fatalf("count %d", n)
	}
}

func chainPlugin(t *testing.T, db *memstore.Store, retention Retention, now time.Time) *Plugin {
	t.Helper()
	pol, err := retention.parse()
	if err != nil {
		t.Fatal(err)
	}
	c, _ := NewCatalog()
	return &Plugin{cfg: Config{HashChain: true}, policy: pol, catalog: c, store: NewStore(db, true), clock: clock.NewFrozen(now)}
}

func TestTheHashChainLinksRowsAndVerifiesTamperingAndPruning(t *testing.T) {
	db := memstore.New(Models()...)
	p := chainPlugin(t, db, Retention{Default: "P90D", Names: map[string]string{UserSignedUp: "P7Y"}}, at("2026-09-11T10:00:00Z"))
	for _, e := range []Event{
		{Name: UserSignedUp, OccurredAt: at("2026-01-01T00:00:00Z"), ActorType: ActorUser, ActorID: "u1", SubjectID: "u1", Data: map[string]any{"email": "zoë@example.com", "a": []string{}}},
		signedIn("u1", at("2026-01-02T00:00:00Z"), ""),
		signedIn("u1", at("2026-09-10T00:00:00Z"), ""),
	} {
		if _, err := p.store.Write(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	var chain []Event
	_ = p.store.Walk(ctx, 2, func(e Event) error { chain = append(chain, e); return nil })
	if len(chain) != 3 || chain[0].PrevHash != "" || chain[0].Hash == "" || chain[1].PrevHash != chain[0].Hash || chain[2].PrevHash != chain[1].Hash {
		t.Fatalf("chain %+v", chain)
	}
	if r, err := p.Verify(ctx); err != nil || r.Rows != 3 || !r.Intact() {
		t.Fatalf("verify %+v %v", r, err)
	}
	n, err := p.Prune(ctx)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d %v: the January sign-in goes, the sign-up is kept seven years", n, err)
	}
	if r, _ := p.Verify(ctx); r.Rows != 3 || !r.Intact() {
		t.Fatalf("after prune %+v", r)
	}
	if page, _ := p.store.Read(ctx, Query{Limit: 1}); page.Events[0].Name != AuditPruned || page.Events[0].Data["last_hash"] != chain[1].Hash {
		t.Fatalf("checkpoint %+v", page.Events[0])
	}
	if _, err := db.Update(ctx, TableEvents, map[string]any{"name": UserSignedUp}, map[string]any{"actor_id": "mallory"}); err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Verify(ctx); len(r.Breaks) != 1 || !strings.Contains(r.Breaks[0], "was altered") {
		t.Fatalf("tampered %+v", r)
	}
	if err := db.Insert(ctx, TableEvents, map[string]any{"id": "ffff", "name": SessionSignedIn, "occurred_at": at("2026-09-11T00:00:00Z"), "actor_type": "system", "data": "[]"}); err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Verify(ctx); len(r.Breaks) != 2 || !strings.Contains(r.Breaks[1], "has no hash") {
		t.Fatalf("unhashed %+v", r)
	}
}

func TestTheHashIsOverTheCanonicalForm(t *testing.T) {
	e := Event{ID: "id1", Name: UserSignedUp, OccurredAt: at("2026-01-01T00:00:00Z"), ActorType: ActorUser, ActorID: "u1", SubjectID: "u1", Data: map[string]any{}}
	canonical := `{"actor_id":"u1","actor_type":"user","data":[],"id":"id1","ip":null,"name":"user.signed_up","occurred_at":"2026-01-01T00:00:00+00:00","organization_id":null,"prev_hash":null,"request_id":null,"session_id":null,"subject_id":"u1","user_agent":null}`
	sum := sha256.Sum256([]byte(canonical))
	if got := hashOf(e, "[]"); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("hash %s", got)
	}
	// A row whose data keys were stored in insertion order (not sorted) verifies over its stored text.
	insertionOrder := `{"z":1,"a":"é/x"}`
	unsorted := e
	unsorted.stored = insertionOrder
	unsorted.Data = map[string]any{"z": json.Number("1"), "a": "é/x"}
	unsorted.Hash = hashOf(e, insertionOrder)
	if !verifies(unsorted) {
		t.Fatal("a row stored in insertion order does not verify")
	}
	if got, _ := canonicalJSON(map[string]any{"s": "é😀/<"}); got != `{"s":"\u00e9\ud83d\ude00/<"}` {
		t.Fatalf("canonical json %s", got)
	}
}

func TestRetentionPolicyValidatesDurations(t *testing.T) {
	pol, err := Retention{}.parse()
	if err != nil || pol.keepUntil(SessionSignedIn, at("2026-09-11T10:00:00Z")).Format(time.RFC3339) != "2026-06-13T10:00:00Z" {
		t.Fatalf("default %v", err)
	}
	p, err := parsePeriod("P1Y2M1W3DT4H5M6S")
	if err != nil || p != (period{1, 2, 10, 4*time.Hour + 5*time.Minute + 6*time.Second}) {
		t.Fatalf("period %+v %v", p, err)
	}
	for _, bad := range []string{"ninety days", "P", "PT", "P1H"} {
		if _, err := parsePeriod(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := (Retention{Names: map[string]string{UserDeleted: "7 years"}}).parse(); err == nil || !strings.Contains(err.Error(), "Config.Retention.Names") {
		t.Fatalf("names %v", err)
	}
	if _, err := (Retention{Default: "x"}).parse(); err == nil || !strings.Contains(err.Error(), "Config.Retention.Default") {
		t.Fatalf("default %v", err)
	}
}

type recordingHandler struct{ records []slog.Record }

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records = append(h.records, r)
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func TestTheChainIsFailOpenAndTheSimpleSinksWrite(t *testing.T) {
	h := &recordingHandler{}
	logger := slog.New(h)
	s := &spy{}
	file := filepath.Join(t.TempDir(), "audit.jsonl")
	failing := SinkFunc(func(context.Context, ...Event) error { return errors.New("down") })
	c := chain{sinks: []Sink{failing, LogSink{Logger: logger}, &FileSink{Path: file}, s}, logger: logger}
	_ = c.Write(ctx, signedIn("u1", at("2026-09-11T10:00:00Z"), ""))
	if len(s.events) != 1 {
		t.Fatal("the sink after the failing one did not run")
	}
	var errs, infos int
	for _, r := range h.records {
		if r.Level == slog.LevelError && strings.Contains(r.Message, "Audit sink") {
			errs++
		}
		if r.Level == slog.LevelInfo && r.Message == "audit "+SessionSignedIn {
			infos++
		}
	}
	if errs != 1 || infos != 1 {
		t.Fatalf("errors %d infos %d", errs, infos)
	}
	raw, _ := os.ReadFile(file)
	var line map[string]any
	if err := json.Unmarshal(raw, &line); err != nil || line["name"] != SessionSignedIn {
		t.Fatalf("file %s %v", raw, err)
	}
	if err := (&FileSink{Path: filepath.Join(t.TempDir(), "missing", "x")}).Write(ctx, Event{}); err == nil {
		t.Fatal("an unwritable file is an error")
	}
	if (&FileSink{}).Write(ctx) != nil || (WebhookSink{}).Write(ctx) != nil || (LogSink{}).Write(ctx, Event{Name: "x"}) != nil {
		t.Fatal("empty writes")
	}
}

// fakeTransport answers scripted statuses (0 is a transport error) and keeps the requests.
type fakeTransport struct {
	statuses []int
	requests []*http.Request
	bodies   []string
}

func (f *fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(r.Body)
	f.requests, f.bodies = append(f.requests, r), append(f.bodies, string(body))
	code := 200
	if len(f.statuses) > 0 {
		code, f.statuses = f.statuses[0], f.statuses[1:]
	}
	if code == 0 {
		return nil, errors.New("connection refused")
	}
	return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(nil)), Header: http.Header{}}, nil
}

func TestTheWebhookSignsRetriesAndGivesUp(t *testing.T) {
	ft := &fakeTransport{statuses: []int{0, 503, 200}}
	var pauses []time.Duration
	sink := WebhookSink{URL: "https://hooks.example.test/audit", Secret: "s3cret", Client: &http.Client{Transport: ft}, Sleep: func(d time.Duration) { pauses = append(pauses, d) }}
	if err := sink.Write(ctx, signedIn("u1", at("2026-09-11T10:00:00Z"), ""), signedIn("u2", at("2026-09-11T10:00:00Z"), "")); err != nil {
		t.Fatal(err)
	}
	if len(ft.requests) != 3 || !slices.Equal(pauses, []time.Duration{200 * time.Millisecond, 400 * time.Millisecond}) {
		t.Fatalf("requests %d pauses %v", len(ft.requests), pauses)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte(ft.bodies[2]))
	if ft.requests[2].Header.Get(SignatureHeader) != "sha256="+hex.EncodeToString(mac.Sum(nil)) || ft.requests[2].Header.Get(DeliveryHeader) == "" {
		t.Fatal("signature or delivery header")
	}
	var body struct{ Events []map[string]any }
	if json.Unmarshal([]byte(ft.bodies[2]), &body) != nil || len(body.Events) != 2 {
		t.Fatalf("body %s", ft.bodies[2])
	}
	ft = &fakeTransport{statuses: []int{400}}
	err := WebhookSink{URL: "https://hooks.example.test/audit", Client: &http.Client{Transport: ft}, Sleep: func(time.Duration) {}}.Write(ctx, Event{Name: "x"})
	if err == nil || len(ft.requests) != 1 || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("a 4xx is final: %v (%d requests)", err, len(ft.requests))
	}
	if err := (WebhookSink{URL: "://bad"}).Write(ctx, Event{Name: "x"}); err == nil {
		t.Fatal("a bad URL is an error")
	}
}

func TestDrainsDeliverAnOrganizationsMatchingEventsAndRecordTheOutcome(t *testing.T) {
	db := memstore.New(Models()...)
	clk := clock.NewFrozen(at("2026-09-11T10:00:00Z"))
	enc, err := security.NewXChaCha20Poly1305(strings.Repeat("k", 32))
	if err != nil {
		t.Fatal(err)
	}
	drains := NewDrains(db, enc, clk)
	hook, _ := drains.Create(ctx, "org1", "https://acme.example.test/audit", "drain-secret", []string{"org.*", SessionSignedIn}, "owner1")
	paused, _ := drains.Create(ctx, "org1", "https://paused.example.test", "x", nil, "")
	_ = drains.SetStatus(ctx, paused.ID, DrainPaused)
	_, _ = drains.Create(ctx, "org2", "https://other.example.test", "y", nil, "")
	if row, _ := db.FindOne(ctx, TableDrains, map[string]any{"id": hook.ID}); row.String("secret") == "drain-secret" {
		t.Fatal("the secret is not encrypted at rest")
	}
	found, ok, err := drains.Find(ctx, hook.ID)
	if err != nil || !ok || found.Secret != "drain-secret" || !slices.Equal(found.Filter, []string{"org.*", SessionSignedIn}) {
		t.Fatalf("found %+v %v", found, err)
	}
	if all, _ := drains.ForOrganization(ctx, "org1", false); len(all) != 2 {
		t.Fatal("org1 has two drains")
	}
	if active, _ := drains.ForOrganization(ctx, "org1", true); len(active) != 1 {
		t.Fatal("one is active")
	}
	if _, has := hook.Map()["secret"]; has {
		t.Fatal("the wire shape carries the secret")
	}

	ft := &fakeTransport{}
	sink := &drainSink{drains: drains, client: &http.Client{Transport: ft}, attempts: 1, sleep: func(time.Duration) {}, logger: slog.New(&recordingHandler{})}
	in := signedIn("u1", clk.Now(), "org1")
	invited := Event{Name: OrgMemberInvited, OccurredAt: clk.Now(), ActorID: "owner1", OrganizationID: "org1"}
	verified := Event{Name: UserEmailVerified, OccurredAt: clk.Now(), ActorID: "u1", OrganizationID: "org1"}
	_ = sink.Write(ctx, in, invited, verified, signedIn("u3", clk.Now(), ""))
	sink.wait(ctx)
	if len(ft.requests) != 1 || ft.requests[0].URL.String() != "https://acme.example.test/audit" {
		t.Fatalf("deliveries %d", len(ft.requests))
	}
	var body struct{ Events []map[string]any }
	_ = json.Unmarshal([]byte(ft.bodies[0]), &body)
	if len(body.Events) != 2 || body.Events[0]["name"] != SessionSignedIn || body.Events[1]["name"] != OrgMemberInvited {
		t.Fatalf("the filter kept %v", body.Events)
	}
	after, _, _ := drains.Find(ctx, hook.ID)
	if after.LastDeliveryAt == nil || after.LastError != "" || after.Map()["last_delivery_at"] == nil {
		t.Fatalf("outcome %+v", after)
	}
	failing := &drainSink{drains: drains, client: &http.Client{Transport: &fakeTransport{statuses: []int{500}}}, attempts: 1, sleep: func(time.Duration) {}, logger: slog.New(&recordingHandler{})}
	_ = failing.Write(ctx, in)
	failing.wait(ctx)
	if failed, _, _ := drains.Find(ctx, hook.ID); failed.LastError != "HTTP 500" {
		t.Fatalf("failure %q", failed.LastError)
	}
	if deleted, _ := drains.Delete(ctx, hook.ID); !deleted {
		t.Fatal("not deleted")
	}
	if _, ok, _ := drains.Find(ctx, hook.ID); ok {
		t.Fatal("still there")
	}
	if !(Drain{}).Accepts("any.thing") {
		t.Fatal("no filter takes every event")
	}
}

func TestWritesOncePerIntervalFromTheLiveSessionEvents(t *testing.T) {
	db := memstore.New(Models()...)
	clk := clock.NewFrozen(at("2026-09-11T10:00:00Z"))
	c := cache.NewMemory(clk)
	a := NewActivity(db, c, clk, 300*time.Second, nil)
	last := func() string {
		t.Helper()
		v, ok, err := a.LastActiveAt(ctx, "u1")
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			return ""
		}
		return v.Format(time.RFC3339)
	}
	a.Listen(ctx, event.UserRegistered{UserID: "u1"})
	if last() != "" {
		t.Fatal("registering is not activity")
	}
	a.Listen(ctx, event.UserLoggedIn{UserID: "u1", SessionID: "s1"})
	if last() != "2026-09-11T10:00:00Z" {
		t.Fatal(last())
	}
	clk.Advance(time.Minute)
	a.Listen(ctx, event.TokenRefreshed{UserID: "u1"})
	if last() != "2026-09-11T10:00:00Z" {
		t.Fatal("inside the interval: no write")
	}
	clk.Advance(10 * time.Minute)
	a.Listen(ctx, event.MFAVerified{UserID: "u1"})
	a.Listen(ctx, event.MFAStepUpCompleted{UserID: "u2"})
	a.Listen(ctx, event.OrganizationSwitched{UserID: "u3"})
	if last() != "2026-09-11T10:11:00Z" {
		t.Fatal("after the interval: one row updated", last())
	}
	if n, _ := db.Count(ctx, TableActivity, map[string]any{"user_id": "u1"}); n != 1 {
		t.Fatalf("%d rows", n)
	}
}
