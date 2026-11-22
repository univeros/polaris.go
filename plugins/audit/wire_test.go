package audit

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/univeros/polaris.go/endpoint"
	"github.com/univeros/polaris.go/event"
	"github.com/univeros/polaris.go/store"
	"github.com/univeros/polaris.go/store/memstore"
)

// Clients read RFC 3339 UTC times ("…Z"); the hash stays over the form earlier releases hashed
// ("…+00:00"), so chains already written keep verifying.
func TestClientsReadZTimesWhileTheHashKeepsItsForm(t *testing.T) {
	e := Event{ID: "id1", Name: UserSignedUp, OccurredAt: at("2026-01-01T00:00:00Z"), ActorType: ActorUser, ActorID: "u1", SubjectID: "u1", Data: map[string]any{}}
	if got := e.Map()["occurred_at"]; got != "2026-01-01T00:00:00Z" {
		t.Fatalf("wire occurred_at %v", got)
	}
	raw, _ := json.Marshal(e)
	if !strings.Contains(string(raw), `"occurred_at":"2026-01-01T00:00:00Z"`) {
		t.Fatalf("json %s", raw)
	}
}

// A row an earlier release wrote, with the hash it stored (SHA-256 of its canonical form, times
// "+00:00", non-ASCII escaped), verifies, and the chain continues from it with rows written now.
func TestAChainWrittenByAnEarlierReleaseKeepsVerifying(t *testing.T) {
	db := memstore.New(Models()...)
	p := chainPlugin(t, db, Retention{Default: "P1Y"}, at("2026-09-11T10:00:00Z"))
	old := store.Row{
		"id": "00000000-0000-7000-8000-000000000001", "name": UserSignedUp, "occurred_at": at("2026-01-01T00:00:00Z"),
		"actor_type": ActorUser, "actor_id": "u1", "subject_id": "u1", "data": `{"email":"zoë@example.com"}`,
		"hash": "f5c3973a916f8a7d26ab44b493c9af7c82134f90dca21e72dca49e12ce436209",
	}
	if err := db.Insert(ctx, TableEvents, old); err != nil {
		t.Fatal(err)
	}
	written, err := p.store.Write(ctx, signedIn("u1", at("2026-09-10T00:00:00Z"), ""))
	if err != nil || written.PrevHash != old["hash"] {
		t.Fatalf("the new row follows the old one: %+v %v", written, err)
	}
	if r, err := p.Verify(ctx); err != nil || r.Rows != 2 || !r.Intact() {
		t.Fatalf("verify %+v %v", r, err)
	}
	page, _ := p.store.Read(ctx, Query{})
	if got := page.Events[1].Map(); got["occurred_at"] != "2026-01-01T00:00:00Z" || got["data"].(map[string]any)["email"] != "zoë@example.com" {
		t.Fatalf("the old row reads %v", got)
	}
}

// The sinks deliver standard JSON: UTF-8, "/" unescaped, an empty object as {}, times in "Z".
func TestTheSinksWriteStandardJSON(t *testing.T) {
	e := Event{ID: "id1", Name: SessionSignedIn, OccurredAt: at("2026-09-11T10:00:00Z"), ActorType: ActorSystem,
		Data: map[string]any{"email": "zoë@example.com", "url": "https://x.test/a", "extra": map[string]any{}}}
	wants := []string{`"zoë@example.com"`, `"https://x.test/a"`, `"extra":{}`, `"occurred_at":"2026-09-11T10:00:00Z"`}
	file := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := (&FileSink{Path: file}).Write(ctx, e); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(file)
	ft := &fakeTransport{}
	if err := (WebhookSink{URL: "https://hooks.example.test/audit", Client: &http.Client{Transport: ft}, Sleep: func(time.Duration) {}}).Write(ctx, e); err != nil {
		t.Fatal(err)
	}
	for _, out := range []string{string(raw), ft.bodies[0]} {
		for _, want := range wants {
			if !strings.Contains(out, want) {
				t.Errorf("%s lacks %s", out, want)
			}
		}
	}
}

// Times a new event carries in its data are RFC 3339 UTC.
func TestEventDataTimesAreZ(t *testing.T) {
	until := at("2026-09-11T10:00:00Z")
	e, _ := mapCore(event.UserLocked{UserID: "u1", Until: &until})
	if e.Data["until"] != "2026-09-11T10:00:00Z" {
		t.Fatalf("until %v", e.Data["until"])
	}
}

// limit is a positive integer in digits: no spaces, fraction, exponent or sign.
func TestTheLimitIsAStrictInteger(t *testing.T) {
	for raw, ok := range map[any]bool{
		"2": true, json.Number("3"): true, "500": true,
		"0": false, "-1": false, "1.5": false, "2.0": false, "1e1": false, " 2": false, "2 ": false, "+2": false, "many": false, "": false,
		json.Number("1.5"): false, json.Number("1e1"): false, true: false,
	} {
		in := endpoint.FromData(httptest.NewRequest("GET", "/audit/me", nil), map[string]any{"limit": raw})
		q, _, valid := parseQuery(in)
		if valid != ok {
			t.Errorf("limit %#v: valid %v", raw, valid)
		}
		if raw == "500" && q.Limit != MaxLimit {
			t.Errorf("limit 500 is clamped: %d", q.Limit)
		}
	}
}
