package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/univeros/polaris.go/repository"
	"github.com/univeros/polaris.go/store"
)

// Page sizes of a Query.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Query is what a reader asks for. Zero fields do not filter. PrincipalID matches the actor or
// the subject. Cursor is the NextCursor of the previous page.
type Query struct {
	Names          []string
	ActorID        string
	SubjectID      string
	PrincipalID    string
	OrganizationID string
	From, To       time.Time
	Cursor         string
	Limit          int // DefaultLimit when 0, at most MaxLimit
}

func (q Query) limit() int {
	switch {
	case q.Limit == 0:
		return DefaultLimit
	case q.Limit < 1:
		return 1
	case q.Limit > MaxLimit:
		return MaxLimit
	}
	return q.Limit
}

// criteria is the conjunction the adapter runs. The adapter takes one condition per column, so a
// closed range keeps the upper bound here and the lower bound in memory: rows older than From
// sort last (newest first), so dropping them never starves a page.
func (q Query) criteria() store.Criteria {
	c := store.Criteria{}
	if len(q.Names) == 1 {
		c["name"] = q.Names[0]
	} else if len(q.Names) > 1 {
		c["name"] = q.Names
	}
	if q.ActorID != "" {
		c["actor_id"] = q.ActorID
	}
	if q.SubjectID != "" {
		c["subject_id"] = q.SubjectID
	}
	if q.OrganizationID != "" {
		c["organization_id"] = q.OrganizationID
	}
	if q.Cursor != "" {
		c["id"] = store.Lt(q.Cursor)
	}
	switch {
	case !q.To.IsZero():
		c["occurred_at"] = store.Lte(q.To)
	case !q.From.IsZero():
		c["occurred_at"] = store.Gte(q.From)
	}
	return c
}

// Page is one page of events, newest first; NextCursor is "" on the last.
type Page struct {
	Events     []Event
	NextCursor string
}

// Map is the wire shape {data, next_cursor}.
func (p Page) Map() map[string]any {
	data := make([]any, len(p.Events))
	for i, e := range p.Events {
		data[i] = e.Map()
	}
	return map[string]any{"data": data, "next_cursor": null(p.NextCursor)}
}

// Store reads and writes polaris_audit_event. Ids are UUID v7, so ordering by id is ordering by
// time and a cursor is the last id seen. With the hash chain on, each row's hash is SHA-256 over
// its canonical JSON (keys sorted, the previous row's hash included), written in one transaction.
type Store struct {
	db        store.Adapter
	hashChain bool
	// ponytail: one writer per process keeps the chain linear here; writers in other processes can
	// still fork it. A database advisory lock would close that.
	mu sync.Mutex
}

// NewStore returns a store over db.
func NewStore(db store.Adapter, hashChain bool) *Store { return &Store{db: db, hashChain: hashChain} }

// Write appends e (an id is minted when empty) and returns the row as stored.
func (s *Store) Write(ctx context.Context, e Event) (Event, error) {
	e = e.normalized()
	data, err := canonicalJSON(e.Data)
	if err != nil {
		return Event{}, err
	}
	e.stored = data
	if !s.hashChain {
		if e.ID == "" {
			e.ID = repository.NewID()
		}
		return e, s.db.Insert(ctx, TableEvents, row(e))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.ID == "" {
		e.ID = repository.NewID()
	}
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		prev, err := s.lastHash(ctx)
		if err != nil {
			return err
		}
		e.PrevHash = prev
		e.Hash = hashOf(e, data)
		return s.db.Insert(ctx, TableEvents, row(e))
	})
	return e, err
}

func (s *Store) lastHash(ctx context.Context) (string, error) {
	rows, err := s.db.FindMany(ctx, TableEvents, store.Criteria{}, store.Query{OrderBy: []store.Order{{Column: "id", Desc: true}}, Limit: 1})
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].String("hash"), nil
}

// hashOf is SHA-256 over the row's canonical JSON: the wire keys plus prev_hash, sorted, data as
// its stored JSON text, each value encoded by canonicalJSON. Rows hashed by earlier releases
// keep verifying only while these bytes stay the same.
func hashOf(e Event, data string) string {
	m := e.Map()
	m["prev_hash"] = null(e.PrevHash)
	keys := slices.Sorted(maps.Keys(m))
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		key, _ := canonicalJSON(k)
		b.WriteString(key)
		b.WriteByte(':')
		if k == "data" {
			b.WriteString(data)
			continue
		}
		v, _ := canonicalJSON(m[k])
		b.WriteString(v)
	}
	b.WriteByte('}')
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// verifies reports whether e's hash is its recomputed hash: over its data re-encoded (keys sorted,
// what Write stores, robust to JSONB reordering), or over the stored text (rows whose data keys
// were written in insertion order by earlier releases).
func verifies(e Event) bool {
	data, err := canonicalJSON(e.Data)
	if err == nil && hashOf(e, data) == e.Hash {
		return true
	}
	return e.stored != "" && e.stored != data && hashOf(e, e.stored) == e.Hash
}

// Read returns one page, newest first. A principal filter is two reads merged (actor, subject),
// because the adapter's criteria are conjunctions.
func (s *Store) Read(ctx context.Context, q Query) (Page, error) {
	limit, c := q.limit(), q.criteria()
	order := store.Query{OrderBy: []store.Order{{Column: "id", Desc: true}}, Limit: limit + 1}
	var rows []store.Row
	if q.PrincipalID == "" {
		var err error
		if rows, err = s.db.FindMany(ctx, TableEvents, c, order); err != nil {
			return Page{}, err
		}
	} else {
		seen := map[string]bool{}
		for _, col := range []string{"actor_id", "subject_id"} {
			cc := store.Criteria{col: q.PrincipalID}
			maps.Copy(cc, c)
			found, err := s.db.FindMany(ctx, TableEvents, cc, order)
			if err != nil {
				return Page{}, err
			}
			for _, r := range found {
				if id := r.String("id"); !seen[id] {
					seen[id] = true
					rows = append(rows, r)
				}
			}
		}
		slices.SortFunc(rows, func(a, b store.Row) int { return strings.Compare(b.String("id"), a.String("id")) })
	}
	events := make([]Event, 0, len(rows))
	for _, r := range rows {
		e := hydrate(r)
		if !q.From.IsZero() && !q.To.IsZero() && e.OccurredAt.Before(q.From) {
			continue
		}
		events = append(events, e)
	}
	page := Page{Events: events}
	if len(events) > limit {
		page.Events = events[:limit]
		page.NextCursor = page.Events[limit-1].ID
	}
	return page, nil
}

func nameCriteria(c store.Criteria, name string) store.Criteria {
	if name != "" {
		c["name"] = name
	}
	return c
}

// DeleteBefore deletes the rows older than before, of one name ("" for every name).
func (s *Store) DeleteBefore(ctx context.Context, before time.Time, name string) (int64, error) {
	return s.db.Delete(ctx, TableEvents, nameCriteria(store.Criteria{"occurred_at": store.Lt(before)}, name))
}

// NewestBefore returns the newest event older than before, of one name ("" for every name).
func (s *Store) NewestBefore(ctx context.Context, before time.Time, name string) (Event, bool, error) {
	rows, err := s.db.FindMany(ctx, TableEvents, nameCriteria(store.Criteria{"occurred_at": store.Lt(before)}, name),
		store.Query{OrderBy: []store.Order{{Column: "id", Desc: true}}, Limit: 1})
	if err != nil || len(rows) == 0 {
		return Event{}, false, err
	}
	return hydrate(rows[0]), true, nil
}

// Walk calls fn for every event in chain order, reading batch rows at a time; fn's error stops it.
func (s *Store) Walk(ctx context.Context, batch int, fn func(Event) error) error {
	after := ""
	for {
		c := store.Criteria{}
		if after != "" {
			c["id"] = store.Gt(after)
		}
		rows, err := s.db.FindMany(ctx, TableEvents, c, store.Query{OrderBy: []store.Order{{Column: "id"}}, Limit: batch})
		if err != nil {
			return err
		}
		for _, r := range rows {
			e := hydrate(r)
			after = e.ID
			if err := fn(e); err != nil {
				return err
			}
		}
		if len(rows) < batch {
			return nil
		}
	}
}

// Count returns the number of stored events.
func (s *Store) Count(ctx context.Context) (int64, error) {
	return s.db.Count(ctx, TableEvents, store.Criteria{})
}

// checkpointHashes returns the last_hash of every pruning checkpoint: the hashes a chain may
// legitimately continue from.
func (s *Store) checkpointHashes(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.FindMany(ctx, TableEvents, store.Criteria{"name": AuditPruned}, store.Query{})
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range rows {
		if h, ok := hydrate(r).Data["last_hash"].(string); ok && h != "" {
			out[h] = true
		}
	}
	return out, nil
}

func hydrate(r store.Row) Event {
	e := Event{
		ID:             r.String("id"),
		Name:           r.String("name"),
		ActorType:      r.String("actor_type"),
		ActorID:        r.String("actor_id"),
		SubjectID:      r.String("subject_id"),
		OrganizationID: r.String("organization_id"),
		SessionID:      r.String("session_id"),
		IP:             r.String("ip"),
		UserAgent:      r.String("user_agent"),
		RequestID:      r.String("request_id"),
		PrevHash:       r.String("prev_hash"),
		Hash:           r.String("hash"),
		Data:           map[string]any{},
		stored:         r.String("data"),
	}
	e.OccurredAt, _ = r.Time("occurred_at")
	dec := json.NewDecoder(bytes.NewReader([]byte(e.stored)))
	dec.UseNumber()
	var data any
	if dec.Decode(&data) == nil {
		if m, ok := data.(map[string]any); ok {
			e.Data = m
		}
	}
	return e
}

func row(e Event) store.Row {
	return store.Row{
		"id":              e.ID,
		"name":            e.Name,
		"occurred_at":     e.OccurredAt,
		"actor_type":      e.ActorType,
		"actor_id":        null(e.ActorID),
		"subject_id":      null(e.SubjectID),
		"organization_id": null(e.OrganizationID),
		"session_id":      null(e.SessionID),
		"ip":              null(e.IP),
		"user_agent":      null(e.UserAgent),
		"data":            e.stored,
		"request_id":      null(e.RequestID),
		"prev_hash":       null(e.PrevHash),
		"hash":            null(e.Hash),
	}
}
