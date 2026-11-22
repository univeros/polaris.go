package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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
// its canonical JSON (keys sorted, the previous row's hash included), written in one transaction
// that first takes the chain's lock (the polaris_audit_chain row), so writers in every process
// append one at a time, each after the newest row and with a greater id.
type Store struct {
	db        store.Adapter
	hashChain bool
	mu        sync.Mutex // queues this process's writers before they reach the database lock
	headReady bool       // the polaris_audit_chain row exists; guarded by mu
}

// chainHead is the id of the polaris_audit_chain row.
const chainHead = "events"

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
	if err := s.ensureHead(ctx); err != nil {
		return Event{}, err
	}
	minted := e.ID == ""
	err = s.db.Tx(ctx, func(ctx context.Context) error {
		if minted {
			e.ID = repository.NewID()
		}
		// The first statement takes the chain's lock until commit: the row's lock on PostgreSQL and
		// MySQL, the database's write lock on SQLite (taken first, its busy timeout waits for it).
		n, err := s.db.Update(ctx, TableChain, store.Criteria{"id": chainHead}, store.Data{"locked_by": e.ID})
		if err == nil && n == 0 {
			s.headReady = false
			err = fmt.Errorf("the %s row is missing", TableChain)
		}
		if err != nil {
			return err
		}
		// The tip is read from the row this transaction just updated, never from a snapshot: on
		// MySQL's REPEATABLE READ a transaction that already read (a host's, sqlstore.WithTx)
		// would see the events table as it was before the lock.
		head, err := s.db.FindOne(ctx, TableChain, store.Criteria{"id": chainHead})
		if err != nil {
			return err
		}
		tipID := head.String("last_id")
		if minted && tipID != "" && e.ID <= tipID {
			// Another process's clock is ahead, or minted in the same millisecond: sort after it.
			if e.ID, err = after(tipID); err != nil {
				return err
			}
		}
		e.PrevHash = head.String("last_hash")
		e.Hash = hashOf(e, data)
		if err := s.db.Insert(ctx, TableEvents, row(e)); err != nil {
			return err
		}
		_, err = s.db.Update(ctx, TableChain, store.Criteria{"id": chainHead}, store.Data{"last_id": e.ID, "last_hash": e.Hash})
		return err
	})
	if err != nil {
		return Event{}, fmt.Errorf("audit: append to the hash chain: %w", err)
	}
	return e, nil
}

// ensureHead inserts the polaris_audit_chain row once, seeded with the newest event, so a chain
// written before the table existed continues from it. No chained write appends before the row
// exists, so the seed is the tip whatever snapshot reads it; when another process inserted the row
// first, the duplicate is ignored. It runs in a savepoint inside a caller's transaction, so the
// duplicate does not abort that transaction on PostgreSQL.
func (s *Store) ensureHead(ctx context.Context) error {
	if s.headReady {
		return nil
	}
	err := s.db.Tx(ctx, func(ctx context.Context) error {
		// The insert comes first, a write taking the lock (on SQLite a read first could not
		// upgrade to the write lock while another writer holds it).
		if err := s.db.Insert(ctx, TableChain, store.Row{"id": chainHead, "last_id": "", "last_hash": "", "locked_by": ""}); err != nil {
			return err
		}
		tip, err := s.newest(ctx)
		if err != nil || tip == nil {
			return err
		}
		_, err = s.db.Update(ctx, TableChain, store.Criteria{"id": chainHead}, store.Data{"last_id": tip.String("id"), "last_hash": tip.String("hash")})
		return err
	})
	if err != nil && !errors.Is(err, store.ErrDuplicate) {
		return fmt.Errorf("audit: create the hash chain's lock row (run Migrate to create %s): %w", TableChain, err)
	}
	s.headReady = true
	return nil
}

// newest is the newest event row, nil when there is none.
func (s *Store) newest(ctx context.Context) (store.Row, error) {
	rows, err := s.db.FindMany(ctx, TableEvents, store.Criteria{}, store.Query{OrderBy: []store.Order{{Column: "id", Desc: true}}, Limit: 1})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// after returns the UUID that sorts right after id: id with its random tail plus one (the version
// and variant bits untouched).
func after(id string) (string, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return "", fmt.Errorf("the newest event id %q is not a UUID: %w", id, err)
	}
	const tailBits = 1<<62 - 1
	tail := binary.BigEndian.Uint64(u[8:])
	if tail&tailBits == tailBits {
		return "", fmt.Errorf("no UUID sorts right after %s", id)
	}
	binary.BigEndian.PutUint64(u[8:], tail+1)
	return u.String(), nil
}

// hashOf is SHA-256 over the row's canonical JSON: the wire keys plus prev_hash, sorted, data as
// its stored JSON text, occurred_at in hashedTimeLayout, each value encoded by canonicalJSON. Rows
// hashed by earlier releases keep verifying only while these bytes stay the same.
func hashOf(e Event, data string) string {
	m := e.Map()
	m["occurred_at"] = e.OccurredAt.UTC().Format(hashedTimeLayout)
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
