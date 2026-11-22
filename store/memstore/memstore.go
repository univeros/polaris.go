// Package memstore is an in-memory store.Adapter for
// tests and prototypes. It has the full criteria semantics, ordering, paging, Increment, nested
// transactions with savepoint semantics and, when given the schema, primary-key and unique-index
// enforcement (store.ErrDuplicate). It is safe for concurrent use; transactions are serialized.
package memstore

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/univeros/polaris.go/schema"
	"github.com/univeros/polaris.go/store"
)

// Store is an in-memory store.Adapter. The zero value is not usable; call New.
type Store struct {
	txMu   sync.Mutex // held for a whole top-level transaction, and by each call outside one
	mu     sync.Mutex // guards tables
	tables map[string][]store.Row
	keys   map[string][]uniqueKey
	refs   map[string][]reference // foreign keys, by referenced table
}

// reference is a foreign key seen from the table it references.
type reference struct {
	child    string
	columns  []string // in child
	parent   []string // in the referenced table
	onDelete string
}

type uniqueKey struct {
	name    string
	columns []string
}

// txKey marks a ctx as running inside a transaction of one Store.
type txKey struct{ s *Store }

var _ store.Adapter = (*Store)(nil)

// New returns an empty store. With models, inserts and updates that would duplicate a primary key
// or a unique index of those tables fail with an error wrapping store.ErrDuplicate; tables without
// a model accept any row. Rows are kept as given: no column defaults,
// types or NOT NULL checks are applied.
func New(models ...schema.Model) *Store {
	s := &Store{tables: map[string][]store.Row{}, keys: map[string][]uniqueKey{}, refs: map[string][]reference{}}
	for _, m := range models {
		for _, fk := range m.ForeignKeys {
			s.refs[fk.ReferencedTable] = append(s.refs[fk.ReferencedTable], reference{m.Table, fk.Columns, fk.ReferencedColumns, fk.OnDelete})
		}
		var keys []uniqueKey
		if pk := m.PrimaryKey(); len(pk) > 0 {
			cols := make([]string, len(pk))
			for i, f := range pk {
				cols[i] = f.Column
			}
			keys = append(keys, uniqueKey{m.Table + "_pkey", cols})
		}
		for _, idx := range m.Indexes {
			if idx.Unique {
				keys = append(keys, uniqueKey{idx.Name, idx.Columns})
			}
		}
		s.keys[m.Table] = keys
	}
	return s
}

// Dialect returns store.Memory.
func (s *Store) Dialect() store.Dialect { return store.Memory }

// Rows returns a copy of every row of a table, in insertion order, for assertions.
func (s *Store) Rows(table string) []store.Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	return cloneRows(s.tables[table])
}

// FindOne returns the first matching row, or nil, nil.
func (s *Store) FindOne(ctx context.Context, table string, c store.Criteria) (store.Row, error) {
	rows, err := s.FindMany(ctx, table, c, store.Query{Limit: 1})
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// FindMany returns copies of the matching rows, ordered and paged by q.
func (s *Store) FindMany(ctx context.Context, table string, c store.Criteria, q store.Query) ([]store.Row, error) {
	defer s.lock(ctx)()
	var rows []store.Row
	for _, r := range s.tables[table] {
		if matches(r, c) {
			rows = append(rows, r)
		}
	}
	if len(q.OrderBy) > 0 {
		slices.SortStableFunc(rows, func(a, b store.Row) int {
			for _, o := range q.OrderBy {
				if n := compare(a[o.Column], b[o.Column]); n != 0 {
					if o.Desc {
						return -n
					}
					return n
				}
			}
			return 0
		})
	}
	rows = rows[min(q.Offset, len(rows)):]
	if q.Limit > 0 {
		rows = rows[:min(q.Limit, len(rows))]
	}
	return cloneRows(rows), nil
}

// Count returns the number of matching rows.
func (s *Store) Count(ctx context.Context, table string, c store.Criteria) (int64, error) {
	defer s.lock(ctx)()
	var n int64
	for _, r := range s.tables[table] {
		if matches(r, c) {
			n++
		}
	}
	return n, nil
}

// Insert stores a copy of row.
func (s *Store) Insert(ctx context.Context, table string, row store.Row) error {
	defer s.lock(ctx)()
	r := maps.Clone(row)
	if err := s.checkUnique(table, s.tables[table], r, -1); err != nil {
		return err
	}
	s.tables[table] = append(s.tables[table], r)
	return nil
}

// Update writes d to every matching row and returns how many matched.
func (s *Store) Update(ctx context.Context, table string, c store.Criteria, d store.Data) (int64, error) {
	defer s.lock(ctx)()
	next := slices.Clone(s.tables[table])
	var changed []int
	for i, r := range next {
		if !matches(r, c) {
			continue
		}
		updated := maps.Clone(r)
		for col, v := range d {
			if inc, ok := v.(store.Increment); ok {
				v = r.Int(col) + inc.By
			}
			updated[col] = v
		}
		next[i] = updated
		changed = append(changed, i)
	}
	for _, i := range changed {
		if err := s.checkUnique(table, next, next[i], i); err != nil {
			return 0, err
		}
	}
	s.tables[table] = next
	return int64(len(changed)), nil
}

// Delete removes every matching row and returns how many it removed. With the schema, the
// foreign keys referencing the table apply as in SQL: ON DELETE CASCADE removes the referencing
// rows, SET NULL clears their columns, any other action fails the whole delete while a
// referencing row exists.
func (s *Store) Delete(ctx context.Context, table string, c store.Criteria) (int64, error) {
	defer s.lock(ctx)()
	work := maps.Clone(s.tables) // slices are replaced on write, never changed in place
	n, err := s.remove(work, table, func(r store.Row) bool { return matches(r, c) })
	if err != nil {
		return 0, err
	}
	s.tables = work
	return n, nil
}

// remove deletes the rows of table that match from work, then applies the foreign keys that
// reference them.
func (s *Store) remove(work map[string][]store.Row, table string, match func(store.Row) bool) (int64, error) {
	var kept, gone []store.Row
	for _, r := range work[table] {
		if match(r) {
			gone = append(gone, r)
		} else {
			kept = append(kept, r)
		}
	}
	if len(gone) == 0 {
		return 0, nil
	}
	work[table] = kept
	for _, ref := range s.refs[table] {
		refers := func(child store.Row) bool {
			return slices.ContainsFunc(gone, func(parent store.Row) bool { return ref.links(child, parent) })
		}
		switch strings.ToUpper(ref.onDelete) {
		case "CASCADE":
			if _, err := s.remove(work, ref.child, refers); err != nil {
				return 0, err
			}
		case "SET NULL":
			work[ref.child] = setNull(work[ref.child], ref.columns, refers)
		default:
			if slices.ContainsFunc(work[ref.child], refers) {
				return 0, fmt.Errorf("memstore: delete from %s violates a foreign key of %s", table, ref.child)
			}
		}
	}
	return int64(len(gone)), nil
}

// links reports whether child references parent through this foreign key.
func (ref reference) links(child, parent store.Row) bool {
	for i, col := range ref.columns {
		if child[col] == nil || compare(child[col], parent[ref.parent[i]]) != 0 {
			return false
		}
	}
	return true
}

func setNull(rows []store.Row, columns []string, match func(store.Row) bool) []store.Row {
	out := slices.Clone(rows)
	for i, r := range out {
		if match(r) {
			cleared := maps.Clone(r)
			for _, col := range columns {
				cleared[col] = nil
			}
			out[i] = cleared
		}
	}
	return out
}

// Tx runs fn in a transaction: fn's error, or a panic, restores the tables as they were when Tx
// began, and a nested Tx restores only what its own fn changed (a savepoint). Top-level
// transactions are serialized: other goroutines wait until the running one ends. fn must use the
// ctx it receives; a call made with an outer ctx from inside fn deadlocks.
func (s *Store) Tx(ctx context.Context, fn func(ctx context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ctx.Value(txKey{s}) == nil {
		s.txMu.Lock()
		defer s.txMu.Unlock()
		ctx = context.WithValue(ctx, txKey{s}, true)
	}
	saved := s.snapshot()
	done := false
	defer func() {
		if !done {
			s.restore(saved)
		}
	}()
	err := fn(ctx)
	done = err == nil
	return err
}

// lock takes the locks a call needs and returns the unlock function: only the table lock inside
// this store's transaction, else the transaction lock too, so a call never sees uncommitted rows.
func (s *Store) lock(ctx context.Context) func() {
	if ctx.Value(txKey{s}) != nil {
		s.mu.Lock()
		return s.mu.Unlock
	}
	s.txMu.Lock()
	s.mu.Lock()
	return func() {
		s.mu.Unlock()
		s.txMu.Unlock()
	}
}

// snapshot copies the table slices; rows themselves are never modified in place, so sharing them
// is safe.
func (s *Store) snapshot() map[string][]store.Row {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string][]store.Row, len(s.tables))
	for t, rows := range s.tables {
		out[t] = slices.Clone(rows)
	}
	return out
}

func (s *Store) restore(saved map[string][]store.Row) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tables = saved
}

// checkUnique reports whether row (at index self of rows, or -1 when not yet in it) collides with
// another row on a primary key or unique index. NULL never collides, as in SQL.
// ponytail: linear scan per key, fine for tests; add hash indexes if memstore ever holds big tables.
func (s *Store) checkUnique(table string, rows []store.Row, row store.Row, self int) error {
	for _, k := range s.keys[table] {
		if slices.ContainsFunc(k.columns, func(c string) bool { return row[c] == nil }) {
			continue
		}
		for i, other := range rows {
			if i == self {
				continue
			}
			if !slices.ContainsFunc(k.columns, func(c string) bool { return other[c] == nil || compare(row[c], other[c]) != 0 }) {
				return fmt.Errorf("memstore: %s violates %s: %w", table, k.name, store.ErrDuplicate)
			}
		}
	}
	return nil
}

func cloneRows(rows []store.Row) []store.Row {
	out := make([]store.Row, len(rows))
	for i, r := range rows {
		out[i] = maps.Clone(r)
	}
	return out
}

func matches(row store.Row, c store.Criteria) bool {
	for col, want := range c {
		got := row[col]
		switch w := want.(type) {
		case store.Cond:
			if !satisfies(got, w) {
				return false
			}
		case nil:
			if got != nil {
				return false
			}
		default:
			if list, ok := store.Values(want); ok {
				if got == nil || !slices.ContainsFunc(list, func(v any) bool { return compare(got, v) == 0 }) {
					return false
				}
			} else if got == nil || compare(got, want) != 0 {
				return false
			}
		}
	}
	return true
}

func satisfies(got any, c store.Cond) bool {
	if c.Op == store.OpNotNull {
		return got != nil
	}
	if got == nil || c.Value == nil {
		return false
	}
	n := compare(got, c.Value)
	switch c.Op {
	case store.OpLt:
		return n < 0
	case store.OpLte:
		return n <= 0
	case store.OpGt:
		return n > 0
	case store.OpGte:
		return n >= 0
	case store.OpNe:
		return n != 0
	}
	return false
}

// norm is a value normalised for comparison: integers (and integer strings, bools) compare as
// integers, floats as floats, everything else as its string form; times are UTC store.TimeLayout,
// the form the SQL adapters store.
type norm struct {
	s       string
	i       int64
	f       float64
	isInt   bool
	isFloat bool
}

func normalise(v any) norm {
	switch x := v.(type) {
	case bool:
		if x {
			return norm{s: "1", i: 1, isInt: true}
		}
		return norm{s: "0", isInt: true}
	case time.Time:
		return normString(x.UTC().Format(store.TimeLayout))
	case string:
		return normString(x)
	case []byte:
		return normString(string(x))
	case float32:
		return norm{s: fmt.Sprint(x), f: float64(x), isFloat: true}
	case float64:
		return norm{s: fmt.Sprint(x), f: x, isFloat: true}
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return norm{s: strconv.FormatInt(rv.Int(), 10), i: rv.Int(), isInt: true}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return normString(strconv.FormatUint(rv.Uint(), 10))
	}
	return normString(fmt.Sprint(v))
}

func normString(s string) norm {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return norm{s: s, i: i, isInt: true}
	}
	return norm{s: s}
}

// compare orders two values; nil sorts before everything.
func compare(a, b any) int {
	if a == nil || b == nil {
		switch {
		case a == nil && b == nil:
			return 0
		case a == nil:
			return -1
		}
		return 1
	}
	x, y := normalise(a), normalise(b)
	switch {
	case x.isInt && y.isInt:
		return cmp.Compare(x.i, y.i)
	case (x.isInt || x.isFloat) && (y.isInt || y.isFloat):
		return cmp.Compare(x.asFloat(), y.asFloat())
	}
	return cmp.Compare(x.s, y.s)
}

func (n norm) asFloat() float64 {
	if n.isInt {
		return float64(n.i)
	}
	return n.f
}
