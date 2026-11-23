package audit

import (
	"context"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"time"
)

// DefaultRetention keeps events 90 days.
const DefaultRetention = "P90D"

// Retention is how long events are kept: a default ISO-8601 duration and longer or shorter ones
// per name ({"user.deleted": "P7Y"}). Drains are the way to keep more.
type Retention struct {
	Default string            // "" means DefaultRetention
	Names   map[string]string // name => duration
}

// period is a parsed ISO-8601 duration.
type period struct {
	years, months, days int
	clock               time.Duration
}

var isoDuration = regexp.MustCompile(`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$`)

func parsePeriod(s string) (period, error) {
	m := isoDuration.FindStringSubmatch(s)
	if m == nil || s == "P" || s[len(s)-1] == 'T' {
		return period{}, fmt.Errorf("audit: %q is not an ISO-8601 duration (P90D, P7Y, PT12H)", s)
	}
	n := make([]int, 8)
	for i := 1; i < 8; i++ {
		if m[i] != "" {
			v, err := strconv.Atoi(m[i])
			if err != nil {
				return period{}, fmt.Errorf("audit: %q is not an ISO-8601 duration: %w", s, err)
			}
			n[i] = v
		}
	}
	return period{years: n[1], months: n[2], days: n[3]*7 + n[4],
		clock: time.Duration(n[5])*time.Hour + time.Duration(n[6])*time.Minute + time.Duration(n[7])*time.Second}, nil
}

func (p period) before(t time.Time) time.Time {
	return t.AddDate(-p.years, -p.months, -p.days).Add(-p.clock)
}

// policy is a validated Retention.
type policy struct {
	def   period
	names map[string]period
}

func (r Retention) parse() (policy, error) {
	def := r.Default
	if def == "" {
		def = DefaultRetention
	}
	p := policy{names: map[string]period{}}
	var err error
	if p.def, err = parsePeriod(def); err != nil {
		return policy{}, fmt.Errorf("%w (Config.Retention.Default)", err)
	}
	for name, d := range r.Names {
		if p.names[name], err = parsePeriod(d); err != nil {
			return policy{}, fmt.Errorf("%w (Config.Retention.Names[%q])", err, name)
		}
	}
	return p, nil
}

// keepUntil is the instant before which events of name are deleted.
func (p policy) keepUntil(name string, now time.Time) time.Time {
	if d, ok := p.names[name]; ok {
		return d.before(now)
	}
	return p.def.before(now)
}

// Prune deletes what the retention policy no longer keeps: the names with their own duration
// first, then every other catalogued name at the default. With the hash chain on, a run that
// deleted anything ends with an audit.pruned checkpoint carrying the hash of the newest pruned
// event and the gaps the run leaves between kept ones (in several checkpoints when they are many),
// which lets Verify accept them. It returns the number of events deleted.
func (p *Plugin) Prune(ctx context.Context) (int64, error) {
	now := p.clock.Now()
	var gaps []string
	if p.cfg.HashChain {
		var err error
		if gaps, err = p.gaps(ctx, now); err != nil {
			return 0, err
		}
	}
	var deleted int64
	var newestID, lastHash string
	track := func(until time.Time, name string) error {
		e, ok, err := p.store.NewestBefore(ctx, until, name)
		if err == nil && ok && e.ID > newestID {
			newestID, lastHash = e.ID, e.Hash
		}
		return err
	}
	prune := func(until time.Time, name string) error {
		if err := track(until, name); err != nil {
			return err
		}
		n, err := p.store.DeleteBefore(ctx, until, name)
		deleted += n
		return err
	}
	overridden := slices.Sorted(maps.Keys(p.policy.names))
	for _, name := range overridden {
		if err := prune(p.policy.keepUntil(name, now), name); err != nil {
			return deleted, err
		}
	}
	def := p.policy.def.before(now)
	if err := track(def, ""); err != nil {
		return deleted, err
	}
	for _, name := range p.catalog.Names() {
		if _, own := p.policy.names[name]; own {
			continue
		}
		n, err := p.store.DeleteBefore(ctx, def, name)
		deleted += n
		if err != nil {
			return deleted, err
		}
	}
	if !p.cfg.HashChain || deleted == 0 {
		return deleted, nil
	}
	data := map[string]any{"count": deleted, "before": timestamp(def), "last_hash": null(lastHash)}
	for {
		n := min(len(gaps), checkpointSize)
		if n > 0 {
			data["gaps"] = gaps[:n]
		}
		if _, err := p.store.Write(ctx, Event{Name: AuditPruned, OccurredAt: now, Data: data}); err != nil {
			return deleted, err
		}
		if gaps = gaps[n:]; len(gaps) == 0 {
			return deleted, nil
		}
		data = map[string]any{"before": timestamp(def)}
	}
}

// checkpointSize is how many gaps one checkpoint carries.
const checkpointSize = 1000

// gaps are the ones Verify must accept once the policy is applied at now, beyond what the checkpoints it
// keeps carry: from the hash of a kept event to the prev_hash of the next. Where the rows between them
// do not form a chain themselves, there is none: pruning does not hide a break.
func (p *Plugin) gaps(ctx context.Context, now time.Time) ([]string, error) {
	pruned := func(e Event) bool {
		return p.catalog.Has(e.Name) && e.OccurredAt.Before(p.policy.keepUntil(e.Name, now))
	}
	accepted, err := p.store.checkpoints(ctx, func(Event) bool { return true })
	if err != nil {
		return nil, err
	}
	stay, err := p.store.checkpoints(ctx, func(e Event) bool { return !pruned(e) })
	if err != nil {
		return nil, err
	}
	out := []string{}
	previous, kept, chained := "", "", true
	err = p.store.Walk(ctx, 500, func(e Event) error {
		chained = chained && accepted.follows(previous, e)
		previous = e.Hash
		if pruned(e) {
			return nil
		}
		if chained && !stay.follows(kept, e) {
			out = append(out, gap(kept, e.PrevHash))
		}
		kept, chained = e.Hash, true
		return nil
	})
	return out, err
}

// gap is the break in the chain from a row's hash to the prev_hash of the row after it.
func gap(hash, prevHash string) string { return hash + ":" + prevHash }

// checkpoints are what the pruning checkpoints explain.
type checkpoints struct {
	lastHashes map[string]bool // of the newest event each run pruned
	gaps       map[string]bool
}

// follows reports whether e legitimately follows the row whose hash is previous ("" for none).
func (c checkpoints) follows(previous string, e Event) bool {
	return e.PrevHash == previous || (previous == "" && e.Name == AuditPruned) || c.lastHashes[e.PrevHash] || c.gaps[gap(previous, e.PrevHash)]
}

// Report is the outcome of Verify: the rows walked and every break found.
type Report struct {
	Rows   int
	Breaks []string
}

// Intact reports whether the chain has no break.
func (r Report) Intact() bool { return len(r.Breaks) == 0 }

// Verify walks the hash chain in order: every row's hash must be its recomputed hash, and its
// prev_hash the previous row's hash, or what a pruning checkpoint carries when the rows between them
// were pruned. It reports each break.
func (p *Plugin) Verify(ctx context.Context) (Report, error) {
	explained, err := p.store.checkpoints(ctx, func(Event) bool { return true })
	if err != nil {
		return Report{}, err
	}
	report := Report{Breaks: []string{}}
	previous := ""
	err = p.store.Walk(ctx, 500, func(e Event) error {
		report.Rows++
		if e.Hash == "" {
			report.Breaks = append(report.Breaks, fmt.Sprintf("%s (%s) has no hash", e.ID, e.Name))
			previous = ""
			return nil
		}
		if !verifies(e) {
			report.Breaks = append(report.Breaks, fmt.Sprintf("%s (%s) was altered", e.ID, e.Name))
		}
		if !explained.follows(previous, e) {
			report.Breaks = append(report.Breaks, fmt.Sprintf("%s (%s) does not follow the previous row", e.ID, e.Name))
		}
		previous = e.Hash
		return nil
	})
	return report, err
}
