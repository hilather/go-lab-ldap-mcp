package audit

import (
	"context"
	"sync"
	"time"
)

const (
	// DefaultCapacity is the maximum number of events retained in memory.
	DefaultCapacity = 4096
	// DefaultTTL is how long an event remains queryable. Older events are
	// skipped even if they have not yet been overwritten.
	DefaultTTL = 24 * time.Hour
)

// Ring is a bounded in-memory recent-event buffer. Oldest events are
// overwritten. Expiry is applied at query time using DefaultTTL unless
// TTL is set on the ring.
type Ring struct {
	mu   sync.Mutex
	buf  []Event
	next int
	size int
	cap  int
	seq  uint64
	ttl  time.Duration
	now  func() time.Time
}

func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Ring{
		buf: make([]Event, capacity),
		cap: capacity,
		ttl: DefaultTTL,
		now: time.Now,
	}
}

func (r *Ring) SetTTL(d time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if d > 0 {
		r.ttl = d
	}
}

func (r *Ring) SetClock(now func() time.Time) {
	if r == nil || now == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
}

func (r *Ring) Emit(_ context.Context, ev Event) {
	if r == nil {
		return
	}
	now := r.now
	if now == nil {
		now = time.Now
	}
	if ev.Time.IsZero() {
		ev.Time = now().UTC()
	} else {
		ev.Time = ev.Time.UTC()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seq++
	ev.Seq = r.seq
	if r.cap == 0 {
		return
	}
	if r.size < r.cap {
		r.buf[r.size] = ev
		r.size++
		return
	}
	r.buf[r.next] = ev
	r.next = (r.next + 1) % r.cap
}

func (r *Ring) List(_ context.Context, q ListQuery) (Page, error) {
	if r == nil {
		return Page{Items: []Event{}}, nil
	}
	now := r.now
	if now == nil {
		now = time.Now
	}
	cutoff := now().Add(-r.ttl)
	r.mu.Lock()
	defer r.mu.Unlock()
	all := r.snapshotLocked()
	var live []Event
	for _, ev := range all {
		if ev.Time.Before(cutoff) {
			continue
		}
		live = append(live, ev)
	}
	return paginate(filterEvents(live, q), q), nil
}

func (r *Ring) Len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.size
}

func (r *Ring) snapshotLocked() []Event {
	if r.size == 0 {
		return nil
	}
	out := make([]Event, 0, r.size)
	if r.size < r.cap {
		out = append(out, r.buf[:r.size]...)
		return out
	}
	out = append(out, r.buf[r.next:]...)
	out = append(out, r.buf[:r.next]...)
	return out
}

func filterEvents(in []Event, q ListQuery) []Event {
	if len(in) == 0 {
		return nil
	}
	var out []Event
	for _, ev := range in {
		if q.Action != "" && ev.Action != q.Action {
			continue
		}
		if q.Actor != "" && ev.Actor != q.Actor {
			continue
		}
		// Newest-first pages: AfterSeq is the last returned sequence;
		// keep strictly older events.
		if q.AfterSeq != 0 && ev.Seq >= q.AfterSeq {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func paginate(in []Event, q ListQuery) Page {
	// Newest first.
	for i, j := 0, len(in)-1; i < j; i, j = i+1, j-1 {
		in[i], in[j] = in[j], in[i]
	}
	limit := q.PageSize
	if limit <= 0 {
		limit = 50
	}
	if len(in) <= limit {
		return Page{Items: emptyEvents(in)}
	}
	page := in[:limit]
	return Page{Items: emptyEvents(page), NextSeq: page[len(page)-1].Seq, HasMore: true}
}

func emptyEvents(in []Event) []Event {
	if in == nil {
		return []Event{}
	}
	return in
}
