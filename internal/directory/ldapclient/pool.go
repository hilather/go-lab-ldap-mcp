package ldapclient

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

// Stats is secret-free pool telemetry for diagnostics.
type Stats struct {
	Active  int   `json:"active"`
	Idle    int   `json:"idle"`
	Max     int   `json:"max"`
	Waiters int   `json:"waiters"`
	Dialed  int64 `json:"dialed"`
	Evicted int64 `json:"evicted"`
}

// Pool is a bounded LDAP connection pool with idle/lifetime eviction.
type Pool struct {
	cfg     Config
	dial    DialFunc
	metrics Metrics

	mu     sync.Mutex
	idle   []*Conn
	active int
	closed bool
	wait   []chan struct{}

	dialed  atomic.Int64
	evicted atomic.Int64
}

// NewPool builds a pool. Dial happens on Acquire, not at construction.
func NewPool(cfg Config) (*Pool, error) {
	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	d := cfg.Dial
	if d == nil {
		d = Dial
	}
	return &Pool{cfg: cfg, dial: d, metrics: metricsOf(cfg.Metrics)}, nil
}

// Acquire returns a bound connection, waiting up to WaitTimeout when full.
func (p *Pool) Acquire(ctx context.Context) (*Conn, error) {
	start := time.Now()
	for {
		if err := ctx.Err(); err != nil {
			return nil, MapError(err)
		}
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return nil, directory.Error("connection", directory.FieldUnavailable, "ldap pool is closed")
		}
		p.evictLocked(time.Now())
		if c := p.takeIdleLocked(); c != nil {
			p.active++
			p.mu.Unlock()
			c.released.Store(false)
			c.pool = p
			p.metrics.OnAcquire(time.Since(start))
			return c, nil
		}
		if p.active < p.cfg.PoolSize {
			p.active++
			p.mu.Unlock()
			c, err := p.dial(ctx, p.cfg)
			if err != nil {
				p.mu.Lock()
				p.active--
				p.signalLocked()
				p.mu.Unlock()
				p.metrics.OnDial(false)
				return nil, MapError(err)
			}
			p.dialed.Add(1)
			p.metrics.OnDial(true)
			c.pool = p
			c.released.Store(false)
			p.metrics.OnAcquire(time.Since(start))
			return c, nil
		}
		ch := make(chan struct{})
		p.wait = append(p.wait, ch)
		p.mu.Unlock()

		timer := time.NewTimer(p.cfg.WaitTimeout)
		select {
		case <-ctx.Done():
			timer.Stop()
			p.removeWaiter(ch)
			return nil, MapError(ctx.Err())
		case <-timer.C:
			p.removeWaiter(ch)
			p.metrics.OnWaitTimeout()
			return nil, directory.Error("connection", directory.FieldUnavailable, "ldap pool wait timeout")
		case <-ch:
			timer.Stop()
		}
	}
}

// Do runs fn on a pooled connection and retries once after a broken session.
func (p *Pool) Do(ctx context.Context, fn func(*Conn) error) error {
	c, err := p.Acquire(ctx)
	if err != nil {
		return err
	}
	err = fn(c)
	if err == nil {
		c.Release()
		return nil
	}
	if !c.isBroken() && !isBroken(err) {
		c.Release()
		return err
	}
	c.Invalidate()
	if ctx.Err() != nil {
		return err
	}
	c2, err2 := p.Acquire(ctx)
	if err2 != nil {
		return err2
	}
	err2 = fn(c2)
	if err2 != nil {
		if c2.isBroken() || isBroken(err2) {
			c2.Invalidate()
		} else {
			c2.Release()
		}
		return err2
	}
	c2.Release()
	return nil
}

// DialDisposable opens a connection that is never returned to the pool (bind-test).
func (p *Pool) DialDisposable(ctx context.Context) (*Conn, error) {
	c, err := p.dial(ctx, p.cfg)
	if err != nil {
		return nil, MapError(err)
	}
	c.pool = nil
	return c, nil
}

func (p *Pool) put(c *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.active--
	now := time.Now()
	if p.closed || c.isBroken() || expired(c, p.cfg, now) {
		p.closeConn(c, evictReason(c, p.cfg, now, p.closed))
		p.signalLocked()
		p.metrics.OnRelease()
		return
	}
	c.lastUsed = now
	c.pool = p
	p.idle = append(p.idle, c)
	p.signalLocked()
	p.metrics.OnRelease()
}

func (p *Pool) takeIdleLocked() *Conn {
	for len(p.idle) > 0 {
		c := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if c.isBroken() || expired(c, p.cfg, time.Now()) {
			p.closeConn(c, evictReason(c, p.cfg, time.Now(), false))
			continue
		}
		return c
	}
	return nil
}

func (p *Pool) evictLocked(now time.Time) {
	kept := p.idle[:0]
	for _, c := range p.idle {
		if c.isBroken() || expired(c, p.cfg, now) {
			p.closeConn(c, evictReason(c, p.cfg, now, false))
			continue
		}
		kept = append(kept, c)
	}
	p.idle = kept
}

func expired(c *Conn, cfg Config, now time.Time) bool {
	if cfg.MaxIdle > 0 && !c.lastUsed.IsZero() && now.Sub(c.lastUsed) > cfg.MaxIdle {
		return true
	}
	if cfg.MaxLifetime > 0 && !c.createdAt.IsZero() && now.Sub(c.createdAt) > cfg.MaxLifetime {
		return true
	}
	return false
}

func evictReason(c *Conn, cfg Config, now time.Time, shutdown bool) string {
	if shutdown {
		return "shutdown"
	}
	if c.isBroken() {
		return "broken"
	}
	if cfg.MaxLifetime > 0 && !c.createdAt.IsZero() && now.Sub(c.createdAt) > cfg.MaxLifetime {
		return "lifetime"
	}
	return "idle"
}

func (p *Pool) closeConn(c *Conn, reason string) {
	if c.raw != nil {
		_ = c.raw.Close()
	}
	p.evicted.Add(1)
	p.metrics.OnEvict(reason)
}

func (p *Pool) signalLocked() {
	if len(p.wait) == 0 {
		return
	}
	ch := p.wait[0]
	p.wait = p.wait[1:]
	close(ch)
}

func (p *Pool) removeWaiter(ch chan struct{}) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, w := range p.wait {
		if w == ch {
			p.wait = append(p.wait[:i], p.wait[i+1:]...)
			return
		}
	}
	// Already signaled; pass the wake to the next waiter.
	p.signalLocked()
}

// Stats returns a snapshot. Values are not identities.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return Stats{
		Active:  p.active,
		Idle:    len(p.idle),
		Max:     p.cfg.PoolSize,
		Waiters: len(p.wait),
		Dialed:  p.dialed.Load(),
		Evicted: p.evicted.Load(),
	}
}

// Close rejects new acquires and closes idle connections. In-use conns close on Release.
func (p *Pool) Close() error {
	return p.Shutdown(context.Background())
}

// Shutdown closes idle connections and waits for in-use ones or ctx.
func (p *Pool) Shutdown(ctx context.Context) error {
	p.mu.Lock()
	p.closed = true
	for _, c := range p.idle {
		p.closeConn(c, "shutdown")
	}
	p.idle = nil
	waiters := p.wait
	p.wait = nil
	p.mu.Unlock()
	for _, ch := range waiters {
		close(ch)
	}
	deadline := time.NewTicker(10 * time.Millisecond)
	defer deadline.Stop()
	for {
		st := p.Stats()
		if st.Active == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			p.mu.Lock()
			// force-close is not possible without tracking active pointers;
			// callers still Close via Release/Invalidate.
			p.mu.Unlock()
			return MapError(ctx.Err())
		case <-deadline.C:
		}
	}
}
