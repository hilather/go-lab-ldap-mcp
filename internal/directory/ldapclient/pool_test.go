package ldapclient

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func testPoolCfg(dial DialFunc, size int) Config {
	return Config{
		Address:            "127.0.0.1:1",
		Transport:          directory.TransportLDAP,
		AllowCleartextBind: true,
		PoolSize:           size,
		WaitTimeout:        500 * time.Millisecond,
		DialTimeout:        time.Second,
		Dial:               dial,
	}
}

func fakeDial(_ context.Context, _ Config) (*Conn, error) {
	client, server := net.Pipe()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := server.Read(buf); err != nil {
				_ = server.Close()
				return
			}
		}
	}()
	raw := ldap.NewConn(client, false)
	raw.Start()
	now := time.Now()
	return &Conn{raw: raw, createdAt: now, lastUsed: now}, nil
}

func TestPoolNeverExceedsMax(t *testing.T) {
	t.Parallel()
	var live atomic.Int32
	var max atomic.Int32
	dial := func(ctx context.Context, cfg Config) (*Conn, error) {
		n := live.Add(1)
		for {
			cur := max.Load()
			if n <= cur || max.CompareAndSwap(cur, n) {
				break
			}
		}
		c, err := fakeDial(ctx, cfg)
		if err != nil {
			live.Add(-1)
			return nil, err
		}
		return c, nil
	}
	p, err := NewPool(testPoolCfg(dial, 3))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := p.Acquire(t.Context())
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			time.Sleep(15 * time.Millisecond)
			c.Release()
		}()
	}
	wg.Wait()
	if got := max.Load(); got > 3 {
		t.Fatalf("live connections %d exceeded pool size 3", got)
	}
	st := p.Stats()
	if st.Active+st.Idle > 3 {
		t.Fatalf("stats %+v exceeded max", st)
	}
	if st.Max != 3 {
		t.Fatalf("max = %d", st.Max)
	}
}

func TestPoolWaitTimeout(t *testing.T) {
	t.Parallel()
	p, err := NewPool(testPoolCfg(fakeDial, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	c, err := p.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Invalidate()
	ctx, cancel := context.WithTimeout(t.Context(), 80*time.Millisecond)
	defer cancel()
	if _, err := p.Acquire(ctx); err == nil {
		t.Fatal("expected wait timeout or cancel")
	}
}

func TestPoolRecoversAfterBroken(t *testing.T) {
	t.Parallel()
	var n atomic.Int32
	dial := func(ctx context.Context, cfg Config) (*Conn, error) {
		n.Add(1)
		return fakeDial(ctx, cfg)
	}
	p, err := NewPool(testPoolCfg(dial, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	c, err := p.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c.Invalidate()
	c2, err := p.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c2.Release()
	if n.Load() < 2 {
		t.Fatalf("expected redial after invalidate, dials=%d", n.Load())
	}
}

func TestPoolDoRetriesBroken(t *testing.T) {
	t.Parallel()
	var n atomic.Int32
	dial := func(ctx context.Context, cfg Config) (*Conn, error) {
		n.Add(1)
		return fakeDial(ctx, cfg)
	}
	p, err := NewPool(testPoolCfg(dial, 2))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	var calls atomic.Int32
	err = p.Do(t.Context(), func(*Conn) error {
		if calls.Add(1) == 1 {
			return directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || n.Load() < 2 {
		t.Fatalf("calls=%d dials=%d", calls.Load(), n.Load())
	}
}

func TestPoolShutdown(t *testing.T) {
	t.Parallel()
	p, err := NewPool(testPoolCfg(fakeDial, 2))
	if err != nil {
		t.Fatal(err)
	}
	c, err := p.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c.Release()
	if err := p.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Acquire(t.Context()); err == nil {
		t.Fatal("acquire after shutdown")
	}
	st := p.Stats()
	if st.Idle != 0 || st.Active != 0 {
		t.Fatalf("leaked after shutdown: %+v", st)
	}
}

func TestDialDisposableNotPooled(t *testing.T) {
	t.Parallel()
	var n atomic.Int32
	dial := func(ctx context.Context, cfg Config) (*Conn, error) {
		n.Add(1)
		return fakeDial(ctx, cfg)
	}
	p, err := NewPool(testPoolCfg(dial, 1))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	c, err := p.DialDisposable(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c.Release()
	if p.Stats().Idle != 0 {
		t.Fatal("disposable connection returned to pool")
	}
}

type recMetrics struct {
	mu    sync.Mutex
	dials int
	evict []string
	waits int
	acq   int
	rel   int
}

func (m *recMetrics) OnDial(bool) {
	m.mu.Lock()
	m.dials++
	m.mu.Unlock()
}
func (m *recMetrics) OnAcquire(time.Duration) {
	m.mu.Lock()
	m.acq++
	m.mu.Unlock()
}
func (m *recMetrics) OnRelease() {
	m.mu.Lock()
	m.rel++
	m.mu.Unlock()
}
func (m *recMetrics) OnEvict(reason string) {
	m.mu.Lock()
	m.evict = append(m.evict, reason)
	m.mu.Unlock()
}
func (m *recMetrics) OnWaitTimeout() {
	m.mu.Lock()
	m.waits++
	m.mu.Unlock()
}

func TestPoolMetricsHooks(t *testing.T) {
	t.Parallel()
	m := &recMetrics{}
	cfg := testPoolCfg(fakeDial, 1)
	cfg.Metrics = m
	p, err := NewPool(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	c, err := p.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	c.Release()
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dials < 1 || m.acq < 1 || m.rel < 1 {
		t.Fatalf("metrics %+v", m)
	}
}
