package ldapclient

import (
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPoolShortLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("short leak test still opens many pipes")
	}
	p, err := NewPool(testPoolCfg(fakeDial, 4))
	if err != nil {
		t.Fatal(err)
	}

	runtime.GC()
	baseG := runtime.NumGoroutine()
	baseFD := fdCount(t)

	const workers = 8
	const duration = 400 * time.Millisecond
	var wg sync.WaitGroup
	stop := time.Now().Add(duration)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(stop) {
				c, err := p.Acquire(t.Context())
				if err != nil {
					t.Errorf("acquire: %v", err)
					return
				}
				c.Release()
			}
		}()
	}
	wg.Wait()
	if err := p.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	runtime.GC()

	st := p.Stats()
	if st.Active != 0 || st.Idle != 0 {
		t.Fatalf("pool not empty after shutdown: %+v", st)
	}
	g := runtime.NumGoroutine()
	if g > baseG+8 {
		t.Fatalf("goroutine leak: before %d after %d", baseG, g)
	}
	if fd := fdCount(t); fd > baseFD+8 {
		t.Fatalf("fd leak: before %d after %d", baseFD, fd)
	}
}

func fdCount(t *testing.T) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skip("no /proc/self/fd")
	}
	return len(ents)
}
