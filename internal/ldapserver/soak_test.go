package ldapserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestNativeSoakConnectionChurn is the T-150 native soak/leak gate: it
// churns many short-lived connections through bind + search + unbind and
// asserts goroutine and file-descriptor counts return to baseline. The
// checks are hand-rolled (runtime.NumGoroutine and /proc/self/fd deltas)
// because go.uber.org/goleak is deliberately not a dependency.
//
// The default cycle count keeps the hermetic suite fast; the medium
// profile (LABLDAP_SOAK_MEDIUM=1) raises it for CI lanes.
//
// The bbolt side of the leak budget lives in
// internal/ldapserver/store/soak_test.go (import direction: store depends
// on ldapserver, so the bolt-backed assertion sits in the store package).
func TestNativeSoakConnectionChurn(t *testing.T) {
	cycles := 200
	workers := 4
	if os.Getenv("LABLDAP_SOAK_MEDIUM") == "1" {
		cycles = 2000
		workers = 8
	}

	opts := testOptions()
	opts.DirectoryManager = dmIdentity(diffDMFixturePassword)
	opts.AllowCleartextBind = true
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		return check.Subject.BypassACI, nil
	}}
	ctx := context.Background()
	err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		for _, e := range []*Entry{
			NewEntry("dc=example,dc=test",
				StringAttribute("objectClass", "top", "domain"),
				StringAttribute("dc", "example")),
			NewEntry("ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "organizationalUnit"),
				StringAttribute("ou", "people")),
			NewEntry("uid=alice,ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "alice"),
				StringAttribute("cn", "Alice Adams"),
				StringAttribute("sn", "Adams")),
		} {
			if err := tx.Add(ctx, e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	s, addr := serveTestServerFrom(t, opts, nil)
	_ = s

	// Warm-up: JIT-free Go still pays one-time costs (first bind allocates
	// pools, metrics maps, etc.), so measure the baseline only after the
	// server has served real traffic.
	soakChurn(t, addr, 8, 2)
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	baseG := runtime.NumGoroutine()
	baseFD := soakFDCount(t)

	soakChurn(t, addr, cycles, workers)

	// Let the last connections' cleanup goroutines drain before sampling.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= baseG+soakSlack && soakFDCount(t) <= baseFD+soakSlack {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	runtime.GC()
	if g := runtime.NumGoroutine(); g > baseG+soakSlack {
		t.Fatalf("goroutine growth: baseline %d, after %d (slack %d)", baseG, g, soakSlack)
	}
	if fd := soakFDCount(t); fd > baseFD+soakSlack {
		t.Fatalf("fd growth: baseline %d, after %d (slack %d)", baseFD, fd, soakSlack)
	}
	t.Logf("soak: %d cycles x %d workers, goroutines %d->%d, fds %d->%d",
		cycles, workers, baseG, runtime.NumGoroutine(), baseFD, soakFDCount(t))
}

// soakSlack bounds accepted post-churn delta. The server keeps one accept
// goroutine and a handful of timers; anything beyond a small constant is a
// leak signal, not steady state.
const soakSlack = 12

// soakChurn runs workers goroutines, each cycling through dial, DM bind,
// subtree search, and unbind. It uses error-returning helpers only: the
// testing.T FailNow family is illegal off the test goroutine.
func soakChurn(t *testing.T, addr string, cycles, workers int) {
	t.Helper()
	per := cycles / workers
	if per < 1 {
		per = 1
	}
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				if err := soakRoundTrip(addr); err != nil {
					t.Errorf("soak round trip: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// soakRoundTrip performs one dial + DM bind + subtree search + unbind
// cycle against the server at addr.
func soakRoundTrip(addr string) error {
	nc, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer func() { _ = nc.Close() }()
	codec := NewBERCodec(BERCodecOptions{})
	ctx := context.Background()
	write := func(id int64, op Operation) error {
		_ = nc.SetWriteDeadline(time.Now().Add(5 * time.Second))
		return codec.WriteMessage(ctx, nc, &Message{ID: id, Op: op})
	}
	read := func() (*Message, error) {
		_ = nc.SetReadDeadline(time.Now().Add(5 * time.Second))
		return codec.ReadMessage(ctx, nc)
	}
	if err := write(1, &BindRequest{Version: 3, Name: "cn=Directory Manager", Password: []byte(diffDMFixturePassword)}); err != nil {
		return fmt.Errorf("bind write: %w", err)
	}
	m, err := read()
	if err != nil {
		return fmt.Errorf("bind read: %w", err)
	}
	if br, ok := m.Op.(*BindResponse); !ok || br.Result.Code != ResultSuccess {
		return fmt.Errorf("bind result: %T %v", m.Op, m.Op)
	}
	if err := write(2, &SearchRequest{
		BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
		Filter: &FilterPresent{Attr: "objectClass"},
	}); err != nil {
		return fmt.Errorf("search write: %w", err)
	}
	for {
		m, err := read()
		if err != nil {
			return fmt.Errorf("search read: %w", err)
		}
		if done, ok := m.Op.(*SearchResultDone); ok {
			if done.Result.Code != ResultSuccess {
				return fmt.Errorf("search result: %v", done.Result)
			}
			break
		}
	}
	// Unbind is fire-and-close: the server answers with a close.
	_ = write(3, &UnbindRequest{})
	return nil
}

// soakFDCount counts open file descriptors via /proc (Linux). On other
// platforms the FD assertion is skipped by reporting zero: the goroutine
// check remains the leak gate there.
func soakFDCount(t *testing.T) int {
	t.Helper()
	if runtime.GOOS != "linux" {
		return 0
	}
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(ents)
}
