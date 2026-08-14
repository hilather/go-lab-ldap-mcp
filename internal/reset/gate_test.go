package reset

import (
	"sync"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

func TestGateBlocksWhenNotReady(t *testing.T) {
	t.Parallel()
	g := NewGate()
	if err := g.Allow(t.Context()); err != nil {
		t.Fatal(err)
	}
	g.Set(Resetting)
	err := g.Allow(t.Context())
	if err == nil {
		t.Fatal("reset must block writes")
	}
	apperr.Assert(t, err).Code(apperr.CodeReset).Retryable(true)
	g.Set(Ready)
	if err := g.Allow(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestGateExclusiveBegin(t *testing.T) {
	t.Parallel()
	g := NewGate()
	tok, err := g.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if g.State() != PreparingReset {
		t.Fatalf("state %s", g.State())
	}
	if _, err := g.Begin(); err == nil {
		t.Fatal("second reset must be refused")
	} else {
		apperr.Assert(t, err).Code(apperr.CodeReset).Retryable(true)
	}
	if err := g.Advance(tok, Resetting); err != nil {
		t.Fatal(err)
	}
	if err := g.Allow(t.Context()); err == nil {
		t.Fatal("writes during reset")
	}
	if err := g.Advance(tok, Verifying); err != nil {
		t.Fatal(err)
	}
	g.Finish(tok, true, Operation{ExpectedRevision: "aaa", AppliedRevision: "aaa"})
	if g.State() != Ready {
		t.Fatalf("state %s", g.State())
	}
	if err := g.Allow(t.Context()); err != nil {
		t.Fatal(err)
	}
	last := g.Last()
	if last.ExpectedRevision != "aaa" || last.AppliedRevision != "aaa" || last.State != Ready {
		t.Fatalf("last %+v", last)
	}
}

func TestGateInvalidTransition(t *testing.T) {
	t.Parallel()
	g := NewGate()
	tok, err := g.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := g.Advance(tok, Verifying); err == nil {
		t.Fatal("PreparingReset -> Verifying")
	} else {
		apperr.Assert(t, err).Code(apperr.CodeReset)
	}
	stale := Token{gen: 99}
	if err := g.Advance(stale, Resetting); err == nil {
		t.Fatal("stale token")
	}
}

func TestGateFailedRetryAndMetrics(t *testing.T) {
	t.Parallel()
	m := &fakeMetrics{}
	g := NewGate()
	g.SetMetrics(m)
	tok, err := g.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if !m.inProgress() {
		t.Fatal("gauge")
	}
	g.Finish(tok, false, Operation{Error: "boom"})
	if g.State() != Failed {
		t.Fatalf("state %s", g.State())
	}
	if m.inProgress() {
		t.Fatal("failed is not in progress")
	}
	if m.outcomes()[0] != "failure" {
		t.Fatalf("outcomes %v", m.outcomes())
	}
	snap := g.Snapshot()
	if snap.Recovery == "" || snap.Error != "boom" {
		t.Fatalf("snapshot %+v", snap)
	}
	if _, err := g.Begin(); err != nil {
		t.Fatal("retry from Failed")
	}
}

func TestGateConcurrentBeginOneWins(t *testing.T) {
	t.Parallel()
	g := NewGate()
	var wg sync.WaitGroup
	errc := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := g.Begin()
			errc <- err
		}()
	}
	wg.Wait()
	close(errc)
	var ok, busy int
	for err := range errc {
		if err == nil {
			ok++
			continue
		}
		busy++
	}
	if ok != 1 || busy != 7 {
		t.Fatalf("ok=%d busy=%d", ok, busy)
	}
}

type fakeMetrics struct {
	mu   sync.Mutex
	prog bool
	got  []string
}

func (f *fakeMetrics) ObserveReset(outcome string) {
	f.mu.Lock()
	f.got = append(f.got, outcome)
	f.mu.Unlock()
}
func (f *fakeMetrics) SetResetInProgress(v bool) {
	f.mu.Lock()
	f.prog = v
	f.mu.Unlock()
}
func (f *fakeMetrics) inProgress() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.prog
}
func (f *fakeMetrics) outcomes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.got...)
}
