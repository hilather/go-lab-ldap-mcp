package reset

import (
	"context"
	"sync"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
)

type State string

const (
	Ready          State = "Ready"
	PreparingReset State = "PreparingReset"
	Resetting      State = "Resetting"
	Verifying      State = "Verifying"
	Failed         State = "Failed"
)

// Metrics is the secret-free reset telemetry hook (T-076). Implementations
// must not label with DNs, revisions, or request IDs.
type Metrics interface {
	ObserveReset(outcome string)
	SetResetInProgress(v bool)
}

// Token is an exclusive Begin generation. Finish/Advance ignore stale tokens.
type Token struct{ gen uint64 }

// Operation is the current or last reset status. No secrets.
type Operation struct {
	Phase             string
	State             State
	Counts            Counts
	ExpectedRevision  string
	AppliedRevision   string
	InventoryChecksum string
	Error             string
	Recovery          string
	StartedAt         time.Time
	FinishedAt        time.Time
}

type Counts struct {
	Deleted int
	Users   int
	Groups  int
	Extra   int
}

// Gate is the exclusive reset lock and validated state machine (T-076).
// Ordinary writes fail with retryable reset_in_progress when state is not Ready.
type Gate struct {
	mu      sync.Mutex
	state   State
	gen     uint64
	metrics Metrics
	cur     Operation
	last    Operation
}

func NewGate() *Gate { return &Gate{state: Ready} }

func (g *Gate) SetMetrics(m Metrics) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.metrics = m
}

func (g *Gate) State() State {
	if g == nil {
		return Ready
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.stateOrReady()
}

func (g *Gate) stateOrReady() State {
	if g.state == "" {
		return Ready
	}
	return g.state
}

// Set is a test hook. Production transitions use Begin/Advance/Finish.
func (g *Gate) Set(s State) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state = s
	g.syncMetricsLocked()
}

func (g *Gate) Allow(context.Context) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	st := g.stateOrReady()
	g.mu.Unlock()
	if st == Ready {
		return nil
	}
	return InProgress()
}

// InProgress is the stable ordinary-write admission error.
func InProgress() *apperr.Error {
	return apperr.New(apperr.CodeReset, "reset in progress").
		WithField(apperr.Field{Path: "reset", Code: "reset_in_progress", Message: "reset in progress"}).
		Retry()
}

// Busy is the exclusive-lock conflict when a second reset is requested.
func Busy() *apperr.Error {
	return InProgress()
}

func Disabled() *apperr.Error {
	return apperr.New(apperr.CodeReset, "soft reset is disabled").
		WithField(apperr.Field{Path: "reset", Code: "disabled", Message: "lifecycle.softReset is false"})
}

// Begin acquires the exclusive reset lock. Ready and Failed may start;
// PreparingReset, Resetting, and Verifying refuse a second reset.
func (g *Gate) Begin() (Token, error) {
	if g == nil {
		return Token{}, apperr.New(apperr.CodeReset, "reset gate is not configured").
			WithField(apperr.Field{Path: "reset", Code: "unavailable", Message: "reset gate is not configured"})
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.stateOrReady()
	if st != Ready && st != Failed {
		return Token{}, Busy()
	}
	if g.cur.State != "" && g.cur.State != Ready {
		g.last = g.cur
	}
	g.gen++
	g.state = PreparingReset
	g.cur = Operation{Phase: string(PreparingReset), State: PreparingReset, StartedAt: time.Now().UTC()}
	g.syncMetricsLocked()
	return Token{gen: g.gen}, nil
}

// Advance validates and records a phase change for tok.
func (g *Gate) Advance(tok Token, to State) error {
	if g == nil {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if tok.gen == 0 || tok.gen != g.gen {
		return apperr.New(apperr.CodeReset, "reset token is stale").
			WithField(apperr.Field{Path: "reset", Code: "stale", Message: "reset token is stale"})
	}
	from := g.stateOrReady()
	if !validTransition(from, to) {
		return apperr.New(apperr.CodeReset, "invalid reset transition").
			WithField(apperr.Field{Path: "reset", Code: "invalid_transition", Message: string(from) + " -> " + string(to)})
	}
	g.state = to
	g.cur.State = to
	g.cur.Phase = string(to)
	g.syncMetricsLocked()
	return nil
}

// Finish releases the lock. Success returns to Ready; failure stays Failed.
func (g *Gate) Finish(tok Token, ok bool, op Operation) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if tok.gen == 0 || tok.gen != g.gen {
		return
	}
	if ok {
		g.state = Ready
		op.State = Ready
		op.Phase = string(Ready)
	} else {
		g.state = Failed
		op.State = Failed
		if op.Phase == "" {
			op.Phase = string(Failed)
		}
		if op.Recovery == "" {
			op.Recovery = RecoveryInstructions
		}
	}
	if op.StartedAt.IsZero() {
		op.StartedAt = g.cur.StartedAt
	}
	op.FinishedAt = time.Now().UTC()
	g.cur = op
	g.last = op
	if g.metrics != nil {
		if ok {
			g.metrics.ObserveReset("success")
		} else {
			g.metrics.ObserveReset("failure")
		}
	}
	g.syncMetricsLocked()
}

func (g *Gate) Update(tok Token, fn func(*Operation)) {
	if g == nil || fn == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if tok.gen == 0 || tok.gen != g.gen {
		return
	}
	fn(&g.cur)
}

func (g *Gate) Current() Operation {
	if g == nil {
		return Operation{State: Ready, Phase: string(Ready)}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cur
}

func (g *Gate) Last() Operation {
	if g == nil {
		return Operation{}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last
}

// Snapshot is current if a reset is active, otherwise last.
func (g *Gate) Snapshot() Operation {
	if g == nil {
		return Operation{State: Ready, Phase: string(Ready)}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.stateOrReady()
	if st != Ready && st != Failed && g.cur.State != "" {
		return g.cur
	}
	if g.cur.State != "" {
		return g.cur
	}
	if g.last.State != "" {
		return g.last
	}
	return Operation{State: st, Phase: string(st)}
}

// MarkFailed records an unresolved baseline without starting a reset.
// A running reset is left unchanged.
func (g *Gate) MarkFailed(reason string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	st := g.stateOrReady()
	if st == PreparingReset || st == Resetting || st == Verifying {
		return
	}
	g.state = Failed
	g.cur = Operation{
		Phase:     string(Failed),
		State:     Failed,
		Error:     reason,
		Recovery:  RecoveryInstructions,
		StartedAt: time.Now().UTC(),
	}
	g.last = g.cur
	g.syncMetricsLocked()
}

func (g *Gate) InProgress() bool {
	if g == nil {
		return false
	}
	st := g.State()
	return st == PreparingReset || st == Resetting || st == Verifying
}

func (g *Gate) syncMetricsLocked() {
	if g.metrics == nil {
		return
	}
	st := g.stateOrReady()
	g.metrics.SetResetInProgress(st == PreparingReset || st == Resetting || st == Verifying)
}

func validTransition(from, to State) bool {
	if from == to {
		return true
	}
	switch from {
	case Ready:
		return to == PreparingReset
	case Failed:
		return to == PreparingReset
	case PreparingReset:
		return to == Resetting || to == Ready || to == Failed
	case Resetting:
		return to == Verifying || to == Failed
	case Verifying:
		return to == Ready || to == Failed
	default:
		return false
	}
}
