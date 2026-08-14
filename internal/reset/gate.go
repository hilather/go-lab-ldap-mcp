package reset

import (
	"context"
	"sync"

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

// Gate is the reset-ready global mutation lock (T-058). Ordinary writes
// fail with retryable reset_in_progress when state is not Ready.
type Gate struct {
	mu    sync.Mutex
	state State
}

func NewGate() *Gate { return &Gate{state: Ready} }

func (g *Gate) State() State {
	if g == nil {
		return Ready
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.state == "" {
		return Ready
	}
	return g.state
}

func (g *Gate) Set(s State) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.state = s
}

func (g *Gate) Allow(context.Context) error {
	if g == nil || g.State() == Ready {
		return nil
	}
	return apperr.New(apperr.CodeReset, "reset in progress").
		WithField(apperr.Field{Path: "reset", Code: "reset_in_progress", Message: "reset in progress"}).
		Retry()
}
