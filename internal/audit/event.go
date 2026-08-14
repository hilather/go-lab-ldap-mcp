package audit

import (
	"context"
	"sync"
	"time"
)

// Event is a secret-free security or mutation record.
type Event struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"requestId"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Result    string    `json:"result"`
	Revisions Revisions `json:"revisions"`
}

type Revisions struct {
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// Hook receives application audit intents. Implementations must not log secrets.
type Hook interface {
	Emit(ctx context.Context, ev Event)
}

// Memory is a test/process-local sink.
type Memory struct {
	mu     sync.Mutex
	Events []Event
}

func (m *Memory) Emit(_ context.Context, ev Event) {
	if m == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Events = append(m.Events, ev)
}

func (m *Memory) Snapshot() []Event {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Event, len(m.Events))
	copy(out, m.Events)
	return out
}
