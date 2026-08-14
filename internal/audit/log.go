package audit

import (
	"context"
	"log/slog"

	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// LogSink writes secret-free structured audit lines.
type LogSink struct {
	Log *slog.Logger
}

func (s LogSink) Emit(ctx context.Context, ev Event) {
	if s.Log == nil {
		return
	}
	if ev.Time.IsZero() {
		// Leave time to the logger timestamp; still record request fields.
	}
	s.Log.InfoContext(ctx, "audit",
		slog.String("audit.action", ev.Action),
		slog.String("audit.actor", ev.Actor),
		slog.String("audit.target", ev.Target),
		slog.String("audit.result", ev.Result),
		slog.String("request_id", ev.RequestID),
		slog.String("audit.before", ev.Revisions.Before),
		slog.String("audit.after", ev.Revisions.After),
	)
}

// Sink is the production pair: structured log plus bounded ring.
type Sink struct {
	Ring *Ring
	Log  *slog.Logger
}

func NewSink(log *slog.Logger, capacity int) *Sink {
	return &Sink{Ring: NewRing(capacity), Log: log}
}

func (s *Sink) Emit(ctx context.Context, ev Event) {
	if s == nil {
		return
	}
	if ev.RequestID == "" {
		ev.RequestID = observability.RequestID(ctx)
	}
	if s.Ring != nil {
		s.Ring.Emit(ctx, ev)
	}
	LogSink{Log: s.Log}.Emit(ctx, ev)
}

func (s *Sink) List(ctx context.Context, q ListQuery) (Page, error) {
	if s == nil || s.Ring == nil {
		return Page{Items: []Event{}}, nil
	}
	return s.Ring.List(ctx, q)
}
