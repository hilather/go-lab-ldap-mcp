package app

import (
	"context"
	"sync"

	"github.com/hilather/go-lab-ldap-mcp/internal/audit"
	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// Authorizer is invoked inside every application command (T-057), not only
// in transport middleware.
type Authorizer interface {
	Authorize(p Principal, op Operation) error
}

// ScopeAuthorizer checks exact scope membership. directory:write does not
// imply password, reset, or export.
type ScopeAuthorizer struct{}

func (ScopeAuthorizer) Authorize(p Principal, op Operation) error {
	return auth.Require(p.Scopes, op.Scope)
}

// Auditor receives success and failure intents without secrets.
type Auditor interface {
	Record(ctx context.Context, ev AuditIntent)
}

// MemoryAuditor is a test hook. It never stores passwords or tokens.
type MemoryAuditor struct {
	mu     sync.Mutex
	Events []AuditIntent
}

func (a *MemoryAuditor) Record(_ context.Context, ev AuditIntent) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Events = append(a.Events, ev)
}

func (a *MemoryAuditor) Snapshot() []AuditIntent {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditIntent, len(a.Events))
	copy(out, a.Events)
	return out
}

// RateLimiter is a hook point for password and bind-test limits (T-065 wires it).
type RateLimiter interface {
	Allow(ctx context.Context, key string) error
}

// MutationGate blocks ordinary writes when a reset is in progress (T-058).
// AllowRead blocks directory reads once mutation begins; Failed stays readable.
type MutationGate interface {
	Allow(ctx context.Context) error
	AllowRead(ctx context.Context) error
}

// OpenGate never blocks. Reset replaces this with a real exclusive gate.
type OpenGate struct{}

func (OpenGate) Allow(context.Context) error     { return nil }
func (OpenGate) AllowRead(context.Context) error { return nil }

// HookAuditor forwards application intents to audit.Hook without secrets.
type HookAuditor struct {
	Hook audit.Hook
}

func (h HookAuditor) Record(ctx context.Context, ev AuditIntent) {
	if h.Hook == nil {
		return
	}
	h.Hook.Emit(ctx, audit.Event{
		RequestID: ev.RequestID,
		Actor:     ev.Actor,
		Action:    ev.Action,
		Target:    ev.Target,
		Result:    ev.Result,
		Revisions: audit.Revisions{Before: ev.Before, After: ev.After},
	})
}

func actorOf(p Principal) string {
	if p.ID == "" {
		return p.Kind
	}
	return p.Kind + ":" + p.ID
}

func requestID(ctx context.Context) string {
	return observability.RequestID(ctx)
}
