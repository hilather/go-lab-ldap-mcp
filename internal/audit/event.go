package audit

import (
	"context"
	"sync"
	"time"
)

// Taxonomy of mutation and security actions (T-071). Every named event
// type in the design is representable. Search is optional and must not
// include filters.
const (
	ActionAuthenticate        = "authenticate"
	ActionSessionCreate       = "session.create"
	ActionSessionDestroy      = "session.destroy"
	ActionUserCreate          = "user.create"
	ActionUserUpdate          = "user.update"
	ActionUserDelete          = "user.delete"
	ActionUserSetEnabled      = "user.set_enabled"
	ActionUserSetPassword     = "user.set_password"
	ActionUserAccountState    = "user.account_state"
	ActionUserExpirePassword  = "user.expire_password"
	ActionUserClearExpiry     = "user.clear_password_expiry"
	ActionUserLock            = "user.lock"
	ActionUserUnlock          = "user.unlock"
	ActionGroupCreate         = "group.create"
	ActionGroupDelete         = "group.delete"
	ActionGroupMembers        = "group.members"
	ActionGroupAddMembers     = "group.add_members"
	ActionGroupRemoveMembers  = "group.remove_members"
	ActionGroupReplaceMembers = "group.replace_members"
	ActionBindTest            = "bind_test"
	ActionReset               = "reset"
	ActionExport              = "export"
	ActionAuthzDeny           = "authz.deny"
)

const (
	ResultSuccess = "success"
	ResultFailure = "failure"
)

// KnownActions is the closed taxonomy. Unknown actions may still be stored
// so a later reset/export service can emit without a ring change.
func KnownActions() []string {
	return []string{
		ActionAuthenticate,
		ActionSessionCreate,
		ActionSessionDestroy,
		ActionUserCreate,
		ActionUserUpdate,
		ActionUserDelete,
		ActionUserSetEnabled,
		ActionUserSetPassword,
		ActionUserAccountState,
		ActionUserExpirePassword,
		ActionUserClearExpiry,
		ActionUserLock,
		ActionUserUnlock,
		ActionGroupCreate,
		ActionGroupDelete,
		ActionGroupMembers,
		ActionGroupAddMembers,
		ActionGroupRemoveMembers,
		ActionGroupReplaceMembers,
		ActionBindTest,
		ActionReset,
		ActionExport,
		ActionAuthzDeny,
	}
}

// Event is a secret-free security or mutation record (§3.8 AuditEvent).
type Event struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"requestId"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Result    string    `json:"result"`
	Revisions Revisions `json:"revisions"`
	// Seq is the process-local ring sequence. Not part of the REST body.
	Seq uint64 `json:"-"`
}

type Revisions struct {
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// Hook receives application audit intents. Implementations must not log secrets.
type Hook interface {
	Emit(ctx context.Context, ev Event)
}

// Lister is the query surface for GET /api/v1/audit.
type Lister interface {
	List(ctx context.Context, q ListQuery) (Page, error)
}

// ListQuery is the §3.8 audit filter (action, actor, cursor, pageSize).
type ListQuery struct {
	Action   string
	Actor    string
	PageSize int
	AfterSeq uint64
}

// Page is the list envelope items plus the next ring sequence cursor.
type Page struct {
	Items   []Event
	NextSeq uint64
	HasMore bool
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

func (m *Memory) List(_ context.Context, q ListQuery) (Page, error) {
	if m == nil {
		return Page{Items: []Event{}}, nil
	}
	items := filterEvents(m.Snapshot(), q)
	return paginate(items, q), nil
}

// Multi fans Emit out to every hook. List uses the first Lister.
type Multi struct {
	Hooks []Hook
	Query Lister
}

func (m Multi) Emit(ctx context.Context, ev Event) {
	for _, h := range m.Hooks {
		if h != nil {
			h.Emit(ctx, ev)
		}
	}
}

func (m Multi) List(ctx context.Context, q ListQuery) (Page, error) {
	if m.Query != nil {
		return m.Query.List(ctx, q)
	}
	return Page{Items: []Event{}}, nil
}
