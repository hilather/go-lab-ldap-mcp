package ldapserver

import "context"

// WriteOp identifies the mutating operation a Plugin is observing.
type WriteOp int

const (
	WriteAdd WriteOp = iota + 1
	WriteModify
	WriteDelete
	WriteRename
)

// String returns a stable lowercase name for structured logs.
func (op WriteOp) String() string {
	switch op {
	case WriteAdd:
		return "add"
	case WriteModify:
		return "modify"
	case WriteDelete:
		return "delete"
	case WriteRename:
		return "rename"
	default:
		return "unknown"
	}
}

// WriteEvent describes one committed-shape write to a Plugin. Before is nil
// for WriteAdd, After is nil for WriteDelete, and a rename reports the old
// DN on Before and the new DN on After.
type WriteEvent struct {
	Op     WriteOp
	Before *Entry
	After  *Entry
}

// Plugin is a write-path hook running inside the same store transaction as
// the write it follows, so derived state commits atomically with its cause
// (parity contract C7). The MemberOf plugin (T-135) maintains memberOf and
// auto-adds nsmemberof; the referential integrity plugin (T-136) repairs
// member references on delete. Plugins are suffix-scoped and must not panic
// on adversarial entry content.
type Plugin interface {
	// Name is a short stable identifier for logs and diagnostics.
	Name() string
	// AfterWrite runs inside the Update transaction after the write has been
	// applied to tx. Returning an error aborts the whole commit, including
	// the original write.
	AfterWrite(ctx context.Context, tx UpdateTx, ev WriteEvent) error
}
