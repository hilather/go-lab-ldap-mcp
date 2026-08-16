package ldapserver

import (
	"context"
	"errors"
	"strings"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Store-domain conditions returned by Store transactions. Dispatch maps them
// to LDAP result codes (noSuchObject, entryAlreadyExists,
// notAllowedOnNonLeaf); compare with errors.Is through wrapping.
var (
	ErrNoSuchObject   = errors.New("ldapserver: no such entry")
	ErrEntryExists    = errors.New("ldapserver: entry already exists")
	ErrNotLeaf        = errors.New("ldapserver: entry has children")
	ErrRenameIntoSelf = errors.New("ldapserver: cannot rename an entry into its own subtree")
	ErrStoreClosed    = errors.New("ldapserver: store is closed")
)

// Entry is one directory entry. DN holds the canonical string form produced
// by internal/config DN parsing; lookups fold case, so DN casing on the
// entry is presentation, not identity.
type Entry struct {
	DN         string
	Attributes []Attribute
}

// Values returns the values of the named attribute. Attribute names are
// matched case-insensitively (RFC 4512).
func (e *Entry) Values(name string) [][]byte {
	if e == nil {
		return nil
	}
	for _, a := range e.Attributes {
		if strings.EqualFold(a.Name, name) {
			return a.Values
		}
	}
	return nil
}

// Store is the entry-store seam consumed by operation dispatch. One Update
// call is one MVCC commit (ADR-0009 decision 7): a handler reads, verifies,
// and writes inside a single Update so the RFC 4528 assertion control
// (T-141) is atomic, and Plugin.AfterWrite hooks run in the same transaction
// so derived attributes such as memberOf commit with the write that caused
// them (parity contract C7).
//
// The bbolt implementation lands in internal/ldapserver/store (T-129);
// equality indices for uid, cn, member, uniqueMember, and objectClass are
// internal to it (ADR-0009 decision 8) and do not appear on this interface.
type Store interface {
	// View runs fn against a read-only snapshot.
	View(ctx context.Context, fn func(tx ReadTx) error) error
	// Update runs fn against a read-write transaction and commits when fn
	// returns nil. A non-nil error rolls the transaction back.
	Update(ctx context.Context, fn func(tx UpdateTx) error) error
	// Close releases store resources. It is called once at shutdown.
	Close() error
}

// ReadTx is the read side of a store transaction. DN arguments are parsed
// internal/config DNs so comparison is structural, never string-suffix
// matching (T-131 reuses those helpers).
type ReadTx interface {
	// Entry returns the entry at exactly dn, or ErrNoSuchObject.
	Entry(ctx context.Context, dn config.DN) (*Entry, error)
	// Children returns the immediate subordinates of dn, or ErrNoSuchObject
	// when dn is absent. Order is implementation-defined.
	Children(ctx context.Context, dn config.DN) ([]*Entry, error)
	// Subtree returns dn and every descendant, or ErrNoSuchObject when dn is
	// absent. Order is implementation-defined; search size limits are
	// enforced by the server, not the store.
	Subtree(ctx context.Context, dn config.DN) ([]*Entry, error)
}

// UpdateTx adds the write primitives needed by Add, Modify, Delete, and
// ModifyDN dispatch.
type UpdateTx interface {
	ReadTx
	// Add inserts a leaf entry. ErrEntryExists when the DN is taken;
	// invalid DNs are rejected with the internal/config parse error.
	Add(ctx context.Context, entry *Entry) error
	// Replace stores entry at its DN, replacing all attributes. It returns
	// ErrNoSuchObject when the entry is absent; Modify dispatch reads the
	// prior entry, applies changes, and writes through here.
	Replace(ctx context.Context, entry *Entry) error
	// Delete removes one leaf entry: ErrNoSuchObject when absent and
	// ErrNotLeaf when it has subordinates. Dispatch decides the
	// notAllowedOnNonLeaf policy; the store guard keeps the tree consistent.
	Delete(ctx context.Context, dn config.DN) error
	// Rename moves the entry at from to to, atomically rewriting every
	// descendant DN. ErrNoSuchObject when from is absent, ErrEntryExists
	// when to is taken, ErrRenameIntoSelf when to is a fold-equal
	// descendant of from (D16).
	Rename(ctx context.Context, from, to config.DN) error
}
