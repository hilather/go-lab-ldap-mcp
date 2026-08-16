package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	bolt "go.etcd.io/bbolt"
)

// Bucket layout (ADR-0009 decision 8):
//
//	dn2id    folded DN (config.DN.FoldedKey) -> 8-byte big-endian entry id
//	id2entry 8-byte big-endian id -> serialized entry (see codec.go)
//	children nested bucket per parent folded DN; keys are child ids
//
// Ids are stable across Rename, so the children index only changes at the
// renamed root's parent linkage and at the nested-bucket keys of moved
// parents. Entry ids never reuse: dn2id lookups are the sole existence
// oracle, so a stale index entry always resolves through dn2id/id2entry.
var (
	bucketDN2ID    = []byte("dn2id")
	bucketID2Entry = []byte("id2entry")
	bucketChildren = []byte("children")
)

// fileMode is the required database file permission (ADR-0009 decision 5).
const fileMode = 0o600

// ErrEmptyPath reports Open called without a database path. It is a stable
// sentinel: callers test with errors.Is instead of matching message text.
var ErrEmptyPath = errors.New("store: empty database path")

// Store is the bbolt-backed ldapserver.Store. One Update is one bbolt
// transaction, so a committed write is crash-safe (ACID) and concurrent
// readers observe pre- or post-commit snapshots, never a partial write
// (MVCC). Writers serialize inside bbolt; db.Batch is deliberately not
// used so each Update commits on its own.
type Store struct {
	mu     sync.RWMutex
	db     *bolt.DB
	closed bool
}

var _ ldapserver.Store = (*Store)(nil)

// Open opens or creates the database at path, creating buckets on first
// use and tightening the file mode to 0600. Errors are wrapped with the
// operation and never carry database file contents.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	db, err := bolt.Open(path, fileMode, nil)
	if err != nil {
		return nil, fmt.Errorf("store: open database: %w", err)
	}
	fail := func(err error) (*Store, error) {
		_ = db.Close()
		return nil, err
	}
	// bbolt applies the mode only at creation; enforce it on reopen too.
	if err := os.Chmod(path, fileMode); err != nil {
		return fail(fmt.Errorf("store: set database file mode: %w", err))
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketDN2ID, bucketID2Entry, bucketChildren} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		version, err := IndexVersion(tx)
		if err != nil {
			return err
		}
		if err := EnsureIndexBuckets(tx); err != nil {
			return err
		}
		if version != indexVersion {
			// Database predates the equality indices or the posting format
			// changed: rebuild from id2entry once, inside this transaction.
			if err := RebuildIndexes(tx, storeEntryIter(tx)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return fail(fmt.Errorf("store: initialize buckets: %w", err))
	}
	return &Store{db: db}, nil
}

// View runs fn against a read-only snapshot. The context is honored before
// the blocking bbolt call and again before the result is returned; a
// cancelled context after a successful read still reports cancellation so
// callers do not act on stale work.
func (s *Store) View(ctx context.Context, fn func(tx ldapserver.ReadTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return fmt.Errorf("store: view: %w", ldapserver.ErrStoreClosed)
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(readTx{tx: tx})
	})
	if err != nil {
		return err
	}
	return ctx.Err()
}

// Update runs fn inside a single read-write transaction and commits when
// fn returns nil; a non-nil error rolls back. The context is checked
// before the blocking call and inside the transaction, but not after
// commit: reporting cancellation for a write that already durably
// committed would mislead callers into retrying a successful mutation.
func (s *Store) Update(ctx context.Context, fn func(tx ldapserver.UpdateTx) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return fmt.Errorf("store: update: %w", ldapserver.ErrStoreClosed)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return fn(updateTx{readTx: readTx{tx: tx}})
	})
}

// Close releases the database file. Later View/Update calls fail with
// ldapserver.ErrStoreClosed. Close is idempotent.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := s.db.Close(); err != nil {
		return fmt.Errorf("store: close database: %w", err)
	}
	return nil
}

type readTx struct {
	tx *bolt.Tx
}

var _ ldapserver.ReadTx = readTx{}

func (t readTx) Entry(ctx context.Context, dn config.DN) (*ldapserver.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	id := t.tx.Bucket(bucketDN2ID).Get([]byte(dn.FoldedKey()))
	if id == nil {
		return nil, fmt.Errorf("store: entry: %w", ldapserver.ErrNoSuchObject)
	}
	return t.entryByID(id)
}

func (t readTx) Children(ctx context.Context, dn config.DN) ([]*ldapserver.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.tx.Bucket(bucketDN2ID).Get([]byte(dn.FoldedKey())) == nil {
		return nil, fmt.Errorf("store: children: %w", ldapserver.ErrNoSuchObject)
	}
	kids := t.tx.Bucket(bucketChildren).Bucket([]byte(dn.FoldedKey()))
	if kids == nil {
		return nil, nil
	}
	var out []*ldapserver.Entry
	err := kids.ForEach(func(id, _ []byte) error {
		e, err := t.entryByID(id)
		if err != nil {
			return err
		}
		out = append(out, e)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: children: %w", err)
	}
	return out, nil
}

func (t readTx) Subtree(ctx context.Context, dn config.DN) ([]*ldapserver.Entry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	base := dn.FoldedKey()
	id := t.tx.Bucket(bucketDN2ID).Get([]byte(base))
	if id == nil {
		return nil, fmt.Errorf("store: subtree: %w", ldapserver.ErrNoSuchObject)
	}
	var out []*ldapserver.Entry
	queue := [][]byte{[]byte(base)}
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		id := t.tx.Bucket(bucketDN2ID).Get(key)
		if id == nil {
			// A children-index key without a dn2id entry is unreachable
			// through the write path; skip defensively rather than panic.
			continue
		}
		e, err := t.entryByID(id)
		if err != nil {
			return nil, fmt.Errorf("store: subtree: %w", err)
		}
		out = append(out, e)
		if kids := t.tx.Bucket(bucketChildren).Bucket(key); kids != nil {
			err := kids.ForEach(func(childID, _ []byte) error {
				childEntry, err := t.entryByID(childID)
				if err != nil {
					return err
				}
				d, err := config.ParseDN(childEntry.DN)
				if err != nil {
					return fmt.Errorf("store: subtree: %w", err)
				}
				queue = append(queue, []byte(d.FoldedKey()))
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("store: subtree: %w", err)
			}
		}
	}
	return out, nil
}

// entryByID loads and decodes one entry. The id came from dn2id or the
// children index inside the same transaction, so a missing or corrupt
// blob indicates store corruption, surfaced as a plain error.
func (t readTx) entryByID(id []byte) (*ldapserver.Entry, error) {
	blob := t.tx.Bucket(bucketID2Entry).Get(id)
	if blob == nil {
		return nil, fmt.Errorf("store: entry id %d: %w", idUint64(id), ldapserver.ErrNoSuchObject)
	}
	e, err := decodeEntry(blob)
	if err != nil {
		return nil, fmt.Errorf("store: decode entry id %d: %w", idUint64(id), err)
	}
	return e, nil
}

type updateTx struct {
	readTx
}

var _ ldapserver.UpdateTx = updateTx{}

func (t updateTx) Add(ctx context.Context, entry *ldapserver.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d, err := config.ParseDN(entry.DN)
	if err != nil {
		return fmt.Errorf("store: add: %w", err)
	}
	key := []byte(d.FoldedKey())
	if t.tx.Bucket(bucketDN2ID).Get(key) != nil {
		return fmt.Errorf("store: add: %w", ldapserver.ErrEntryExists)
	}
	id, err := t.tx.Bucket(bucketID2Entry).NextSequence()
	if err != nil {
		return fmt.Errorf("store: add: allocate entry id: %w", err)
	}
	idb := uint64Bytes(id)
	stored := &ldapserver.Entry{DN: d.String(), Attributes: entry.Attributes}
	blob, err := encodeEntry(stored)
	if err != nil {
		return fmt.Errorf("store: add: %w", err)
	}
	if err := t.tx.Bucket(bucketDN2ID).Put(key, idb); err != nil {
		return fmt.Errorf("store: add: %w", err)
	}
	if err := t.tx.Bucket(bucketID2Entry).Put(idb, blob); err != nil {
		return fmt.Errorf("store: add: %w", err)
	}
	if err := t.linkChild(d, idb); err != nil {
		return err
	}
	// Equality postings commit in this same transaction (T-130).
	if err := AddPostings(t.tx, id, stored); err != nil {
		return fmt.Errorf("store: add: %w", err)
	}
	return nil
}

func (t updateTx) Replace(ctx context.Context, entry *ldapserver.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d, err := config.ParseDN(entry.DN)
	if err != nil {
		return fmt.Errorf("store: replace: %w", err)
	}
	key := []byte(d.FoldedKey())
	id := t.tx.Bucket(bucketDN2ID).Get(key)
	if id == nil {
		return fmt.Errorf("store: replace: %w", ldapserver.ErrNoSuchObject)
	}
	old, err := decodeEntry(t.tx.Bucket(bucketID2Entry).Get(id))
	if err != nil {
		return fmt.Errorf("store: replace: %w", err)
	}
	stored := &ldapserver.Entry{DN: d.String(), Attributes: entry.Attributes}
	blob, err := encodeEntry(stored)
	if err != nil {
		return fmt.Errorf("store: replace: %w", err)
	}
	if err := t.tx.Bucket(bucketID2Entry).Put(id, blob); err != nil {
		return fmt.Errorf("store: replace: %w", err)
	}
	// Swap equality postings in the same transaction as the entry write.
	if err := ReindexEntry(t.tx, idUint64(id), old, stored); err != nil {
		return fmt.Errorf("store: replace: %w", err)
	}
	return nil
}

func (t updateTx) Delete(ctx context.Context, dn config.DN) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := []byte(dn.FoldedKey())
	id := t.tx.Bucket(bucketDN2ID).Get(key)
	if id == nil {
		return fmt.Errorf("store: delete: %w", ldapserver.ErrNoSuchObject)
	}
	if kids := t.tx.Bucket(bucketChildren).Bucket(key); kids != nil {
		if k, _ := kids.Cursor().First(); k != nil {
			return fmt.Errorf("store: delete: %w", ldapserver.ErrNotLeaf)
		}
	}
	old, err := decodeEntry(t.tx.Bucket(bucketID2Entry).Get(id))
	if err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	if err := t.unlinkChild(dn, id); err != nil {
		return err
	}
	if err := t.tx.Bucket(bucketChildren).DeleteBucket(key); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
		return fmt.Errorf("store: delete: %w", err)
	}
	if err := t.tx.Bucket(bucketDN2ID).Delete(key); err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	if err := t.tx.Bucket(bucketID2Entry).Delete(id); err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	// Drop equality postings in the same transaction as the entry delete.
	if err := RemovePostings(t.tx, idUint64(id), old); err != nil {
		return fmt.Errorf("store: delete: %w", err)
	}
	return nil
}

func (t updateTx) Rename(ctx context.Context, from, to config.DN) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fromKey, toKey := from.FoldedKey(), to.FoldedKey()
	if t.tx.Bucket(bucketDN2ID).Get([]byte(fromKey)) == nil {
		return fmt.Errorf("store: rename: %w", ldapserver.ErrNoSuchObject)
	}
	if t.tx.Bucket(bucketDN2ID).Get([]byte(toKey)) != nil {
		return fmt.Errorf("store: rename: %w", ldapserver.ErrEntryExists)
	}
	// D16 defense in depth: a folded descendant destination would
	// prefix-swap the children index off the tree.
	if to.IsDescendantOfFold(from) {
		return fmt.Errorf("store: rename: %w", ldapserver.ErrRenameIntoSelf)
	}
	moves, err := t.collectMoves(from, to)
	if err != nil {
		return err
	}
	// Every destination key must be free before any write, so a clash
	// leaves the transaction untouched (FakeStore parity).
	for _, m := range moves {
		if m.newKey == m.oldKey {
			continue
		}
		if t.tx.Bucket(bucketDN2ID).Get([]byte(m.newKey)) != nil {
			return fmt.Errorf("store: rename: %w", ldapserver.ErrEntryExists)
		}
	}
	for _, m := range moves {
		if err := t.tx.Bucket(bucketDN2ID).Delete([]byte(m.oldKey)); err != nil {
			return fmt.Errorf("store: rename: %w", err)
		}
		if err := t.tx.Bucket(bucketDN2ID).Put([]byte(m.newKey), m.id); err != nil {
			return fmt.Errorf("store: rename: %w", err)
		}
		blob, err := encodeEntry(&ldapserver.Entry{DN: m.newDN, Attributes: m.entry.Attributes})
		if err != nil {
			return fmt.Errorf("store: rename: %w", err)
		}
		if err := t.tx.Bucket(bucketID2Entry).Put(m.id, blob); err != nil {
			return fmt.Errorf("store: rename: %w", err)
		}
	}
	if err := t.moveChildBuckets(moves); err != nil {
		return err
	}
	// The subtree's internal parent-child links are keyed by ids and the
	// moved parents' bucket keys; only the root's link to its parent
	// changes.
	//
	// Equality postings need no work here (T-130): ids and attribute
	// values are stable across Rename, so value -> id postings stay valid.
	// The RDN attribute maintenance for deleteoldrdn is applied by
	// handleModifyDN through a follow-up Replace, which reindexes.
	return t.relinkRoot(from, to)
}

// move is one subtree member scheduled for a Rename. Ids are preserved;
// only keys, DN strings, and children-index bucket keys change.
type move struct {
	oldKey, newKey, newDN string
	id                    []byte
	entry                 *ldapserver.Entry
}

// collectMoves walks the children index from from and computes each
// descendant's destination. Canonical stored DNs end with from's canonical
// string (folding lowercases without changing length), so the destination
// is a prefix swap on both forms.
func (t updateTx) collectMoves(from, to config.DN) ([]move, error) {
	fromKey, toKey := from.FoldedKey(), to.FoldedKey()
	fromDN, toDN := from.String(), to.String()
	var moves []move
	queue := []string{fromKey}
	for len(queue) > 0 {
		key := queue[0]
		queue = queue[1:]
		id := t.tx.Bucket(bucketDN2ID).Get([]byte(key))
		if id == nil {
			continue
		}
		e, err := t.entryByID(id)
		if err != nil {
			return nil, fmt.Errorf("store: rename: %w", err)
		}
		moves = append(moves, move{
			oldKey: key,
			newKey: key[:len(key)-len(fromKey)] + toKey,
			newDN:  e.DN[:len(e.DN)-len(fromDN)] + toDN,
			id:     append([]byte(nil), id...),
			entry:  e,
		})
		if kids := t.tx.Bucket(bucketChildren).Bucket([]byte(key)); kids != nil {
			err := kids.ForEach(func(childID, _ []byte) error {
				childEntry, err := t.entryByID(childID)
				if err != nil {
					return err
				}
				d, err := config.ParseDN(childEntry.DN)
				if err != nil {
					return fmt.Errorf("store: rename: %w", err)
				}
				queue = append(queue, d.FoldedKey())
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("store: rename: %w", err)
			}
		}
	}
	return moves, nil
}

// moveChildBuckets re-keys the children-index nested bucket of every moved
// entry that has children.
func (t updateTx) moveChildBuckets(moves []move) error {
	children := t.tx.Bucket(bucketChildren)
	for _, m := range moves {
		if m.newKey == m.oldKey {
			continue
		}
		src := children.Bucket([]byte(m.oldKey))
		if src == nil {
			continue
		}
		// Merge rather than create: entries may already be indexed under
		// the destination key if children were added before their parent
		// existed (the store does not require parent presence; dispatch
		// does). Ids are unique, so the sets cannot overlap.
		dst, err := children.CreateBucketIfNotExists([]byte(m.newKey))
		if err != nil {
			return fmt.Errorf("store: rename: move children index: %w", err)
		}
		err = src.ForEach(func(id, _ []byte) error {
			return dst.Put(id, nil)
		})
		if err != nil {
			return fmt.Errorf("store: rename: move children index: %w", err)
		}
		if err := children.DeleteBucket([]byte(m.oldKey)); err != nil {
			return fmt.Errorf("store: rename: move children index: %w", err)
		}
	}
	return nil
}

// relinkRoot moves the renamed root's id from the old parent's child set
// to the new parent's. Depth-1 DNs have no parent link.
func (t updateTx) relinkRoot(from, to config.DN) error {
	id := t.tx.Bucket(bucketDN2ID).Get([]byte(to.FoldedKey()))
	if id == nil {
		return fmt.Errorf("store: rename: %w", ldapserver.ErrNoSuchObject)
	}
	if err := t.unlinkChild(from, id); err != nil {
		return err
	}
	return t.linkChild(to, id)
}

// linkChild records id under dn's parent folded key. Entries are only
// added with an existing parent (dispatch checks), but the index is keyed
// by folded DN so the link is well-defined even without the parent entry.
func (t updateTx) linkChild(dn config.DN, id []byte) error {
	parent, ok := parentFoldedKey(dn)
	if !ok {
		return nil
	}
	kids, err := t.tx.Bucket(bucketChildren).CreateBucketIfNotExists([]byte(parent))
	if err != nil {
		return fmt.Errorf("store: index child link: %w", err)
	}
	if err := kids.Put(id, nil); err != nil {
		return fmt.Errorf("store: index child link: %w", err)
	}
	return nil
}

func (t updateTx) unlinkChild(dn config.DN, id []byte) error {
	parent, ok := parentFoldedKey(dn)
	if !ok {
		return nil
	}
	kids := t.tx.Bucket(bucketChildren).Bucket([]byte(parent))
	if kids == nil {
		return nil
	}
	if err := kids.Delete(id); err != nil {
		return fmt.Errorf("store: index child unlink: %w", err)
	}
	return nil
}

// parentFoldedKey returns the folded key of dn's parent. The canonical
// String form is split at the first unescaped comma so escaped separators
// inside an RDN value cannot split it (same approach as the server's
// parentDN helper).
func parentFoldedKey(dn config.DN) (string, bool) {
	s := dn.String()
	esc := false
	for i, r := range s {
		if esc {
			esc = false
			continue
		}
		if r == '\\' {
			esc = true
			continue
		}
		if r == ',' {
			parent, err := config.ParseDN(s[i+1:])
			if err != nil {
				return "", false
			}
			return parent.FoldedKey(), true
		}
	}
	return "", false
}

func uint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func idUint64(id []byte) uint64 {
	if len(id) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(id)
}
