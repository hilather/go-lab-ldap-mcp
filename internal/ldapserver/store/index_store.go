package store

// Glue between the T-129 entry store (store.go) and the T-130 equality
// indices (index.go): the EntryIter over id2entry, the readTx
// EqualCandidateResolver that lets Search resolve an indexed equality
// predicate without a full scan, and the Store-level verify/rebuild helpers
// a daemon can run at startup or after a crash.

import (
	"context"
	"fmt"

	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	bolt "go.etcd.io/bbolt"
)

// storeEntryIter adapts the id2entry bucket to EntryIter inside an open
// transaction.
func storeEntryIter(tx *bolt.Tx) EntryIter {
	return func(yield func(id uint64, e *ldapserver.Entry) bool) {
		c := tx.Bucket(bucketID2Entry).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			e, err := decodeEntry(v)
			if err != nil || !yield(idUint64(k), e) {
				return
			}
		}
	}
}

// EqualCandidates implements EqualCandidateResolver on the bbolt readTx:
// the indexed equality predicate resolves to entry ids through LookupIDs
// and each id fetches its entry inside the same MVCC read snapshot. ok is
// false when the attribute has no equality index, telling the caller to
// keep the Subtree/Children scan path. Returned entries are candidates:
// the caller still evaluates the full filter against each.
func (t readTx) EqualCandidates(ctx context.Context, attr string, value []byte) ([]*ldapserver.Entry, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	ids, indexed, err := LookupIDs(ctx, t.tx, attr, value)
	if err != nil || !indexed {
		return nil, indexed, err
	}
	counter := ReadCounterFrom(ctx)
	out := make([]*ldapserver.Entry, 0, len(ids))
	for _, id := range ids {
		if counter != nil {
			counter.AddEntryFetch()
		}
		e, err := t.entryByID(uint64Bytes(id))
		if err != nil {
			return nil, true, fmt.Errorf("store: equal candidates: %w", err)
		}
		out = append(out, e)
	}
	return out, true, nil
}

// VerifyIndexes checks that every equality posting agrees with the live
// id2entry contents. Run it after a reopen to confirm crash consistency;
// the error names only the bucket and entry id, never a value.
func (s *Store) VerifyIndexes(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return fmt.Errorf("store: verify indexes: %w", ldapserver.ErrStoreClosed)
	}
	return s.db.View(func(tx *bolt.Tx) error {
		return VerifyIndexes(tx, storeEntryIter(tx))
	})
}

// RebuildIndexes rewrites every posting bucket from the live entries in a
// single read-write transaction. Open already rebuilds when the stamped
// index version differs; this method exists for operator-driven recovery.
func (s *Store) RebuildIndexes(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return fmt.Errorf("store: rebuild indexes: %w", ldapserver.ErrStoreClosed)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return RebuildIndexes(tx, storeEntryIter(tx))
	})
}
