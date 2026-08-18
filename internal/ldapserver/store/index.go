package store

// Equality indices for the bbolt entry store (T-130, ADR-0009 decisions 7-8).
//
// This file owns the posting layout and maintenance rules; store.go owns
// dn2id / id2entry and calls into these helpers from its write paths.
//
// # Posting layout
//
// One top-level bucket per indexed attribute, created by EnsureIndexBuckets:
//
//	eq_uid, eq_cn, eq_member, eq_uniquemember, eq_objectclass
//
// Each key is normalizeIndexKey(attr, value) || 0x00 || id (8-byte big
// endian) with an empty value, so a prefix seek on normalizedValue || 0x00
// yields the entry ids holding that value in ascending id order. A meta
// bucket "idxmeta" records the index format version so a future matching-rule
// change (T-131) can bump indexVersion and force a RebuildIndexes; Open
// rebuilds postings from id2entry whenever the stamped version differs.
//
// # Integration contract (landed in store.go)
//
// The bbolt store maintains postings inside the SAME bolt read-write
// transaction as the entry write, so one Store.Update is one MVCC commit
// covering entry and index (single-commit mutate):
//
//   - Add:     after the id2entry write, AddPostings(tx, id, entry).
//   - Replace: decodes the prior entry, then ReindexEntry(tx, id, old, new)
//     beside the id2entry rewrite.
//   - Delete:  decodes the entry, RemovePostings(tx, id, entry), then
//     removes dn2id / id2entry.
//   - Rename:  entry ids and attribute values stay stable, so value -> id
//     postings remain valid with no reindex; the RDN attribute maintenance
//     that handleModifyDN applies lands through its follow-up Replace.
//
// A failed fn rolls the whole bolt transaction back, so a partial
// entry/index state can never commit; VerifyIndexes confirms entry/index
// agreement after a reopen (crash recovery check), and Store.VerifyIndexes
// / Store.RebuildIndexes expose that to the daemon.
//
// # Search wiring merge point (op_search.go, not touched by T-130)
//
// The bbolt readTx implements EqualCandidateResolver (index_store.go).
// Search dispatch may type-assert the ReadTx to that interface and, when
// the filter tree contains an indexed equality predicate, resolve the
// candidate set through EqualCandidates instead of a full Subtree/Children
// scan, still running the normal filter evaluation on each fetched entry so
// the index only ever narrows candidates, never decides the match.
// Base/scope restriction stays a DN-descendant check on the fetched
// entries.
//
// # Normalization rule
//
// Index keys fold case and insignificant whitespace for caseIgnoreMatch
// attributes and fold DN-valued attributes structurally through
// internal/config. The folded key must stay at least as coarse as the
// filter evaluator's equality rule: the index may return candidates the
// evaluator later rejects, but must never drop a true match. The T-131
// RuleMatcher equality for these attributes (Unicode-lower + U+0020
// collapse for strings, EqualFold for DNs) satisfies that over the FoldedKey
// and Fields-based folds used here; exotic Unicode simple-fold pairs (for
// example U+017F versus "s" inside a DN) are a documented approximation on
// par with T-131's deferred-NFKC stance. If a future matching-rule change
// alters normalization, bump indexVersion and Open rebuilds.

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	bolt "go.etcd.io/bbolt"
)

// indexVersion is the posting format version stored in idxmeta. Bump it when
// normalizeIndexKey changes so open/migration can force RebuildIndexes.
const indexVersion uint64 = 1

// idxMetaBucket holds index bookkeeping; key "version" is an 8-byte
// big-endian indexVersion.
const idxMetaBucket = "idxmeta"

// idxVersionKey is the idxmeta key carrying the posting format version.
var idxVersionKey = []byte("version")

// indexBucketPrefix prefixes every equality posting bucket.
const indexBucketPrefix = "eq_"

// indexedAttribute maps a lowercased attribute name to its posting bucket
// and value kind. ADR-0009 decision 8 fixes the Contract-tier equality set.
type indexedAttribute struct {
	bucket       string
	dn           bool // value is a DN; fold structurally, not as text
	uniqueMember bool // strip RFC 4519 '#' bit-string before DN parse
}

// indexedAttributes is the equality index registry. Attribute names are
// compared case-insensitively and without attribute options; an attribute
// with options (e.g. "cn;lang-en") is not indexed and search falls back to
// a scan.
var indexedAttributes = map[string]indexedAttribute{
	"uid":          {bucket: "eq_uid"},
	"cn":           {bucket: "eq_cn"},
	"member":       {bucket: "eq_member", dn: true},
	"uniquemember": {bucket: "eq_uniquemember", dn: true, uniqueMember: true},
	"objectclass":  {bucket: "eq_objectclass"},
}

// IndexedAttributes lists the lowercased attribute names with equality
// indices, in deterministic order. It is exported for diagnostics and tests.
func IndexedAttributes() []string {
	out := make([]string, 0, len(indexedAttributes))
	for _, name := range []string{"cn", "member", "objectclass", "uid", "uniquemember"} {
		if _, ok := indexedAttributes[name]; ok {
			out = append(out, name)
		}
	}
	return out
}

// ReadCounter instruments store reads so tests can prove an indexed
// equality search does not scan every entry (T-130 acceptance). Attach one
// to the context with WithReadCounter; the bbolt readTx EqualCandidates
// path increments EntryFetches per id2entry fetch and LookupIDs increments
// IndexReads for each posting key it examines.
type ReadCounter struct {
	entryFetches atomic.Int64
	indexReads   atomic.Int64
}

// EntryFetches reports how many entries were fetched by id or DN.
func (c *ReadCounter) EntryFetches() int64 { return c.entryFetches.Load() }

// IndexReads reports how many posting keys index lookups examined.
func (c *ReadCounter) IndexReads() int64 { return c.indexReads.Load() }

// AddEntryFetch records one entry fetch by id or DN.
func (c *ReadCounter) AddEntryFetch() { c.entryFetches.Add(1) }

func (c *ReadCounter) addIndexRead() { c.indexReads.Add(1) }

type readCounterKey struct{}

// WithReadCounter returns a context carrying c for store instrumentation.
func WithReadCounter(ctx context.Context, c *ReadCounter) context.Context {
	return context.WithValue(ctx, readCounterKey{}, c)
}

// ReadCounterFrom returns the counter attached with WithReadCounter, or nil.
func ReadCounterFrom(ctx context.Context) *ReadCounter {
	c, _ := ctx.Value(readCounterKey{}).(*ReadCounter)
	return c
}

// normalizeIndexKey folds an attribute value into its posting-key form.
// Errors are secret-free: values never appear in them.
func normalizeIndexKey(spec indexedAttribute, value []byte) []byte {
	if spec.dn {
		// distinguishedNameMatch: fold through the structural DN parser so
		// "CN=Bob, OU=People" and "cn=bob,ou=people" share a key. Values
		// that fail DN parse (schema enforcement may still be stubbed)
		// fall back to the text fold so they remain searchable.
		raw := value
		if spec.uniqueMember {
			raw = stripUniqueMemberSuffix(value)
		}
		if d, err := config.ParseDN(string(raw)); err == nil {
			return []byte(d.FoldedKey())
		}
	}
	// caseIgnoreMatch approximation: fold case and insignificant
	// whitespace. T-131 owns the final rule; keep this no finer-grained
	// than the evaluator.
	return []byte(strings.ToLower(strings.Join(strings.Fields(string(value)), " ")))
}

// stripUniqueMemberSuffix drops the optional RFC 4519 '#' bit-string from a
// uniqueMember value. An escaped "\#" is DN data, not the separator.
func stripUniqueMemberSuffix(v []byte) []byte {
	s := string(v)
	esc := false
	for i := 0; i < len(s); i++ {
		if esc {
			esc = false
			continue
		}
		if s[i] == '\\' {
			esc = true
			continue
		}
		if s[i] == '#' {
			return []byte(s[:i])
		}
	}
	return v
}

// postingKey builds the bucket key normalizedValue || 0x00 || id.
func postingKey(norm []byte, id uint64) []byte {
	key := make([]byte, 0, len(norm)+9)
	key = append(key, norm...)
	key = append(key, 0x00)
	return binary.BigEndian.AppendUint64(key, id)
}

// parsePostingKey splits a posting key into value key and id, rejecting
// malformed keys.
func parsePostingKey(key []byte) (norm []byte, id uint64, ok bool) {
	if len(key) < 9 || key[len(key)-9] != 0x00 {
		return nil, 0, false
	}
	return key[:len(key)-9], binary.BigEndian.Uint64(key[len(key)-8:]), true
}

// EnsureIndexBuckets creates the posting and meta buckets when absent and
// stamps the format version on a fresh database. It is idempotent and must
// run inside a writable transaction during store open/migration.
func EnsureIndexBuckets(tx *bolt.Tx) error {
	if tx == nil {
		return errors.New("store: ensure index buckets: nil transaction")
	}
	for _, spec := range indexedAttributes {
		if _, err := tx.CreateBucketIfNotExists([]byte(spec.bucket)); err != nil {
			return fmt.Errorf("store: create index bucket %s: %w", spec.bucket, err)
		}
	}
	meta, err := tx.CreateBucketIfNotExists([]byte(idxMetaBucket))
	if err != nil {
		return fmt.Errorf("store: create index meta bucket: %w", err)
	}
	if meta.Get(idxVersionKey) == nil {
		if err := meta.Put(idxVersionKey, binary.BigEndian.AppendUint64(nil, indexVersion)); err != nil {
			return fmt.Errorf("store: stamp index version: %w", err)
		}
	}
	return nil
}

// IndexVersion reports the stamped posting format version, or 0 when the
// meta bucket or key is absent (pre-T-130 database: caller should rebuild).
func IndexVersion(tx *bolt.Tx) (uint64, error) {
	if tx == nil {
		return 0, errors.New("store: index version: nil transaction")
	}
	meta := tx.Bucket([]byte(idxMetaBucket))
	if meta == nil {
		return 0, nil
	}
	raw := meta.Get(idxVersionKey)
	if len(raw) != 8 {
		return 0, nil
	}
	return binary.BigEndian.Uint64(raw), nil
}

// AddPostings indexes every indexed attribute value of e under id. It runs
// inside the same writable transaction as the entry write.
func AddPostings(tx *bolt.Tx, id uint64, e *ldapserver.Entry) error {
	return reindex(tx, id, e, func(b *bolt.Bucket, key []byte) error {
		return b.Put(key, []byte{})
	})
}

// RemovePostings deletes the postings written for e under id. The caller
// must pass the entry as stored before the delete or replace.
func RemovePostings(tx *bolt.Tx, id uint64, e *ldapserver.Entry) error {
	return reindex(tx, id, e, func(b *bolt.Bucket, key []byte) error {
		return b.Delete(key)
	})
}

// ReindexEntry swaps postings from old to new under a stable id. It is the
// Replace and Rename(deleteoldrdn) integration path; a nil old or new entry
// is treated as attribute-less.
func ReindexEntry(tx *bolt.Tx, id uint64, old, cur *ldapserver.Entry) error {
	if err := RemovePostings(tx, id, old); err != nil {
		return err
	}
	return AddPostings(tx, id, cur)
}

func reindex(tx *bolt.Tx, id uint64, e *ldapserver.Entry, apply func(b *bolt.Bucket, key []byte) error) error {
	if tx == nil {
		return errors.New("store: reindex: nil transaction")
	}
	if e == nil {
		return nil
	}
	for _, a := range e.Attributes {
		spec, ok := indexedAttributes[strings.ToLower(a.Name)]
		if !ok {
			continue
		}
		b := tx.Bucket([]byte(spec.bucket))
		if b == nil {
			return fmt.Errorf("store: reindex: index bucket %s missing (EnsureIndexBuckets not run)", spec.bucket)
		}
		for _, v := range a.Values {
			if err := apply(b, postingKey(normalizeIndexKey(spec, v), id)); err != nil {
				return fmt.Errorf("store: reindex bucket %s entry id %d: %w", spec.bucket, id, err)
			}
		}
	}
	return nil
}

// LookupIDs returns the entry ids holding an equality posting for
// attr=value, in ascending id order. indexed is false when attr has no
// equality index, in which case the caller must fall back to a scan. A
// missing posting bucket is an integrity error, not an empty result.
//
// Errors never contain attribute values (secret-free).
func LookupIDs(ctx context.Context, tx *bolt.Tx, attr string, value []byte) (ids []uint64, indexed bool, err error) {
	if tx == nil {
		return nil, false, errors.New("store: index lookup: nil transaction")
	}
	spec, ok := indexedAttributes[strings.ToLower(attr)]
	if !ok {
		return nil, false, nil
	}
	b := tx.Bucket([]byte(spec.bucket))
	if b == nil {
		return nil, true, fmt.Errorf("store: index lookup: bucket %s missing (EnsureIndexBuckets not run)", spec.bucket)
	}
	norm := normalizeIndexKey(spec, value)
	prefix := make([]byte, 0, len(norm)+1)
	prefix = append(append(prefix, norm...), 0x00)
	counter := ReadCounterFrom(ctx)
	c := b.Cursor()
	for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
		if counter != nil {
			counter.addIndexRead()
		}
		// Exact-value guard: a normalized value containing 0x00 must not
		// widen the prefix match into a sibling value's postings.
		v, id, ok := parsePostingKey(k)
		if !ok || !bytes.Equal(v, norm) {
			continue
		}
		ids = append(ids, id)
	}
	return ids, true, nil
}

// EntryIter feeds VerifyIndexes and RebuildIndexes with every id2entry
// record. The T-129 entry store implements it as a cursor walk over its
// id2entry bucket; iteration stops when yield returns false.
type EntryIter func(yield func(id uint64, e *ldapserver.Entry) bool)

// VerifyIndexes compares every posting bucket against the live entry
// contents and returns the first disagreement. The error names only the
// bucket and entry id — never a value — so it is safe to log. A nil return
// means entry and index agree exactly; run it after a reopen to confirm
// crash consistency.
func VerifyIndexes(tx *bolt.Tx, entries EntryIter) error {
	if tx == nil {
		return errors.New("store: verify indexes: nil transaction")
	}
	if entries == nil {
		return errors.New("store: verify indexes: nil entry iterator")
	}
	expected := map[string]map[string]struct{}{}
	entries(func(id uint64, e *ldapserver.Entry) bool {
		if e == nil {
			return true
		}
		for _, a := range e.Attributes {
			spec, ok := indexedAttributes[strings.ToLower(a.Name)]
			if !ok {
				continue
			}
			set := expected[spec.bucket]
			if set == nil {
				set = map[string]struct{}{}
				expected[spec.bucket] = set
			}
			for _, v := range a.Values {
				set[string(postingKey(normalizeIndexKey(spec, v), id))] = struct{}{}
			}
		}
		return true
	})
	for _, spec := range indexedAttributes {
		b := tx.Bucket([]byte(spec.bucket))
		if b == nil {
			return fmt.Errorf("store: verify indexes: bucket %s missing", spec.bucket)
		}
		set := expected[spec.bucket]
		var stale string
		var staleOK bool
		if err := b.ForEach(func(k, _ []byte) error {
			ks := string(k)
			if _, ok := set[ks]; !ok {
				stale, staleOK = ks, true
				return errVerifyStop
			}
			delete(set, ks)
			return nil
		}); err != nil && !errors.Is(err, errVerifyStop) {
			return fmt.Errorf("store: verify indexes: scan bucket %s: %w", spec.bucket, err)
		}
		if staleOK {
			_, id, ok := parsePostingKey([]byte(stale))
			if ok {
				return fmt.Errorf("store: verify indexes: bucket %s has stale posting for entry id %d", spec.bucket, id)
			}
			return fmt.Errorf("store: verify indexes: bucket %s has malformed posting key", spec.bucket)
		}
		for missing := range set {
			_, id, ok := parsePostingKey([]byte(missing))
			if ok {
				return fmt.Errorf("store: verify indexes: bucket %s is missing posting for entry id %d", spec.bucket, id)
			}
			return fmt.Errorf("store: verify indexes: internal key rebuild failed")
		}
	}
	return nil
}

// errVerifyStop aborts a ForEach once a mismatch is found.
var errVerifyStop = errors.New("store: verify indexes: mismatch found")

// RebuildIndexes clears every posting bucket and rewrites it from the live
// entries. It must run inside a writable transaction; combined with the
// entry reads in the same MVCC snapshot the rebuild is atomic. Use it for
// crash recovery when VerifyIndexes fails and for format-version upgrades.
func RebuildIndexes(tx *bolt.Tx, entries EntryIter) error {
	if tx == nil {
		return errors.New("store: rebuild indexes: nil transaction")
	}
	if entries == nil {
		return errors.New("store: rebuild indexes: nil entry iterator")
	}
	for _, spec := range indexedAttributes {
		if err := tx.DeleteBucket([]byte(spec.bucket)); err != nil && !errors.Is(err, bolt.ErrBucketNotFound) {
			return fmt.Errorf("store: rebuild indexes: clear bucket %s: %w", spec.bucket, err)
		}
		if _, err := tx.CreateBucket([]byte(spec.bucket)); err != nil {
			return fmt.Errorf("store: rebuild indexes: create bucket %s: %w", spec.bucket, err)
		}
	}
	var reindexErr error
	entries(func(id uint64, e *ldapserver.Entry) bool {
		if err := AddPostings(tx, id, e); err != nil {
			reindexErr = err
			return false
		}
		return true
	})
	if reindexErr != nil {
		return fmt.Errorf("store: rebuild indexes: %w", reindexErr)
	}
	return nil
}

// EqualCandidateResolver is the optional ReadTx extension that lets Search
// resolve an indexed equality predicate without a full Subtree/Children
// scan. The bbolt readTx implements it (index_store.go) by calling
// LookupIDs and fetching each id2entry record inside the same read
// snapshot; op_search type-asserts the ReadTx to this interface (merge
// point documented above).
//
// ok is false when attr is not indexed, telling dispatch to keep the
// scan path. Returned entries still go through the normal filter
// evaluation, so resolver false negatives are impossible as long as
// normalizeIndexKey is no finer-grained than the evaluator's equality rule.
type EqualCandidateResolver interface {
	EqualCandidates(ctx context.Context, attr string, value []byte) (entries []*ldapserver.Entry, ok bool, err error)
}
