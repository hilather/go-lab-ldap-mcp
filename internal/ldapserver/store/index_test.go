package store

// Tests for the T-130 equality indices. They run against a minimal
// test-local dn2id/id2entry harness (prefix ix) standing in for the T-129
// entry store; the harness implements the integration contract documented
// in index.go (postings in the same bolt transaction as the entry write),
// so these tests keep passing unchanged once T-129 wires the same calls
// into its real ReadTx/UpdateTx.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	bolt "go.etcd.io/bbolt"
)

var (
	ixBucketDN2ID    = []byte("dn2id")
	ixBucketID2Entry = []byte("id2entry")
)

func ixOpen(t *testing.T, path string) *bolt.DB {
	t.Helper()
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("open bolt: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{ixBucketDN2ID, ixBucketID2Entry} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return EnsureIndexBuckets(tx)
	})
	if err != nil {
		t.Fatalf("init buckets: %v", err)
	}
	return db
}

func ixEncode(e *ldapserver.Entry) ([]byte, error) {
	return json.Marshal(e)
}

func ixDecode(raw []byte) (*ldapserver.Entry, error) {
	var e ldapserver.Entry
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// ixAdd is the harness Add: dn2id/id2entry write plus postings in one tx.
func ixAdd(db *bolt.DB, e *ldapserver.Entry) error {
	return db.Update(func(tx *bolt.Tx) error {
		d, err := config.ParseDN(e.DN)
		if err != nil {
			return err
		}
		dn2id := tx.Bucket(ixBucketDN2ID)
		if dn2id.Get([]byte(d.FoldedKey())) != nil {
			return ldapserver.ErrEntryExists
		}
		id, err := dn2id.NextSequence()
		if err != nil {
			return err
		}
		raw, err := ixEncode(e)
		if err != nil {
			return err
		}
		idb := binary.BigEndian.AppendUint64(nil, id)
		if err := dn2id.Put([]byte(d.FoldedKey()), idb); err != nil {
			return err
		}
		if err := tx.Bucket(ixBucketID2Entry).Put(idb, raw); err != nil {
			return err
		}
		return AddPostings(tx, id, e)
	})
}

// ixReplace is the harness Replace: read old, swap entry and postings.
func ixReplace(db *bolt.DB, e *ldapserver.Entry) error {
	return db.Update(func(tx *bolt.Tx) error {
		d, err := config.ParseDN(e.DN)
		if err != nil {
			return err
		}
		idb := tx.Bucket(ixBucketDN2ID).Get([]byte(d.FoldedKey()))
		if idb == nil {
			return ldapserver.ErrNoSuchObject
		}
		oldRaw := tx.Bucket(ixBucketID2Entry).Get(idb)
		old, err := ixDecode(oldRaw)
		if err != nil {
			return err
		}
		raw, err := ixEncode(e)
		if err != nil {
			return err
		}
		if err := tx.Bucket(ixBucketID2Entry).Put(idb, raw); err != nil {
			return err
		}
		return ReindexEntry(tx, binary.BigEndian.Uint64(idb), old, e)
	})
}

// ixDelete is the harness Delete: read, remove postings, remove records.
func ixDelete(db *bolt.DB, dn string) error {
	return db.Update(func(tx *bolt.Tx) error {
		d, err := config.ParseDN(dn)
		if err != nil {
			return err
		}
		idb := tx.Bucket(ixBucketDN2ID).Get([]byte(d.FoldedKey()))
		if idb == nil {
			return ldapserver.ErrNoSuchObject
		}
		old, err := ixDecode(tx.Bucket(ixBucketID2Entry).Get(idb))
		if err != nil {
			return err
		}
		if err := RemovePostings(tx, binary.BigEndian.Uint64(idb), old); err != nil {
			return err
		}
		if err := tx.Bucket(ixBucketDN2ID).Delete([]byte(d.FoldedKey())); err != nil {
			return err
		}
		return tx.Bucket(ixBucketID2Entry).Delete(idb)
	})
}

// ixRename moves a DN keeping the entry id stable, per the Rename
// integration contract; attribute values are unchanged, so postings stay
// valid without a reindex.
func ixRename(db *bolt.DB, from, to string) error {
	return db.Update(func(tx *bolt.Tx) error {
		fd, err := config.ParseDN(from)
		if err != nil {
			return err
		}
		td, err := config.ParseDN(to)
		if err != nil {
			return err
		}
		dn2id := tx.Bucket(ixBucketDN2ID)
		idb := dn2id.Get([]byte(fd.FoldedKey()))
		if idb == nil {
			return ldapserver.ErrNoSuchObject
		}
		if dn2id.Get([]byte(td.FoldedKey())) != nil {
			return ldapserver.ErrEntryExists
		}
		e, err := ixDecode(tx.Bucket(ixBucketID2Entry).Get(idb))
		if err != nil {
			return err
		}
		e.DN = td.String()
		raw, err := ixEncode(e)
		if err != nil {
			return err
		}
		if err := tx.Bucket(ixBucketID2Entry).Put(idb, raw); err != nil {
			return err
		}
		if err := dn2id.Delete([]byte(fd.FoldedKey())); err != nil {
			return err
		}
		return dn2id.Put([]byte(td.FoldedKey()), idb)
	})
}

// ixIter adapts the id2entry bucket to EntryIter inside an open tx.
func ixIter(tx *bolt.Tx) EntryIter {
	return func(yield func(id uint64, e *ldapserver.Entry) bool) {
		c := tx.Bucket(ixBucketID2Entry).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			e, err := ixDecode(v)
			if err != nil || !yield(binary.BigEndian.Uint64(k), e) {
				return
			}
		}
	}
}

// ixFetch reads one entry by id, counting the read on the context counter.
func ixFetch(ctx context.Context, tx *bolt.Tx, id uint64) (*ldapserver.Entry, error) {
	if c := ReadCounterFrom(ctx); c != nil {
		c.AddEntryFetch()
	}
	raw := tx.Bucket(ixBucketID2Entry).Get(binary.BigEndian.AppendUint64(nil, id))
	if raw == nil {
		return nil, ldapserver.ErrNoSuchObject
	}
	return ixDecode(raw)
}

func ixVerify(t *testing.T, db *bolt.DB) {
	t.Helper()
	err := db.View(func(tx *bolt.Tx) error { return VerifyIndexes(tx, ixIter(tx)) })
	if err != nil {
		t.Fatalf("VerifyIndexes: %v", err)
	}
}

func ixLookup(t *testing.T, ctx context.Context, db *bolt.DB, attr, value string) []uint64 {
	t.Helper()
	var ids []uint64
	var indexed bool
	err := db.View(func(tx *bolt.Tx) error {
		var err error
		ids, indexed, err = LookupIDs(ctx, tx, attr, []byte(value))
		return err
	})
	if err != nil {
		t.Fatalf("LookupIDs(%s): %v", attr, err)
	}
	if !indexed {
		t.Fatalf("LookupIDs(%s): attribute should be indexed", attr)
	}
	return ids
}

func ixEntry(dn string, attrs ...ldapserver.Attribute) *ldapserver.Entry {
	return &ldapserver.Entry{DN: dn, Attributes: attrs}
}

func ixStrAttr(name string, values ...string) ldapserver.Attribute {
	a := ldapserver.Attribute{Name: name}
	for _, v := range values {
		a.Values = append(a.Values, []byte(v))
	}
	return a
}

func TestEnsureIndexBucketsIdempotent(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	err := db.Update(func(tx *bolt.Tx) error {
		if err := EnsureIndexBuckets(tx); err != nil {
			return err
		}
		v, err := IndexVersion(tx)
		if err != nil {
			return err
		}
		if v != indexVersion {
			return fmt.Errorf("version %d, want %d", v, indexVersion)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLookupUnindexedAttributeFallsBack(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	err := db.View(func(tx *bolt.Tx) error {
		ids, indexed, err := LookupIDs(context.Background(), tx, "mail", []byte("a@b.c"))
		if err != nil {
			return err
		}
		if indexed || ids != nil {
			return errors.New("mail must not be indexed; caller falls back to scan")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestEqualityLookupCaseAndDNFolding(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	ctx := context.Background()
	if err := ixAdd(db, ixEntry("uid=Alice,ou=people,dc=example,dc=test",
		ixStrAttr("uid", "Alice"),
		ixStrAttr("cn", "Alice   Adams"),
		ixStrAttr("objectClass", "inetOrgPerson", "top"),
	)); err != nil {
		t.Fatal(err)
	}
	if err := ixAdd(db, ixEntry("cn=devs,ou=groups,dc=example,dc=test",
		ixStrAttr("cn", "devs"),
		ixStrAttr("objectClass", "groupOfNames"),
		ixStrAttr("member", "CN=Alice, OU=People, DC=Example, DC=Test"),
	)); err != nil {
		t.Fatal(err)
	}
	ixVerify(t, db)

	// Case fold: uid stored "Alice" resolves for "alice" and "ALICE".
	for _, v := range []string{"alice", "ALICE", "Alice"} {
		if ids := ixLookup(t, ctx, db, "uid", v); len(ids) != 1 {
			t.Fatalf("uid=%s: got %d ids, want 1", v, len(ids))
		}
	}
	// Whitespace-insensitive cn fold.
	if ids := ixLookup(t, ctx, db, "cn", "alice adams"); len(ids) != 1 {
		t.Fatalf("cn fold: got %d ids, want 1", len(ids))
	}
	// Structural DN fold on member regardless of case and spacing.
	ids := ixLookup(t, ctx, db, "member", "cn=alice,ou=people,dc=example,dc=test")
	if len(ids) != 1 {
		t.Fatalf("member DN fold: got %d ids, want 1", len(ids))
	}
	// Multi-valued objectClass resolves per value.
	if ids := ixLookup(t, ctx, db, "objectClass", "inetorgperson"); len(ids) != 1 {
		t.Fatalf("objectClass fold: got %d ids, want 1", len(ids))
	}
	// Absent value resolves to no ids, not an error.
	if ids := ixLookup(t, ctx, db, "uid", "nobody"); len(ids) != 0 {
		t.Fatalf("absent uid: got %d ids, want 0", len(ids))
	}
}

// TestIndexedEqualityDoesNotScanAllEntries is the 1k-entry acceptance case:
// an indexed equality lookup must touch only the posting and the matching
// entry, never the whole id2entry space.
func TestIndexedEqualityDoesNotScanAllEntries(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	const n = 1000
	for i := 0; i < n; i++ {
		e := ixEntry(fmt.Sprintf("uid=user%04d,ou=people,dc=example,dc=test", i),
			ixStrAttr("uid", fmt.Sprintf("user%04d", i)),
			ixStrAttr("cn", fmt.Sprintf("User Number %04d", i)),
			ixStrAttr("objectClass", "inetOrgPerson"),
		)
		if err := ixAdd(db, e); err != nil {
			t.Fatal(err)
		}
	}
	ixVerify(t, db)

	counter := &ReadCounter{}
	ctx := WithReadCounter(context.Background(), counter)
	ids := ixLookup(t, ctx, db, "uid", "user0423")
	if len(ids) != 1 {
		t.Fatalf("indexed lookup: got %d ids, want 1", len(ids))
	}
	var hit *ldapserver.Entry
	err := db.View(func(tx *bolt.Tx) error {
		var err error
		hit, err = ixFetch(ctx, tx, ids[0])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(hit.Values("cn")[0]); got != "User Number 0423" {
		t.Fatalf("fetched wrong entry: cn=%q", got)
	}
	if got := counter.EntryFetches(); got != 1 {
		t.Fatalf("indexed search fetched %d entries out of %d, want 1", got, n)
	}
	if got := counter.IndexReads(); got > 4 {
		t.Fatalf("indexed search examined %d posting keys, want a tiny bound", got)
	}

	// Case-folded lookup hits the same single entry without a scan.
	counter2 := &ReadCounter{}
	ids = ixLookup(t, WithReadCounter(context.Background(), counter2), db, "uid", "USER0423")
	if len(ids) != 1 {
		t.Fatalf("folded indexed lookup: got %d ids, want 1", len(ids))
	}
}

// TestReadThenWriteSingleCommit proves the RFC 4528-ready shape: inside one
// bolt read-write transaction (what Store.Update exposes) a handler reads,
// asserts, and writes, and the whole unit commits or rolls back together.
func TestReadThenWriteSingleCommit(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	dn := "cn=counter,dc=example,dc=test"
	if err := ixAdd(db, ixEntry(dn, ixStrAttr("cn", "counter"), ixStrAttr("description", "0"))); err != nil {
		t.Fatal(err)
	}

	bump := func(expect int) error {
		return db.Update(func(tx *bolt.Tx) error {
			idb := tx.Bucket(ixBucketDN2ID).Get([]byte("cn=counter,dc=example,dc=test"))
			if idb == nil {
				return ldapserver.ErrNoSuchObject
			}
			e, err := ixDecode(tx.Bucket(ixBucketID2Entry).Get(idb))
			if err != nil {
				return err
			}
			cur, err := strconv.Atoi(string(e.Values("description")[0]))
			if err != nil {
				return err
			}
			if cur != expect {
				return fmt.Errorf("assertion failed: counter is %d", cur)
			}
			e.Attributes[1].Values[0] = []byte(strconv.Itoa(cur + 1))
			raw, err := ixEncode(e)
			if err != nil {
				return err
			}
			return tx.Bucket(ixBucketID2Entry).Put(idb, raw)
		})
	}

	// Sequential read-modify-write commits chain consistently.
	const seq = 32
	for i := 0; i < seq; i++ {
		if err := bump(i); err != nil {
			t.Fatalf("bump %d: %v", i, err)
		}
	}

	// Concurrent writers all asserting the same value: bolt serializes the
	// read-write transactions, so exactly one commits; the rest re-read the
	// new value inside their own transaction and fail the assertion.
	var wg sync.WaitGroup
	var committed atomic.Int64
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := bump(seq); err == nil {
				committed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := committed.Load(); got != 1 {
		t.Fatalf("%d conflicting assertion updates committed, want exactly 1", got)
	}

	var final string
	if err := db.View(func(tx *bolt.Tx) error {
		e, err := ixDecode(tx.Bucket(ixBucketID2Entry).Get(tx.Bucket(ixBucketDN2ID).Get([]byte("cn=counter,dc=example,dc=test"))))
		if err != nil {
			return err
		}
		final = string(e.Values("description")[0])
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if final != strconv.Itoa(seq+1) {
		t.Fatalf("counter = %s, want %d", final, seq+1)
	}
	ixVerify(t, db)
}

// TestRollbackLeavesNoPartialIndex: a failing Update must roll back the
// entry write and its postings together.
func TestRollbackLeavesNoPartialIndex(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	ctx := context.Background()
	injected := errors.New("injected failure")
	err := db.Update(func(tx *bolt.Tx) error {
		e := ixEntry("uid=ghost,dc=example,dc=test", ixStrAttr("uid", "ghost"), ixStrAttr("objectClass", "inetOrgPerson"))
		d, err := config.ParseDN(e.DN)
		if err != nil {
			return err
		}
		dn2id := tx.Bucket(ixBucketDN2ID)
		id, err := dn2id.NextSequence()
		if err != nil {
			return err
		}
		raw, err := ixEncode(e)
		if err != nil {
			return err
		}
		idb := binary.BigEndian.AppendUint64(nil, id)
		if err := dn2id.Put([]byte(d.FoldedKey()), idb); err != nil {
			return err
		}
		if err := tx.Bucket(ixBucketID2Entry).Put(idb, raw); err != nil {
			return err
		}
		if err := AddPostings(tx, id, e); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) {
		t.Fatalf("got %v, want injected error", err)
	}
	if ids := ixLookup(t, ctx, db, "uid", "ghost"); len(ids) != 0 {
		t.Fatalf("rolled-back posting leaked: %d ids", len(ids))
	}
	ixVerify(t, db)
}

// TestIndexConsistencyAfterReopen simulates crash points by closing and
// reopening the file between commits; the index must always agree with
// id2entry. bbolt recovers to the last committed transaction on open.
func TestIndexConsistencyAfterReopen(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/ix.bolt"
	ctx := context.Background()

	db := ixOpen(t, path)
	for i := 0; i < 20; i++ {
		if err := ixAdd(db, ixEntry(fmt.Sprintf("uid=u%02d,dc=example,dc=test", i),
			ixStrAttr("uid", fmt.Sprintf("u%02d", i)),
			ixStrAttr("objectClass", "inetOrgPerson"),
		)); err != nil {
			t.Fatal(err)
		}
	}
	// "Crash" between commit points: close without any extra writes.
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = ixOpen(t, path)
	ixVerify(t, db)
	if ids := ixLookup(t, ctx, db, "uid", "u07"); len(ids) != 1 {
		t.Fatalf("after reopen: uid=u07 gave %d ids, want 1", len(ids))
	}

	// Mutate every write path, then reopen and re-verify.
	if err := ixAdd(db, ixEntry("uid=u99,dc=example,dc=test", ixStrAttr("uid", "u99"), ixStrAttr("objectClass", "inetOrgPerson"))); err != nil {
		t.Fatal(err)
	}
	if err := ixReplace(db, ixEntry("uid=u01,dc=example,dc=test", ixStrAttr("uid", "u01"), ixStrAttr("cn", "Renamed One"), ixStrAttr("objectClass", "inetOrgPerson"))); err != nil {
		t.Fatal(err)
	}
	if err := ixDelete(db, "uid=u02,dc=example,dc=test"); err != nil {
		t.Fatal(err)
	}
	if err := ixRename(db, "uid=u03,dc=example,dc=test", "uid=u03b,dc=example,dc=test"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	db = ixOpen(t, path)
	ixVerify(t, db)
	if ids := ixLookup(t, ctx, db, "uid", "u02"); len(ids) != 0 {
		t.Fatalf("deleted uid=u02 still indexed: %d ids", len(ids))
	}
	if ids := ixLookup(t, ctx, db, "cn", "renamed one"); len(ids) != 1 {
		t.Fatalf("replaced cn not indexed: %d ids", len(ids))
	}
	// Rename keeps the id and unchanged attribute values: uid=u03 still
	// resolves, now pointing at the entry stored under uid=u03b.
	ids := ixLookup(t, ctx, db, "uid", "u03")
	if len(ids) != 1 {
		t.Fatalf("renamed entry lost uid posting: %d ids", len(ids))
	}
	var e *ldapserver.Entry
	err := db.View(func(tx *bolt.Tx) error {
		var err error
		e, err = ixFetch(ctx, tx, ids[0])
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if e.DN != "uid=u03b,dc=example,dc=test" {
		t.Fatalf("renamed entry DN = %q", e.DN)
	}
}

// TestRebuildIndexes: corruption in a posting bucket is detected by
// VerifyIndexes and repaired by RebuildIndexes inside one writable tx.
func TestRebuildIndexes(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		if err := ixAdd(db, ixEntry(fmt.Sprintf("uid=r%02d,dc=example,dc=test", i),
			ixStrAttr("uid", fmt.Sprintf("r%02d", i)),
			ixStrAttr("objectClass", "inetOrgPerson"),
		)); err != nil {
			t.Fatal(err)
		}
	}
	ixVerify(t, db)

	// Corrupt: drop one real posting and inject a stale one.
	err := db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("eq_uid"))
		c := b.Cursor()
		k, _ := c.First()
		if k == nil {
			return errors.New("expected postings")
		}
		if err := b.Delete(append([]byte(nil), k...)); err != nil {
			return err
		}
		return b.Put(postingKey(normalizeIndexKey(indexedAttributes["uid"], []byte("phantom")), 9999), []byte{})
	})
	if err != nil {
		t.Fatal(err)
	}
	err = db.View(func(tx *bolt.Tx) error { return VerifyIndexes(tx, ixIter(tx)) })
	if err == nil || !strings.Contains(err.Error(), "stale posting") && !strings.Contains(err.Error(), "missing posting") {
		t.Fatalf("VerifyIndexes after corruption = %v, want stale/missing posting error", err)
	}
	if strings.Contains(err.Error(), "phantom") {
		t.Fatalf("verify error leaks an attribute value: %v", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error { return RebuildIndexes(tx, ixIter(tx)) }); err != nil {
		t.Fatalf("RebuildIndexes: %v", err)
	}
	ixVerify(t, db)
	if ids := ixLookup(t, ctx, db, "uid", "phantom"); len(ids) != 0 {
		t.Fatalf("stale posting survived rebuild: %d ids", len(ids))
	}
	for i := 0; i < 10; i++ {
		if ids := ixLookup(t, ctx, db, "uid", fmt.Sprintf("r%02d", i)); len(ids) != 1 {
			t.Fatalf("after rebuild uid=r%02d: %d ids, want 1", i, len(ids))
		}
	}
}

// TestAddDeleteSymmetry covers posting churn across repeated write cycles.
func TestAddDeleteSymmetry(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	ctx := context.Background()
	for round := 0; round < 3; round++ {
		for i := 0; i < 25; i++ {
			e := ixEntry(fmt.Sprintf("uid=c%02d,dc=example,dc=test", i),
				ixStrAttr("uid", fmt.Sprintf("c%02d", i)),
				ixStrAttr("objectClass", "inetOrgPerson", "top"),
			)
			if err := ixAdd(db, e); err != nil {
				t.Fatal(err)
			}
		}
		ixVerify(t, db)
		if ids := ixLookup(t, ctx, db, "objectClass", "inetorgperson"); len(ids) != 25 {
			t.Fatalf("round %d: objectClass postings = %d, want 25", round, len(ids))
		}
		for i := 0; i < 25; i++ {
			if err := ixDelete(db, fmt.Sprintf("uid=c%02d,dc=example,dc=test", i)); err != nil {
				t.Fatal(err)
			}
		}
		ixVerify(t, db)
		if ids := ixLookup(t, ctx, db, "objectClass", "inetorgperson"); len(ids) != 0 {
			t.Fatalf("round %d: %d postings leaked after delete", round, len(ids))
		}
	}
}
