package store

// Integration tests for the T-130 indices against the real T-129 Store:
// posting maintenance inside Store.Update commits, MVCC snapshot reads via
// EqualCandidateResolver, RFC 4528-shaped read-then-write, crash reopen,
// and version-triggered rebuild on Open.

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	bolt "go.etcd.io/bbolt"
)

func openStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func storeUser(uid, cn string) *ldapserver.Entry {
	return &ldapserver.Entry{
		DN: fmt.Sprintf("uid=%s,ou=people,dc=example,dc=test", uid),
		Attributes: []ldapserver.Attribute{
			{Name: "uid", Values: [][]byte{[]byte(uid)}},
			{Name: "cn", Values: [][]byte{[]byte(cn)}},
			{Name: "objectClass", Values: [][]byte{[]byte("inetOrgPerson"), []byte("top")}},
		},
	}
}

func storeAdd(t *testing.T, s *Store, e *ldapserver.Entry) {
	t.Helper()
	err := s.Update(context.Background(), func(tx ldapserver.UpdateTx) error {
		return tx.Add(context.Background(), e)
	})
	if err != nil {
		t.Fatalf("add %s: %v", e.DN, err)
	}
}

// equalCandidates resolves an indexed equality predicate through the
// ReadTx extension exactly the way op_search will (merge point).
func equalCandidates(t *testing.T, ctx context.Context, s *Store, attr, value string) []*ldapserver.Entry {
	t.Helper()
	var out []*ldapserver.Entry
	err := s.View(ctx, func(tx ldapserver.ReadTx) error {
		r, ok := tx.(EqualCandidateResolver)
		if !ok {
			return errors.New("readTx does not implement EqualCandidateResolver")
		}
		entries, indexed, err := r.EqualCandidates(ctx, attr, []byte(value))
		if err != nil {
			return err
		}
		if !indexed {
			return fmt.Errorf("attribute %s should be indexed", attr)
		}
		out = entries
		return nil
	})
	if err != nil {
		t.Fatalf("EqualCandidates(%s=%s): %v", attr, value, err)
	}
	return out
}

// TestStoreIndexedEqualityDoesNotScan is the 1k-entry acceptance case
// against the real bbolt Store.
func TestStoreIndexedEqualityDoesNotScan(t *testing.T) {
	s := openStore(t, t.TempDir()+"/store.bolt")
	ctx := context.Background()
	storeAdd(t, s, &ldapserver.Entry{
		DN: "dc=example,dc=test",
		Attributes: []ldapserver.Attribute{
			{Name: "objectClass", Values: [][]byte{[]byte("domain"), []byte("top")}},
		},
	})
	storeAdd(t, s, &ldapserver.Entry{
		DN: "ou=people,dc=example,dc=test",
		Attributes: []ldapserver.Attribute{
			{Name: "ou", Values: [][]byte{[]byte("people")}},
			{Name: "objectClass", Values: [][]byte{[]byte("organizationalUnit"), []byte("top")}},
		},
	})
	const n = 1000
	for i := 0; i < n; i++ {
		uid := fmt.Sprintf("user%04d", i)
		storeAdd(t, s, storeUser(uid, fmt.Sprintf("User Number %04d", i)))
	}

	counter := &ReadCounter{}
	hits := equalCandidates(t, WithReadCounter(ctx, counter), s, "uid", "user0742")
	if len(hits) != 1 {
		t.Fatalf("indexed lookup: got %d hits, want 1", len(hits))
	}
	if got := string(hits[0].Values("cn")[0]); got != "User Number 0742" {
		t.Fatalf("wrong entry: cn=%q", got)
	}
	if got := counter.EntryFetches(); got != 1 {
		t.Fatalf("indexed search fetched %d of %d entries, want 1", got, n)
	}
	if got := counter.IndexReads(); got > 4 {
		t.Fatalf("indexed search examined %d posting keys, want a tiny bound", got)
	}

	// Case-folded lookup resolves the same single entry without a scan.
	counter2 := &ReadCounter{}
	hits = equalCandidates(t, WithReadCounter(ctx, counter2), s, "uid", "USER0742")
	if len(hits) != 1 || counter2.EntryFetches() != 1 {
		t.Fatalf("folded lookup: %d hits, %d fetches", len(hits), counter2.EntryFetches())
	}

	// Contrast: a subtree scan walks every entry under the base.
	base, err := config.ParseDN("ou=people,dc=example,dc=test")
	if err != nil {
		t.Fatal(err)
	}
	var scanned int
	err = s.View(ctx, func(tx ldapserver.ReadTx) error {
		entries, err := tx.Subtree(ctx, base)
		scanned = len(entries)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	// Subtree includes the base entry itself: ou=people plus the users.
	if scanned != n+1 {
		t.Fatalf("subtree scan returned %d, want %d", scanned, n+1)
	}
}

// TestStoreReadThenWriteSingleCommit proves the RFC 4528-ready shape on the
// real Store: one Update reads, asserts, and writes, committing as a unit.
func TestStoreReadThenWriteSingleCommit(t *testing.T) {
	s := openStore(t, t.TempDir()+"/store.bolt")
	ctx := context.Background()
	dn, err := config.ParseDN("cn=counter,dc=example,dc=test")
	if err != nil {
		t.Fatal(err)
	}
	err = s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		return tx.Add(ctx, &ldapserver.Entry{
			DN: dn.String(),
			Attributes: []ldapserver.Attribute{
				{Name: "cn", Values: [][]byte{[]byte("counter")}},
				{Name: "objectClass", Values: [][]byte{[]byte("device")}},
				{Name: "description", Values: [][]byte{[]byte("0")}},
			},
		})
	})
	if err != nil {
		t.Fatal(err)
	}

	bump := func(expect int) error {
		return s.Update(ctx, func(tx ldapserver.UpdateTx) error {
			e, err := tx.Entry(ctx, dn)
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
			e.Attributes[2].Values[0] = []byte(strconv.Itoa(cur + 1))
			return tx.Replace(ctx, e)
		})
	}

	const seq = 24
	for i := 0; i < seq; i++ {
		if err := bump(i); err != nil {
			t.Fatalf("bump %d: %v", i, err)
		}
	}

	// Concurrent writers asserting the same value: Store.Update is one
	// serialized bbolt commit, so exactly one assertion passes.
	var wg sync.WaitGroup
	var committed atomic.Int64
	for i := 0; i < 12; i++ {
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

	if err := s.View(ctx, func(tx ldapserver.ReadTx) error {
		e, err := tx.Entry(ctx, dn)
		if err != nil {
			return err
		}
		if got := string(e.Values("description")[0]); got != strconv.Itoa(seq+1) {
			return fmt.Errorf("counter = %s, want %d", got, seq+1)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyIndexes(ctx); err != nil {
		t.Fatalf("VerifyIndexes: %v", err)
	}
}

// TestStoreIndexConsistencyAcrossReopen exercises add, replace, delete, and
// rename with closes between commit points; postings must agree with
// id2entry after every reopen.
func TestStoreIndexConsistencyAcrossReopen(t *testing.T) {
	path := t.TempDir() + "/store.bolt"
	ctx := context.Background()

	s := openStore(t, path)
	storeAdd(t, s, storeUser("alice", "Alice"))
	storeAdd(t, s, storeUser("bob", "Bob"))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = openStore(t, path)
	if err := s.VerifyIndexes(ctx); err != nil {
		t.Fatalf("after first reopen: %v", err)
	}
	// Replace changes indexed values.
	aliceDN, _ := config.ParseDN("uid=alice,ou=people,dc=example,dc=test")
	err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		e, err := tx.Entry(ctx, aliceDN)
		if err != nil {
			return err
		}
		e.Attributes[1].Values[0] = []byte("Alice Cooper")
		return tx.Replace(ctx, e)
	})
	if err != nil {
		t.Fatal(err)
	}
	// Rename keeps ids; the old uid posting remains valid (attribute
	// values unchanged at the store layer).
	from, _ := config.ParseDN("uid=bob,ou=people,dc=example,dc=test")
	to, _ := config.ParseDN("uid=robert,ou=people,dc=example,dc=test")
	if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error { return tx.Rename(ctx, from, to) }); err != nil {
		t.Fatal(err)
	}
	// Delete the other entry.
	delDN, _ := config.ParseDN("uid=alice,ou=people,dc=example,dc=test")
	if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error { return tx.Delete(ctx, delDN) }); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s = openStore(t, path)
	if err := s.VerifyIndexes(ctx); err != nil {
		t.Fatalf("after mutation reopen: %v", err)
	}
	if hits := equalCandidates(t, ctx, s, "uid", "alice"); len(hits) != 0 {
		t.Fatalf("deleted alice still indexed: %d hits", len(hits))
	}
	hits := equalCandidates(t, ctx, s, "uid", "bob")
	if len(hits) != 1 || hits[0].DN != "uid=robert,ou=people,dc=example,dc=test" {
		t.Fatalf("renamed bob: %d hits, dn %v", len(hits), hits)
	}
}

// TestStoreOpenRebuildsMissingIndices simulates a database written before
// the equality indices existed: Open must detect the absent version stamp
// and rebuild postings from id2entry.
func TestStoreOpenRebuildsMissingIndices(t *testing.T) {
	path := t.TempDir() + "/store.bolt"
	ctx := context.Background()

	s := openStore(t, path)
	storeAdd(t, s, storeUser("carol", "Carol"))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Drop the index buckets and version stamp, faking a pre-T-130 file.
	raw, err := bolt.Open(path, fileMode, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = raw.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket([]byte(idxMetaBucket)); err != nil {
			return err
		}
		for _, name := range IndexedAttributes() {
			if err := tx.DeleteBucket([]byte(indexBucketPrefix + name)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	s = openStore(t, path)
	if err := s.VerifyIndexes(ctx); err != nil {
		t.Fatalf("after rebuild-on-open: %v", err)
	}
	if hits := equalCandidates(t, ctx, s, "uid", "carol"); len(hits) != 1 {
		t.Fatalf("rebuilt index: %d hits for carol, want 1", len(hits))
	}
}
