package store

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	bolt "go.etcd.io/bbolt"
)

// Index format v3: stored attribute names post to their type's bucket, the
// same resolution filter evaluation uses (C6 attribute descriptions).
func TestIndexPostsByAttributeType(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	ctx := context.Background()
	for _, e := range []*ldapserver.Entry{
		ixEntry("uid=bob,dc=example,dc=test", ixStrAttr("uid", "bob"), ixStrAttr("uid;x-test", "bobtag")),
		ixEntry("uid=a,dc=example,dc=test", ixStrAttr("userid", "aliasu")),
		ixEntry("uid=o,dc=example,dc=test", ixStrAttr("0.9.2342.19200300.100.1.1", "oidu")),
		ixEntry("cn=g,dc=example,dc=test", ixStrAttr("commonName;lang-en", "Gruppe"),
			ixStrAttr("member;x-a", "uid=bob,dc=example,dc=test"),
			ixStrAttr("2.5.4.0", "groupOfNames")),
	} {
		if err := ixAdd(db, e); err != nil {
			t.Fatal(err)
		}
	}
	ixVerify(t, db)
	for _, c := range []struct{ attr, value string }{
		{"uid", "bobtag"}, {"uid", "aliasu"}, {"uid", "oidu"}, {"cn", "gruppe"},
		{"member", "uid=bob,dc=example,dc=test"}, {"objectClass", "groupofnames"},
	} {
		if ids := ixLookup(t, ctx, db, c.attr, c.value); len(ids) != 1 {
			t.Errorf("(%s=%s): %d ids, want 1", c.attr, c.value, len(ids))
		}
	}
	// Removing the subtype value drops its posting.
	if err := ixReplace(db, ixEntry("uid=bob,dc=example,dc=test", ixStrAttr("uid", "bob"))); err != nil {
		t.Fatal(err)
	}
	ixVerify(t, db)
	if ids := ixLookup(t, ctx, db, "uid", "bobtag"); len(ids) != 0 {
		t.Fatalf("(uid=bobtag) after removal: %d ids, want 0", len(ids))
	}
}

// The same value under the type and a subtype shares one posting; removing
// either spelling must keep it while the other remains.
func TestIndexDualSpellingValueRemoval(t *testing.T) {
	db := ixOpen(t, t.TempDir()+"/ix.bolt")
	ctx := context.Background()
	dn := "uid=dup,dc=example,dc=test"
	if err := ixAdd(db, ixEntry(dn, ixStrAttr("uid", "dup"), ixStrAttr("uid;x-test", "dup"))); err != nil {
		t.Fatal(err)
	}
	if ids := ixLookup(t, ctx, db, "uid", "dup"); len(ids) != 1 {
		t.Fatalf("dual spelling: %d ids, want 1", len(ids))
	}
	if err := ixReplace(db, ixEntry(dn, ixStrAttr("uid", "dup"))); err != nil {
		t.Fatal(err)
	}
	ixVerify(t, db)
	if ids := ixLookup(t, ctx, db, "uid", "dup"); len(ids) != 1 {
		t.Fatalf("after dropping the subtype: %d ids, want 1", len(ids))
	}
	if err := ixReplace(db, ixEntry(dn, ixStrAttr("uid;x-test", "dup"))); err != nil {
		t.Fatal(err)
	}
	ixVerify(t, db)
	if ids := ixLookup(t, ctx, db, "uid", "dup"); len(ids) != 1 {
		t.Fatalf("after dropping the base value: %d ids, want 1", len(ids))
	}
}

func storeIndexVersion(t *testing.T, s *Store) uint64 {
	t.Helper()
	var v uint64
	if err := s.db.View(func(tx *bolt.Tx) error {
		var err error
		v, err = IndexVersion(tx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return v
}

// Open rebuilds a v2 database once, stamps v3 in the same transaction, and
// does not rebuild on the next Open: a posting corrupted after the upgrade
// is still reported by VerifyIndexes rather than silently repaired.
func TestOpenStampsIndexVersionAfterRebuild(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.bolt")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
		if err := tx.Add(ctx, ldapserver.NewEntry("dc=test", ldapserver.StringAttribute("dc", "test"))); err != nil {
			return err
		}
		return tx.Add(ctx, ldapserver.NewEntry("uid=bob,dc=test",
			ldapserver.StringAttribute("uid", "bob"), ldapserver.StringAttribute("uid;x-test", "bobtag")))
	}); err != nil {
		t.Fatal(err)
	}
	if v := storeIndexVersion(t, s); v != indexVersion {
		t.Fatalf("fresh store version %d, want %d", v, indexVersion)
	}
	// Model a v2 database: no posting for the subtype value, stamp 2.
	bobtag := postingKeyFor(t, s, "uid", "bobtag")
	if err := s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket([]byte("eq_uid")).Delete(bobtag); err != nil {
			return err
		}
		return tx.Bucket([]byte(idxMetaBucket)).Put(idxVersionKey, binary.BigEndian.AppendUint64(nil, 2))
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v := storeIndexVersion(t, s); v != indexVersion {
		t.Fatalf("after upgrade version %d, want %d", v, indexVersion)
	}
	if err := s.VerifyIndexes(ctx); err != nil {
		t.Fatalf("after upgrade: %v", err)
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("eq_uid")).Get(bobtag) == nil {
			t.Fatal("upgrade rebuild did not post uid;x-test")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket([]byte("eq_uid")).Delete(bobtag) }); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.VerifyIndexes(ctx); err == nil {
		t.Fatal("reopen rebuilt the indexes again: corrupted posting was repaired")
	}
}

// postingKeyFor returns the eq posting key of one value of the only entry
// that has it.
func postingKeyFor(t *testing.T, s *Store, attr, value string) []byte {
	t.Helper()
	var key []byte
	if err := s.db.View(func(tx *bolt.Tx) error {
		ids, indexed, err := LookupIDs(t.Context(), tx, attr, []byte(value))
		if err != nil {
			return err
		}
		if !indexed || len(ids) != 1 {
			t.Fatalf("LookupIDs(%s=%s) = %v indexed=%v", attr, value, ids, indexed)
		}
		key = postingKey(normalizeIndexKey(indexedAttributes[attr], []byte(value)), ids[0])
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return key
}
