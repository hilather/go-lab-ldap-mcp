package store

import (
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	bolt "go.etcd.io/bbolt"
)

func TestDNKeyMigrationAndCollisionIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.bolt")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	const escaped = `uid=alice\,ou=people,dc=test`
	const plain = `uid=alice,ou=people,dc=test`
	err = s.Update(t.Context(), func(tx ldapserver.UpdateTx) error {
		if err := tx.Add(t.Context(), ldapserver.NewEntry("dc=test", ldapserver.StringAttribute("dc", "test"))); err != nil {
			return err
		}
		return tx.Add(t.Context(), ldapserver.NewEntry(escaped, ldapserver.StringAttribute("uid", "escaped")))
	})
	if err != nil {
		t.Fatal(err)
	}
	// Model the legacy unescaped folded-key index. Stored DN blobs remain
	// authoritative and the reopen must restore all derived indexes atomically.
	err = s.db.Update(func(tx *bolt.Tx) error {
		old := []byte(plain)
		current := []byte(mustParseDN(t, escaped).FoldedKey())
		id := append([]byte(nil), tx.Bucket(bucketDN2ID).Get(current)...)
		if err := tx.Bucket(bucketDN2ID).Delete(current); err != nil {
			return err
		}
		if err := tx.Bucket(bucketDN2ID).Put(old, id); err != nil {
			return err
		}
		return tx.Bucket([]byte(idxMetaBucket)).Put(idxVersionKey, binary.BigEndian.AppendUint64(nil, 1))
	})
	if err != nil {
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
	err = s.Update(t.Context(), func(tx ldapserver.UpdateTx) error {
		return tx.Add(t.Context(), ldapserver.NewEntry(plain, ldapserver.StringAttribute("uid", "plain")))
	})
	if err != nil {
		t.Fatalf("distinct DN aliases prior entry: %v", err)
	}
	err = s.View(t.Context(), func(tx ldapserver.ReadTx) error {
		for dn, want := range map[string]string{escaped: "escaped", plain: "plain"} {
			e, err := tx.Entry(t.Context(), mustParseDN(t, dn))
			if err != nil {
				return err
			}
			if got := string(e.Values("uid")[0]); got != want {
				t.Fatalf("DN alias: got %q, want %q", got, want)
			}
		}
		children, err := tx.Children(t.Context(), mustParseDN(t, "dc=test"))
		if err != nil {
			return err
		}
		if len(children) != 1 || children[0].DN != escaped {
			t.Fatalf("migrated child index: %#v", children)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyIndexes(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestDNKeyMigrationFailureRollsBack(t *testing.T) {
	for _, kind := range []string{"invalid", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "directory.bolt")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			err = s.Update(t.Context(), func(tx ldapserver.UpdateTx) error {
				return tx.Add(t.Context(), ldapserver.NewEntry("dc=test", ldapserver.StringAttribute("dc", "test")))
			})
			if err != nil {
				t.Fatal(err)
			}
			err = s.db.Update(func(tx *bolt.Tx) error {
				entry := ldapserver.NewEntry("dc=test", ldapserver.StringAttribute("dc", "test"))
				if kind == "invalid" {
					entry.DN = "invalid"
				}
				blob, err := encodeEntry(entry)
				if err != nil {
					return err
				}
				if err := tx.Bucket(bucketID2Entry).Put(uint64Bytes(99), blob); err != nil {
					return err
				}
				if err := tx.Bucket(bucketDN2ID).Put([]byte("legacy-sentinel"), uint64Bytes(99)); err != nil {
					return err
				}
				return tx.Bucket([]byte(idxMetaBucket)).Put(idxVersionKey, binary.BigEndian.AppendUint64(nil, 1))
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if reopened, err := Open(path); err == nil {
				reopened.Close()
				t.Fatal("migration unexpectedly accepted invalid/duplicate DN")
			}
			raw, err := bolt.Open(path, fileMode, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer raw.Close()
			err = raw.View(func(tx *bolt.Tx) error {
				if got := tx.Bucket(bucketDN2ID).Get([]byte("legacy-sentinel")); len(got) == 0 {
					t.Fatal("failed migration changed legacy DN index")
				}
				if got, err := IndexVersion(tx); err != nil || got != 1 {
					t.Fatalf("failed migration version=%d err=%v", got, err)
				}
				if got := tx.Bucket(bucketID2Entry).Get(uint64Bytes(99)); len(got) == 0 {
					t.Fatal("failed migration discarded stored entry")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
