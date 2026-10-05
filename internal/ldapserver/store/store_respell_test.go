package store

import (
	"context"
	"slices"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
)

// TestStoreRenameRespells pins the bbolt side of case-only renames
// (resolved CAND-30): Rename between DNs with equal folded keys respells
// the entry and every descendant in place, and the parent and child
// indexes keep resolving under either spelling. The İ parent checks the
// descendant rebase when folding changes a value's byte length.
func TestStoreRenameRespells(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, tc := range []struct {
		name, from, to string
		kids           []string // child RDNs seeded under from
	}{
		{"leaf", "uid=alice,ou=people,dc=example,dc=test", "uid=ALICE,ou=people,dc=example,dc=test", nil},
		{"subtree", "ou=people,dc=example,dc=test", "ou=PEOPLE,dc=example,dc=test", []string{"uid=alice", "uid=bob"}},
		{"multibyte", "ou=İt,dc=example,dc=test", "ou=İT,dc=example,dc=test", []string{"uid=carol"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, _ := openTemp(t)
			seedTree(t, s)
			if tc.name == "multibyte" {
				if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
					if err := tx.Add(ctx, ldapserver.NewEntry(tc.from, ldapserver.StringAttribute("objectClass", "top", "organizationalUnit"))); err != nil {
						return err
					}
					return tx.Add(ctx, ldapserver.NewEntry("uid=carol,"+tc.from, ldapserver.StringAttribute("objectClass", "top", "person")))
				}); err != nil {
					t.Fatal(err)
				}
			}
			from, to := mustParseDN(t, tc.from), mustParseDN(t, tc.to)
			if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error { return tx.Rename(ctx, from, to) }); err != nil {
				t.Fatalf("Rename: %v", err)
			}
			if err := s.View(ctx, func(tx ldapserver.ReadTx) error {
				for _, dn := range []string{tc.from, tc.to} {
					e, err := tx.Entry(ctx, mustParseDN(t, dn))
					if err != nil {
						t.Fatalf("Entry(%q): %v", dn, err)
					}
					if e.DN != tc.to {
						t.Errorf("Entry(%q).DN = %q, want %q", dn, e.DN, tc.to)
					}
				}
				parent, _ := to.Parent()
				sibs, err := tx.Children(ctx, parent)
				if err != nil {
					return err
				}
				if n := countDN(sibs, tc.to); n != 1 {
					t.Errorf("parent children %v: respelled entry %d times", dnsOf(sibs), n)
				}
				for _, dn := range []string{tc.from, tc.to} {
					kids, err := tx.Children(ctx, mustParseDN(t, dn))
					if err != nil {
						return err
					}
					want := make([]string, 0, len(tc.kids))
					for _, k := range tc.kids {
						want = append(want, k+","+tc.to)
					}
					slices.Sort(want)
					if got := dnsOf(kids); !slices.Equal(got, want) {
						t.Errorf("Children(%q) = %v, want %v", dn, got, want)
					}
					sub, err := tx.Subtree(ctx, mustParseDN(t, dn))
					if err != nil {
						return err
					}
					if len(sub) != len(tc.kids)+1 {
						t.Errorf("Subtree(%q) = %v", dn, dnsOf(sub))
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func countDN(entries []*ldapserver.Entry, dn string) int {
	n := 0
	for _, e := range entries {
		if e.DN == dn {
			n++
		}
	}
	return n
}
