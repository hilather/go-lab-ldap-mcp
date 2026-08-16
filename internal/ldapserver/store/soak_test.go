package store

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
)

// TestBoltSoakWriteCycles is the T-150 bbolt growth gate: repeated
// add/delete churn plus read-only subtree scans must not grow the database
// file without bound. bbolt never shrinks the file, so the assertion is
// steady-state, not shrinkage: after a warm-up that reaches a stable
// freelist, further identical cycles reuse freed pages and the file size
// stays flat.
//
// Complements the connection-churn soak in internal/ldapserver (which owns
// goroutine/FD deltas); the bolt file assertion lives here because the
// store package is the only place both types are importable.
func TestBoltSoakWriteCycles(t *testing.T) {
	t.Parallel()
	s, path := openTemp(t)
	ctx := context.Background()

	peopleDN := mustDN(t, "ou=people,dc=example,dc=test")
	seed := func() {
		t.Helper()
		err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
			for _, e := range []*ldapserver.Entry{
				ldapserver.NewEntry("dc=example,dc=test",
					ldapserver.StringAttribute("objectClass", "top", "domain"),
					ldapserver.StringAttribute("dc", "example")),
				ldapserver.NewEntry("ou=people,dc=example,dc=test",
					ldapserver.StringAttribute("objectClass", "top", "organizationalUnit"),
					ldapserver.StringAttribute("ou", "people")),
			} {
				if err := tx.Add(ctx, e); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	seed()

	// oneCycle adds and deletes one entry and runs one subtree read.
	oneCycle := func(i int) {
		t.Helper()
		dn := fmt.Sprintf("uid=churn-%d,ou=people,dc=example,dc=test", i%8)
		err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
			return tx.Add(ctx, ldapserver.NewEntry(dn,
				ldapserver.StringAttribute("objectClass", "top", "person"),
				ldapserver.StringAttribute("uid", fmt.Sprintf("churn-%d", i%8)),
				ldapserver.StringAttribute("cn", "Churn User"),
				ldapserver.StringAttribute("sn", "Churn"),
				ldapserver.StringAttribute("description", "churn entry value with a little body")))
		})
		if err != nil {
			t.Fatalf("cycle %d add: %v", i, err)
		}
		if err := s.Update(ctx, func(tx ldapserver.UpdateTx) error {
			d, err := config.ParseDN(dn)
			if err != nil {
				return err
			}
			return tx.Delete(ctx, d)
		}); err != nil {
			t.Fatalf("cycle %d delete: %v", i, err)
		}
		if err := s.View(ctx, func(tx ldapserver.ReadTx) error {
			_, err := tx.Subtree(ctx, peopleDN)
			return err
		}); err != nil {
			t.Fatalf("cycle %d subtree: %v", i, err)
		}
	}

	fileSize := func() int64 {
		t.Helper()
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat bolt: %v", err)
		}
		return st.Size()
	}

	const warmup = 64
	for i := 0; i < warmup; i++ {
		oneCycle(i)
	}
	base := fileSize()
	for i := warmup; i < warmup*4; i++ {
		oneCycle(i)
	}
	got := fileSize()
	if got != base {
		t.Fatalf("bolt file grew after warm-up: %d -> %d bytes (freelist not reusing pages)", base, got)
	}
	t.Logf("bolt size stable at %d bytes across %d churn cycles", got, warmup*4)
}

func mustDN(t *testing.T, s string) config.DN {
	t.Helper()
	d, err := config.ParseDN(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
