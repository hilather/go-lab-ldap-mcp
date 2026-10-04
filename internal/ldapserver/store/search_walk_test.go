package store

import (
	"errors"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
)

func TestSearchWalkStopsBeforeDecodingRemainingEntries(t *testing.T) {
	s, _ := openTemp(t)
	seedTree(t, s)
	stop := errors.New("stop")
	err := s.View(t.Context(), func(tx ldapserver.ReadTx) error {
		walker := tx.(ldapserver.SearchWalker)
		count := 0
		err := walker.WalkSearch(t.Context(), mustParseDN(t, "dc=example,dc=test"), ldapserver.ScopeWholeSubtree, func(*ldapserver.Entry) error {
			count++
			return stop
		})
		if count != 1 || !errors.Is(err, stop) {
			t.Fatalf("callback termination: count=%d err=%v", count, err)
		}
		count = 0
		err = walker.WalkSearch(t.Context(), mustParseDN(t, "dc=example,dc=test"), ldapserver.ScopeWholeSubtree, func(*ldapserver.Entry) error { count++; return nil })
		if count != 4 || err != nil {
			t.Fatalf("complete traversal: count=%d err=%v", count, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
