package parity

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver/store"
)

type searchCountingStore struct {
	*store.Store
	counter *store.ReadCounter
}

func (s searchCountingStore) View(ctx context.Context, fn func(ldapserver.ReadTx) error) error {
	return s.Store.View(ctx, func(tx ldapserver.ReadTx) error { return fn(searchCountingTx{tx, s.counter}) })
}

type searchCountingTx struct {
	ldapserver.ReadTx
	counter *store.ReadCounter
}

func (t searchCountingTx) WalkEqual(ctx context.Context, attr string, value []byte, visit func(*ldapserver.Entry) error) (bool, error) {
	return t.ReadTx.(ldapserver.SearchEqualWalker).WalkEqual(store.WithReadCounter(ctx, t.counter), attr, value, visit)
}

func TestProductionSearchUsesBoundedEqualityIndex(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "directory.bolt"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	err = s.Update(t.Context(), func(tx ldapserver.UpdateTx) error {
		for _, dn := range []string{"dc=example,dc=test", "ou=people,dc=example,dc=test"} {
			if err := tx.Add(t.Context(), ldapserver.NewEntry(dn, ldapserver.StringAttribute("objectClass", "top"))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Update(t.Context(), func(tx ldapserver.UpdateTx) error {
		for i := 0; i < 1000; i++ {
			if err := tx.Add(t.Context(), ldapserver.NewEntry(fmt.Sprintf("uid=test%04d,ou=people,dc=example,dc=test", i), ldapserver.StringAttribute("uid", fmt.Sprintf("test%04d", i)), ldapserver.StringAttribute("cn", "Common"), ldapserver.StringAttribute("objectClass", "inetOrgPerson"))); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	schema, err := ldapserver.StandardSchema()
	if err != nil {
		t.Fatal(err)
	}
	counter := &store.ReadCounter{}
	srv, err := ldapserver.New(ldapserver.Options{Suffix: "dc=example,dc=test", LDAPAddress: "127.0.0.1:0", Store: searchCountingStore{s, counter}, Schema: schema, Codec: ldapserver.NewBERCodec(ldapserver.BERCodecOptions{}), ACI: &ldapserver.FakeACI{Decide: func(context.Context, ldapserver.ReadTx, ldapserver.ACICheck) (bool, error) { return true, nil }}, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for srv.LDAPAddr() == nil && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if srv.LDAPAddr() == nil {
		t.Fatal("listener unavailable")
	}
	client, err := ldap.DialURL("ldap://" + srv.LDAPAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	request := ldap.NewSearchRequest("ou=people,dc=example,dc=test", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(&(uid=test0500)(cn=Common))", []string{"uid"}, nil)
	res, err := client.Search(request)
	if err != nil || len(res.Entries) != 1 {
		t.Fatalf("indexed conjunction: %v", err)
	}
	if got := counter.EntryFetches(); got != 1 {
		t.Fatalf("index should decode one candidate, got %d", got)
	}
	// Base-object scope already identifies one entry. A broad equality
	// predicate must not walk global postings to reach the last matching ID.
	baseBefore := counter.EntryFetches()
	baseIndexBefore := counter.IndexReads()
	baseRequest := ldap.NewSearchRequest("uid=test0999,ou=people,dc=example,dc=test", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(cn=Common)", []string{"uid"}, nil)
	baseResult, err := client.Search(baseRequest)
	if err != nil || len(baseResult.Entries) != 1 || baseResult.Entries[0].GetAttributeValue("uid") != "test0999" {
		t.Fatalf("direct base equality: %v", err)
	}
	if counter.EntryFetches() != baseBefore || counter.IndexReads() != baseIndexBefore {
		t.Fatal("base-object search walked global equality postings")
	}
	// A wide posting list still stops after the additional matching entry;
	// no complete postings slice or subtree is allocated before the limit.
	before := counter.EntryFetches()
	request.Filter = "(cn=Common)"
	request.SizeLimit = 1
	res, err = client.Search(request)
	if !ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) || len(res.Entries) != 1 {
		t.Fatalf("indexed limit: %v", err)
	}
	if got := counter.EntryFetches() - before; got != 2 {
		t.Fatalf("bounded index fetches=%d, want2", got)
	}
}
