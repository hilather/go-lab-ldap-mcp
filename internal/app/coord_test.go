package app

import (
	"sync"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

func TestCoordinatorSerializesGroupMembership(t *testing.T) {
	t.Parallel()
	repo := newFakeGroups()
	svc := New(Deps{Groups: repo, Locks: NewCoordinator()}).Groups
	alice := directory.MemberRef{Kind: "user", ID: "alice"}
	g, err := svc.Create(t.Context(), writer(), directory.GroupSpec{ID: "staff", Members: []directory.MemberRef{alice}})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	for _, id := range []string{"bob", "carol"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			_, e := svc.AddMembers(t.Context(), writer(), "staff", []directory.MemberRef{{Kind: "user", ID: id}}, g.Revision)
			errc <- e
		}(id)
	}
	wg.Wait()
	close(errc)
	var ok, conflict int
	for e := range errc {
		if e == nil {
			ok++
			continue
		}
		if fieldCode(e) == directory.FieldConflict {
			conflict++
			continue
		}
		t.Fatalf("unexpected: %v", e)
	}
	if ok != 1 || conflict != 1 {
		t.Fatalf("ok=%d conflict=%d", ok, conflict)
	}
	got, err := svc.Get(t.Context(), writer(), "staff")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Members) != 2 {
		t.Fatalf("lost update: %+v", got.Members)
	}
}

func TestResetGateBlocksOrdinaryWrites(t *testing.T) {
	t.Parallel()
	g := reset.NewGate()
	g.Set(reset.Resetting)
	svc := New(Deps{Users: newFakeUsers(), Gate: g}).Users
	_, err := svc.Create(t.Context(), writer(), CreateUser{ID: "x", Password: Secret("unit-user-pass-12")})
	if err == nil {
		t.Fatal("write during reset")
	}
}
