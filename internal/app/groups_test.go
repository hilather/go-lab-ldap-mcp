package app

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestGroupServiceMembershipIdempotent(t *testing.T) {
	t.Parallel()
	repo := newFakeGroups()
	aud := &MemoryAuditor{}
	svc := New(Deps{Groups: repo, Audit: aud}).Groups
	alice := directory.MemberRef{Kind: "user", ID: "alice"}
	bob := directory.MemberRef{Kind: "user", ID: "bob"}
	g, err := svc.Create(t.Context(), writer(), directory.GroupSpec{ID: "staff", Members: []directory.MemberRef{alice}})
	if err != nil {
		t.Fatal(err)
	}
	sum, err := svc.AddMembers(t.Context(), writer(), "staff", []directory.MemberRef{alice}, g.Revision)
	if err != nil || len(sum.Added) != 0 || len(sum.Unchanged) != 1 {
		t.Fatalf("idempotent add: %+v %v", sum, err)
	}
	sum, err = svc.AddMembers(t.Context(), writer(), "staff", []directory.MemberRef{bob}, sum.Revision)
	if err != nil || len(sum.Added) != 1 {
		t.Fatalf("add bob: %+v %v", sum, err)
	}
	sum, err = svc.RemoveMembers(t.Context(), writer(), "staff", []directory.MemberRef{bob}, sum.Revision)
	if err != nil || len(sum.Removed) != 1 {
		t.Fatalf("remove: %+v %v", sum, err)
	}
	sum, err = svc.RemoveMembers(t.Context(), writer(), "staff", []directory.MemberRef{bob}, sum.Revision)
	if err != nil || len(sum.Removed) != 0 || len(sum.Unchanged) != 1 {
		t.Fatalf("idempotent remove: %+v %v", sum, err)
	}
	_, err = svc.ReplaceMembers(t.Context(), writer(), "staff", []directory.MemberRef{alice, bob}, "")
	if err == nil {
		t.Fatal("replace requires revision")
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
	if err := svc.Delete(t.Context(), writer(), "staff", ""); err == nil {
		t.Fatal("delete requires revision")
	}
	if err := svc.Delete(t.Context(), writer(), "staff", sum.Revision); err != nil {
		t.Fatal(err)
	}
	for _, ev := range aud.Snapshot() {
		if ev.Action == "" || ev.Result == "" {
			t.Fatalf("audit: %+v", ev)
		}
	}
}

func TestGroupRejectsEmptyAndCycle(t *testing.T) {
	t.Parallel()
	svc := New(Deps{Groups: newFakeGroups()}).Groups
	_, err := svc.Create(t.Context(), writer(), directory.GroupSpec{ID: "staff"})
	if err == nil {
		t.Fatal("empty group")
	}
	_, err = svc.Create(t.Context(), writer(), directory.GroupSpec{
		ID:      "staff",
		Members: []directory.MemberRef{{Kind: "group", ID: "staff"}},
	})
	if err == nil {
		t.Fatal("self member")
	}
}

func TestGroupForbidden(t *testing.T) {
	t.Parallel()
	svc := New(Deps{Groups: newFakeGroups()}).Groups
	_, err := svc.Create(t.Context(), reader(), directory.GroupSpec{
		ID: "staff", Members: []directory.MemberRef{{Kind: "user", ID: "a"}},
	})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("forbidden: %v", err)
	}
}
