package app

import (
	"encoding/json"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/audit"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const unitPass = "unit-ops-pass-12"

func TestEveryOperationCoverage(t *testing.T) {
	t.Parallel()
	users := newFakeUsers()
	groups := newFakeGroups()
	sink := &audit.Memory{}
	svc := New(Deps{
		Users:            users,
		Groups:           groups,
		Search:           fakeSearch{page: directory.SearchPage{Entries: []directory.SearchEntry{{DN: "uid=a,dc=x", Attributes: []directory.AttrKV{{Name: "cn", Value: "A"}}}}}},
		Bind:             fakeBind{res: directory.BindTestResult{Outcome: directory.BindOutcomeSuccess}},
		Schema:           fakeSchema{dse: directory.RootDSE{VendorName: "389"}},
		Caps:             fakeCaps{caps: directory.Capabilities{RequiredOK: true}},
		Marker:           fakeMarker{m: directory.BaselineMarker{AppliedRevision: "aaa"}},
		Audit:            HookAuditor{Hook: sink},
		ExpectedRevision: "aaa",
		ControlRevision:  "bbb",
	})
	ctx := t.Context()
	w := writer()
	none := Principal{Kind: KindToken, ID: "none"}

	u, err := svc.Users.Create(ctx, w, CreateUser{ID: "alice", Password: observability.Secret(unitPass)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Users.Get(ctx, w, "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Users.List(ctx, w, directory.UserListQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Users.Update(ctx, none, "alice", UpdateUser{Revision: u.Revision}); err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("forbidden update: %v", err)
	}
	if _, err := svc.Users.Update(ctx, w, "alice", UpdateUser{Revision: "stale", UserPatch: directory.UserPatch{Attributes: map[string]string{"sn": "Z"}}}); err == nil || fieldCode(err) != directory.FieldConflict {
		t.Fatalf("conflict update: %v", err)
	}
	u, err = svc.Users.Update(ctx, w, "alice", UpdateUser{Revision: u.Revision, UserPatch: directory.UserPatch{Attributes: map[string]string{"sn": "Z"}}})
	if err != nil {
		t.Fatal(err)
	}
	u, err = svc.Users.SetEnabled(ctx, w, "alice", false, u.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Users.SetPassword(ctx, w, "alice", observability.Secret(unitPass+"x"), u.Revision); err != nil {
		t.Fatal(err)
	}
	if err := svc.Users.SetPassword(ctx, w, "alice", observability.Secret(""), u.Revision); err == nil {
		t.Fatal("password validation")
	}

	alice := directory.MemberRef{Kind: "user", ID: "alice"}
	g, err := svc.Groups.Create(ctx, w, directory.GroupSpec{ID: "staff", Members: []directory.MemberRef{alice}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Groups.Get(ctx, w, "staff"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Groups.List(ctx, w, directory.GroupListQuery{}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Groups.AddMembers(ctx, none, "staff", []directory.MemberRef{{Kind: "user", ID: "bob"}}, g.Revision); err == nil {
		t.Fatal("forbidden members")
	}
	if _, err := svc.Groups.ReplaceMembers(ctx, w, "staff", []directory.MemberRef{alice}, "nope"); err == nil || fieldCode(err) != directory.FieldConflict {
		t.Fatalf("replace conflict: %v", err)
	}
	sum, err := svc.Groups.AddMembers(ctx, w, "staff", []directory.MemberRef{{Kind: "user", ID: "bob"}}, g.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Groups.Delete(ctx, w, "staff", sum.Revision); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Query.Search(ctx, w, directory.SearchQuery{Filter: "(uid=a)"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Query.BindTest(ctx, w, "alice", observability.Secret(unitPass), directory.TransportLDAPS); err != nil {
		t.Fatal(err)
	}
	schemaP := Principal{Kind: KindToken, ID: "s", Scopes: directory.ScopeSet{"schema:read"}}
	if _, err := svc.Query.RootDSE(ctx, schemaP); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Query.Schema(ctx, schemaP); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Query.Capabilities(ctx, w); err != nil {
		t.Fatal(err)
	}
	b, err := svc.Query.Baseline(ctx, w)
	if err != nil || !b.Match || b.ControlRevision != "bbb" {
		t.Fatalf("baseline %+v %v", b, err)
	}

	users.listErr = directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
	if _, err := svc.Users.List(ctx, w, directory.UserListQuery{}); err == nil || !isUnavailable(err) {
		t.Fatalf("unavailable: %v", err)
	}

	if err := svc.Users.Delete(ctx, w, "alice", u.Revision); err != nil {
		t.Fatal(err)
	}

	var sawDeny, sawBind bool
	for _, ev := range sink.Snapshot() {
		raw, _ := json.Marshal(ev)
		if hasSecret(string(raw), unitPass, unitPass+"x") {
			t.Fatalf("secret in audit: %s", raw)
		}
		if ev.RequestID == "" && ev.Actor == "" {
			t.Fatalf("empty audit: %+v", ev)
		}
		if ev.Action == audit.ActionAuthzDeny {
			sawDeny = true
			if ev.Actor != "token:none" {
				t.Fatalf("deny actor %q", ev.Actor)
			}
		}
		if ev.Action == audit.ActionBindTest {
			sawBind = true
			if ev.Target != "bind" {
				t.Fatalf("bind target %q", ev.Target)
			}
		}
	}
	if !sawDeny || !sawBind {
		t.Fatalf("missing deny=%v bind=%v", sawDeny, sawBind)
	}
}
