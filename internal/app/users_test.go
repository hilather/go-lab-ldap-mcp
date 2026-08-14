package app

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestUserServiceCreateGetUpdateDelete(t *testing.T) {
	t.Parallel()
	repo := newFakeUsers()
	aud := &MemoryAuditor{}
	svc := New(Deps{Users: repo, Audit: aud}).Users
	ctx := t.Context()
	u, err := svc.Create(ctx, writer(), CreateUser{
		ID: "alice", Password: observability.Secret("unit-user-pass-12"),
		Attributes: map[string]string{"sn": "Example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.Get(ctx, writer(), "alice")
	if err != nil || got.Revision != u.Revision {
		t.Fatalf("get: %+v %v", got, err)
	}
	upd, err := svc.Update(ctx, writer(), "alice", UpdateUser{
		UserPatch: directory.UserPatch{Attributes: map[string]string{"description": "x"}},
		Revision:  u.Revision,
	})
	if err != nil || upd.Revision == u.Revision {
		t.Fatalf("update: %+v %v", upd, err)
	}
	if err := svc.Delete(ctx, writer(), "alice", upd.Revision); err != nil {
		t.Fatal(err)
	}
	if ev := aud.Snapshot(); len(ev) < 3 {
		t.Fatalf("audit events: %+v", ev)
	}
	for _, ev := range aud.Snapshot() {
		raw, _ := json.Marshal(ev)
		if hasSecret(string(raw), "unit-user-pass-12") {
			t.Fatalf("password in audit: %s", raw)
		}
	}
}

func TestUserCreatePasswordFailureCompensates(t *testing.T) {
	t.Parallel()
	repo := newFakeUsers()
	repo.addErr = directory.Error("password", directory.FieldIncomplete, "user create did not complete")
	repo.leftover = true
	aud := &MemoryAuditor{}
	svc := New(Deps{Users: repo, Audit: aud}).Users
	_, err := svc.Create(t.Context(), writer(), CreateUser{ID: "ghost", Password: observability.Secret("unit-user-pass-12")})
	if err == nil {
		t.Fatal("expected failure")
	}
	if _, err := repo.Get(t.Context(), "ghost"); err == nil {
		t.Fatal("leftover user was not compensated")
	}
	if len(repo.deleted) != 1 || repo.deleted[0] != "ghost" {
		t.Fatalf("deleted=%v", repo.deleted)
	}
	ev := aud.Snapshot()
	if len(ev) != 1 || ev[0].Result != AuditFailure || ev[0].Action != OpUserCreate.Name {
		t.Fatalf("audit: %+v", ev)
	}
}

func TestUserCreateReadFailureDoesNotCompensate(t *testing.T) {
	t.Parallel()
	repo := newFakeUsers()
	repo.addErr = directory.Error("entry", directory.FieldUnavailable, "directory unavailable")
	repo.leftover = true
	svc := New(Deps{Users: repo}).Users
	_, err := svc.Create(t.Context(), writer(), CreateUser{ID: "keepme", Password: observability.Secret("unit-user-pass-12")})
	if err == nil || !isUnavailable(err) {
		t.Fatalf("want unavailable: %v", err)
	}
	if _, err := repo.Get(t.Context(), "keepme"); err != nil {
		t.Fatal("post-success leftover must not be deleted")
	}
	if len(repo.deleted) != 0 {
		t.Fatalf("compensated: %v", repo.deleted)
	}
}

func TestUserCreateConflictDoesNotDeleteExisting(t *testing.T) {
	t.Parallel()
	repo := newFakeUsers()
	repo.put(directory.User{ID: "alice", UID: "alice", Enabled: true})
	svc := New(Deps{Users: repo}).Users
	_, err := svc.Create(t.Context(), writer(), CreateUser{ID: "alice", Password: observability.Secret("unit-user-pass-12")})
	if err == nil || fieldCode(err) != directory.FieldConflict {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := repo.Get(t.Context(), "alice"); err != nil {
		t.Fatal("pre-existing user deleted")
	}
}

func TestUserValidationAndRevision(t *testing.T) {
	t.Parallel()
	svc := New(Deps{Users: newFakeUsers()}).Users
	_, err := svc.Create(t.Context(), writer(), CreateUser{ID: "alice"})
	if err == nil {
		t.Fatal("password required")
	}
	apperr.Assert(t, err).Code(apperr.CodeConfiguration)
	_, err = svc.Create(t.Context(), writer(), CreateUser{
		ID: "alice", Password: observability.Secret("x"),
		Attributes: map[string]string{"userPassword": "nope"},
	})
	if err == nil {
		t.Fatal("forbidden attr")
	}
	_, err = svc.Update(t.Context(), writer(), "alice", UpdateUser{UserPatch: directory.UserPatch{Attributes: map[string]string{"sn": "x"}}})
	if err == nil {
		t.Fatal("revision required")
	}
	if err := svc.Delete(t.Context(), writer(), "alice", ""); err == nil {
		t.Fatal("delete revision required")
	}
}

func TestUserForbiddenAndUnavailable(t *testing.T) {
	t.Parallel()
	repo := newFakeUsers()
	svc := New(Deps{Users: repo}).Users
	_, err := svc.Create(t.Context(), reader(), CreateUser{ID: "alice", Password: observability.Secret("x")})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("forbidden write: %v", err)
	}
	if !strings.Contains(err.Error(), "missing required scope") {
		t.Fatalf("public: %v", err)
	}
	var e *apperr.Error
	if !asError(err, &e) || e.Fields()[0].Message != "directory:write" {
		t.Fatalf("required scope not identified: %#v", err)
	}
	if strings.Contains(err.Error(), "reader") || strings.Contains(err.Error(), "admin") {
		t.Fatal("token id in missing-scope error")
	}

	repo.listErr = directory.Error("connection", directory.FieldUnavailable, "directory unavailable")
	_, err = svc.List(t.Context(), writer(), directory.UserListQuery{})
	if err == nil || !isUnavailable(err) {
		t.Fatalf("unavailable: %v", err)
	}
}

func TestUserPasswordScopeIndependent(t *testing.T) {
	t.Parallel()
	repo := newFakeUsers()
	u := repo.put(directory.User{ID: "alice", UID: "alice", Enabled: true})
	writeOnly := Principal{Kind: KindToken, ID: "w", Scopes: directory.ScopeSet{"directory:write"}}
	svc := New(Deps{Users: repo}).Users
	err := svc.SetPassword(t.Context(), writeOnly, "alice", observability.Secret("unit-user-pass-99"), u.Revision)
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("write must not imply password: %v", err)
	}
}
