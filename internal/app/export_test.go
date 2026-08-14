package app

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/reset"
)

func exporter() Principal {
	return Principal{Kind: KindToken, ID: "admin", Scopes: directory.ScopeSet{
		"lab:export", "directory:read",
	}}
}

func TestExportRequiresLabExportScope(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"})
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	var buf bytes.Buffer
	err := svc.Export.Write(t.Context(), writer(), &buf, ExportRequest{})
	if err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("want auth: %v", err)
	}
}

func TestExportOmitsSecretsAndIsDeterministic(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{
		ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []directory.AttrKV{
			{Name: "sn", Value: "Example"},
			{Name: "userPassword", Value: seedAlice},
		},
	})
	inv := newLiveReset(users, groups)
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	var a, b bytes.Buffer
	if err := svc.Export.Write(t.Context(), exporter(), &a, ExportRequest{}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Export.Write(t.Context(), exporter(), &b, ExportRequest{}); err != nil {
		t.Fatal(err)
	}
	if a.String() != b.String() {
		t.Fatalf("nondeterministic export")
	}
	if strings.Contains(a.String(), seedAlice) || strings.Contains(strings.ToLower(a.String()), "userpassword") {
		t.Fatalf("secret leaked:\n%s", a.String())
	}
	got, err := directory.ParseLDIF(&a)
	if err != nil || len(got) == 0 {
		t.Fatalf("parse %d %v\n%s", len(got), err, a.String())
	}
}

func TestExportLimitIsExplicit(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"})
	users.put(directory.User{ID: "bob", UID: "bob", DN: "uid=bob,ou=people,dc=example,dc=test"})
	inv := newLiveReset(users, groups)
	d := resetDeps(users, groups, inv, reset.NewGate())
	d.ExportMaxEntries = 1
	svc := New(d)
	var buf bytes.Buffer
	err := svc.Export.Write(t.Context(), exporter(), &buf, ExportRequest{})
	if err == nil {
		t.Fatal("limit")
	}
	if apperr.CodeOf(err) != apperr.CodeExport || fieldCode(err) != "limit" {
		t.Fatalf("want export limit: %v", err)
	}
	if strings.Contains(buf.String(), directory.LDIFCompleteMark) {
		t.Fatalf("limit presented as complete:\n%s", buf.String())
	}
}

func TestExportCancelStopsReads(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	users.put(directory.User{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"})
	inv := newLiveReset(users, groups)
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := svc.Export.Write(ctx, exporter(), io.Discard, ExportRequest{})
	if err == nil {
		t.Fatal("canceled")
	}
}

func TestExportBlockedDuringReset(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	svc.Reset.gate.Set(reset.Resetting)
	err := svc.Export.Write(t.Context(), exporter(), io.Discard, ExportRequest{})
	if err == nil {
		t.Fatal("export during reset")
	}
	apperr.Assert(t, err).Code(apperr.CodeReset).Retryable(true)
}

func TestResetCurrentRequiresScope(t *testing.T) {
	t.Parallel()
	users, groups := newFakeUsers(), newFakeGroups()
	inv := newLiveReset(users, groups)
	svc := New(resetDeps(users, groups, inv, reset.NewGate()))
	if _, err := svc.Reset.Current(t.Context(), writer()); err == nil || apperr.CodeOf(err) != apperr.CodeAuth {
		t.Fatalf("want auth: %v", err)
	}
	st, err := svc.Reset.Current(t.Context(), resetter())
	if err != nil {
		t.Fatal(err)
	}
	if st.State != string(reset.Ready) {
		t.Fatalf("%+v", st)
	}
}
