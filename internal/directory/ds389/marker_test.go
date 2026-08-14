package ds389

import (
	"context"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func sampleMarkerReq(write bool) bootstrap.MarkerRequest {
	return bootstrap.MarkerRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:     "dc=example,dc=test",
			PeopleDN:   "ou=people,dc=example,dc=test",
			GroupsDN:   "ou=groups,dc=example,dc=test",
			RuntimeDN:  "uid=rt,ou=people,dc=example,dc=test",
			DMPassword: observability.Secret("dm-secret"),
			Write:      write,
		},
		DN:               "cn=labldap-baseline,dc=example,dc=test",
		AppliedRevision:  "abc123",
		ExpectedRevision: "abc123",
		ApplyVersion:     "labldap-bootstrap/dev",
		AppliedAt:        "2026-08-13T00:00:00Z",
	}
}

func TestWriteMarkerPreferredAndRead(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	req := sampleMarkerReq(true)
	if err := eng.WriteMarker(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	got, err := eng.ReadMarker(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.AppliedRevision != "abc123" || got.ExpectedRevision != "abc123" {
		t.Fatalf("marker = %+v", got)
	}
	if got.ApplyVersion != "labldap-bootstrap/dev" || got.AppliedAt != "2026-08-13T00:00:00Z" {
		t.Fatalf("marker = %+v", got)
	}
	if got.Encoding != markerEncodingAttr {
		t.Fatalf("encoding = %s", got.Encoding)
	}
	entry := mem.entries["cn=labldap-baseline,dc=example,dc=test"]
	if entry == nil || !hasObjectClass(entry, "device") {
		t.Fatal("marker missing device class")
	}
	joined := strings.ToLower(strings.Join(mem.adds, " ") + strings.Join(mem.mods, " "))
	if strings.Contains(joined, "dm-secret") || strings.Contains(joined, "password") {
		t.Fatal("marker write leaked secret")
	}
}

func TestWriteMarkerJSONFallback(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	mem.failPreferredMarker = true
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	if err := eng.WriteMarker(t.Context(), sampleMarkerReq(true)); err != nil {
		t.Fatal(err)
	}
	got, err := eng.ReadMarker(t.Context(), sampleMarkerReq(false))
	if err != nil {
		t.Fatal(err)
	}
	if got.Encoding != markerEncodingJSON || got.AppliedRevision != "abc123" {
		t.Fatalf("fallback marker = %+v", got)
	}
}

func TestWriteMarkerRefusesValidate(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	err := eng.WriteMarker(t.Context(), sampleMarkerReq(false))
	if err == nil {
		t.Fatal("expected apply-only error")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.marker")
	if _, ok := mem.entries["cn=labldap-baseline,dc=example,dc=test"]; ok {
		t.Fatal("validate wrote marker")
	}
}

func TestWriteMarkerInjectedFailureLeavesPrior(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	req := sampleMarkerReq(true)
	if err := eng.WriteMarker(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	eng.FailWriteMarker = bootstrap.PhaseError("marker", "apply_failed", "injected")
	req.AppliedRevision = "newrev"
	if err := eng.WriteMarker(t.Context(), req); err == nil {
		t.Fatal("expected injected failure")
	}
	got, err := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}.ReadMarker(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if got.AppliedRevision != "abc123" {
		t.Fatalf("prior marker overwritten: %+v", got)
	}
}

func TestReadMarkerMissing(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	got, err := eng.ReadMarker(t.Context(), sampleMarkerReq(false))
	if err != nil {
		t.Fatal(err)
	}
	if got.AppliedRevision != "" || got.DN != "cn=labldap-baseline,dc=example,dc=test" {
		t.Fatalf("%+v", got)
	}
}

func TestWriteMarkerRejectsSecretMaterial(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	req := sampleMarkerReq(true)
	req.AppliedRevision = "password-digest"
	if err := eng.WriteMarker(t.Context(), req); err == nil {
		t.Fatal("expected secret reject")
	}
}

func TestInspectDriftExtraAndMissing(t *testing.T) {
	mem := &seedMem{entries: baseEntries()}
	mem.entries["uid=alice,ou=people,dc=example,dc=test"] = &ldap.Entry{DN: "uid=alice,ou=people,dc=example,dc=test"}
	mem.entries["uid=extra,ou=people,dc=example,dc=test"] = &ldap.Entry{DN: "uid=extra,ou=people,dc=example,dc=test"}
	mem.entries["cn=staff,ou=groups,dc=example,dc=test"] = &ldap.Entry{DN: "cn=staff,ou=groups,dc=example,dc=test"}
	mem.entries["dc=example,dc=test"].Attributes = []*ldap.EntryAttribute{
		{Name: "aci", Values: []string{`(targetattr!="userPassword")(version 3.0; acl "labldap:runtime-suffix-read"; allow (read) userdn="ldap:///anyone";)`}},
	}
	eng := Engine{TreeDial: func(context.Context, bootstrap.TreeRequest) (treeConn, error) { return mem, nil }}
	rep, err := eng.Inspect(t.Context(), bootstrap.DriftRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:    "dc=example,dc=test",
			PeopleDN:  "ou=people,dc=example,dc=test",
			GroupsDN:  "ou=groups,dc=example,dc=test",
			RuntimeDN: "uid=rt,ou=people,dc=example,dc=test",
		},
		Users:  []config.NormalizedUser{{ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"}},
		Groups: []config.NormalizedGroup{{ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test"}},
		ACIs: []config.NamedACI{{
			ID:     "labldap:runtime-suffix-read",
			Target: "dc=example,dc=test",
			Text:   `(targetattr!="userPassword")(version 3.0; acl "labldap:runtime-suffix-read"; allow (read) userdn="ldap:///anyone";)`,
		}},
		MarkerDN:          "cn=labldap-baseline,dc=example,dc=test",
		DirectoryRevision: "abc123",
		Preserve:          []string{"uid=rt,ou=people,dc=example,dc=test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Differ || len(rep.ExtraUsers) != 1 {
		t.Fatalf("report = %+v", rep)
	}
	if rep.MarkerRevision != "" {
		t.Fatal("missing marker should have empty revision")
	}
}
