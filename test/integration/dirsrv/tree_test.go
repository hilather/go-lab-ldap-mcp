//go:build integration

package dirsrv

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestShippedApplyTreeReadbackAndIdempotent(t *testing.T) {
	inst := Start(t)
	d := inst.Dial(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	out1, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out1)
	}
	if !strings.Contains(out1, `"phase": "tree"`) && !strings.Contains(out1, `"phase":"tree"`) {
		t.Fatalf("missing tree phase:\n%s", out1)
	}
	for _, dn := range []string{
		"dc=example,dc=test",
		"ou=people,dc=example,dc=test",
		"ou=groups,dc=example,dc=test",
		"uid=rt,ou=people,dc=example,dc=test",
	} {
		got := ldapSearch(t, d, dn, "dn", "objectClass")
		if !strings.Contains(got, dn) {
			t.Fatalf("missing %s:\n%s", dn, got)
		}
	}
	out2, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("re-apply: %v\n%s", err, out2)
	}
	people := ldapSearchChildren(t, d, "dc=example,dc=test")
	if strings.Count(people, "ou=people") != 1 || strings.Count(people, "ou=groups") != 1 {
		t.Fatalf("duplicate parents:\n%s", people)
	}
	rts := ldapSearchChildren(t, d, "ou=people,dc=example,dc=test")
	if strings.Count(rts, "uid=rt,") != 1 {
		t.Fatalf("duplicate runtime:\n%s", rts)
	}
}

func TestShippedTreeRuntimeBindAndNoGroup(t *testing.T) {
	inst := Start(t)
	d := inst.Dial(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if err := runtimeBind(t, d, "uid=rt,ou=people,dc=example,dc=test", "runtime-secret"); err != nil {
		t.Fatalf("runtime LDAPS bind: %v", err)
	}
	mo := ldapSearch(t, d, "uid=rt,ou=people,dc=example,dc=test", "memberOf")
	if strings.Contains(strings.ToLower(mo), "memberof:") {
		t.Fatalf("runtime has memberOf:\n%s", mo)
	}
	hits := ldapSearchFilter(t, d, "ou=groups,dc=example,dc=test", "(member=uid=rt,ou=people,dc=example,dc=test)")
	if strings.Contains(hits, "dn:") {
		t.Fatalf("runtime listed in a group:\n%s", hits)
	}
	before := ldapSearch(t, d, "ou=people,dc=example,dc=test", "dn")
	if out, err := execValidate(t, inst, guest); err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	after := ldapSearch(t, d, "ou=people,dc=example,dc=test", "dn")
	if before != after {
		t.Fatalf("validate mutated tree\nbefore=%s\nafter=%s", before, after)
	}
}

func TestShippedTreeParentFailedAndAccountBind(t *testing.T) {
	inst := Start(t)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	inst.WriteCA(t, ca)
	_, err := ds389.Engine{}.ReconcileTree(t.Context(), bootstrap.TreeRequest{
		Suffix:          "dc=example,dc=test",
		PeopleDN:        "ou=people,dc=example,dc=test",
		GroupsDN:        "ou=groups,dc=example,dc=test",
		RuntimeDN:       "uid=rt,ou=people,dc=example,dc=test",
		RuntimePassword: observability.Secret("runtime-secret"),
		DMPassword:      inst.Password(),
		LDAPURL:         "ldaps://" + inst.LDAPSAddr,
		CAFile:          ca,
		Host:            inst.Hostname(t),
		Write:           false,
	})
	if err == nil {
		t.Fatal("expected parent_failed")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.tree")
	if !treeField(err, "parent_failed") {
		t.Fatalf("want parent_failed: %v", err)
	}

	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	_, err = ds389.Engine{}.ReconcileTree(t.Context(), bootstrap.TreeRequest{
		Suffix:          "dc=example,dc=test",
		PeopleDN:        "ou=people,dc=example,dc=test",
		GroupsDN:        "ou=groups,dc=example,dc=test",
		RuntimeDN:       "uid=rt,ou=people,dc=example,dc=test",
		RuntimePassword: observability.Secret("wrong-runtime-password"),
		DMPassword:      inst.Password(),
		LDAPURL:         "ldaps://" + inst.LDAPSAddr,
		CAFile:          ca,
		Host:            inst.Hostname(t),
		Write:           false,
	})
	if err == nil {
		t.Fatal("expected account_bind")
	}
	if !treeField(err, "account_bind") {
		t.Fatalf("want account_bind: %v", err)
	}
}

func treeField(err error, code string) bool {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	for _, f := range e.Fields() {
		if f.Path == "phase.tree" && f.Code == code {
			return true
		}
	}
	return false
}
