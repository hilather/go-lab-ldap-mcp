//go:build integration

package dirsrv

import (
	"errors"
	"os/exec"
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
		got := ldapSearch(t, inst, dn, "dn", "objectClass")
		if !strings.Contains(got, dn) {
			t.Fatalf("missing %s:\n%s", dn, got)
		}
	}
	out2, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("re-apply: %v\n%s", err, out2)
	}
	people := ldapSearchChildren(t, inst, "dc=example,dc=test")
	if strings.Count(people, "ou=people") != 1 || strings.Count(people, "ou=groups") != 1 {
		t.Fatalf("duplicate parents:\n%s", people)
	}
	rts := ldapSearchChildren(t, inst, "ou=people,dc=example,dc=test")
	if strings.Count(rts, "uid=rt,") != 1 {
		t.Fatalf("duplicate runtime:\n%s", rts)
	}
}

func TestShippedTreeRuntimeBindAndNoGroup(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if err := runtimeBind(t, inst, "uid=rt,ou=people,dc=example,dc=test", "runtime-secret"); err != nil {
		t.Fatalf("runtime LDAPS bind: %v", err)
	}
	mo := ldapSearch(t, inst, "uid=rt,ou=people,dc=example,dc=test", "memberOf")
	if strings.Contains(strings.ToLower(mo), "memberof:") {
		t.Fatalf("runtime has memberOf:\n%s", mo)
	}
	hits := ldapSearchFilter(t, inst, "ou=groups,dc=example,dc=test", "(member=uid=rt,ou=people,dc=example,dc=test)")
	if strings.Contains(hits, "dn:") {
		t.Fatalf("runtime listed in a group:\n%s", hits)
	}
	before := ldapSearch(t, inst, "ou=people,dc=example,dc=test", "dn")
	if out, err := execValidate(t, inst, guest); err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	after := ldapSearch(t, inst, "ou=people,dc=example,dc=test", "dn")
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

func runtimeBind(t *testing.T, inst *Instance, dn, password string) error {
	t.Helper()
	cmd := exec.Command("docker", "exec", inst.Name,
		"ldapsearch", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", dn, "-w", password, "-s", "base", "-b", dn, "dn")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("runtime bind: %v\n%s", err, out)
	}
	return err
}

func ldapSearchChildren(t *testing.T, inst *Instance, base string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", inst.Name,
		"ldapsearch", "-x", "-LLL", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal(),
		"-b", base, "-s", "one", "dn").CombinedOutput()
	if err != nil {
		t.Fatalf("search children %s: %v\n%s", base, err, out)
	}
	return string(out)
}

func ldapSearchFilter(t *testing.T, inst *Instance, base, filter string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", inst.Name,
		"ldapsearch", "-x", "-LLL", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal(),
		"-b", base, filter, "dn").CombinedOutput()
	if err != nil {
		t.Fatalf("search %s %s: %v\n%s", base, filter, err, out)
	}
	return string(out)
}
