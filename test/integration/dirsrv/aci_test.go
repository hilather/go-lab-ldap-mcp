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
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
)

func TestShippedApplyACIReadback(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"phase": "aci"`) && !strings.Contains(out, `"phase":"aci"`) {
		t.Fatalf("missing aci phase:\n%s", out)
	}
	suf := ldapSearch(t, inst, "dc=example,dc=test", "aci")
	if !strings.Contains(suf, `acl "labldap:runtime-suffix-read"`) {
		t.Fatalf("missing runtime-suffix-read:\n%s", suf)
	}
	if !strings.Contains(suf, `acl "Enable anyone domain read"`) {
		t.Fatalf("unmanaged domain-read ACI was removed:\n%s", suf)
	}
	people := ldapSearch(t, inst, "ou=people,dc=example,dc=test", "aci")
	if !strings.Contains(people, `acl "labldap:runtime-people-write"`) || !strings.Contains(people, `acl "labldap:runtime-password"`) {
		t.Fatalf("missing people ACIs:\n%s", people)
	}
	groups := ldapSearch(t, inst, "ou=groups,dc=example,dc=test", "aci")
	if !strings.Contains(groups, `acl "labldap:runtime-groups-write"`) {
		t.Fatalf("missing groups ACI:\n%s", groups)
	}
	out2, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("re-apply: %v\n%s", err, out2)
	}
	if strings.Count(ldapSearch(t, inst, "dc=example,dc=test", "aci"), `acl "labldap:runtime-suffix-read"`) != 1 {
		t.Fatal("duplicate named ACI after re-apply")
	}
}

func TestShippedACIServerReject(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	inst.WriteCA(t, ca)
	_, err := ds389.Engine{}.ReconcileACIs(t.Context(), bootstrap.ACIRequest{
		TreeRequest: bootstrap.TreeRequest{
			DMPassword: inst.Password(),
			LDAPURL:    "ldaps://" + inst.LDAPSAddr,
			CAFile:     ca,
			Host:       inst.Hostname(t),
			Write:      true,
		},
		ACIs: []config.NamedACI{{
			ID:     "labldap:probe-reject",
			Target: "dc=example,dc=test",
			Text:   "(this is not a valid aci",
		}},
	})
	if err == nil {
		t.Fatal("expected server_reject")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.aci")
	if !aciField(err, "server_reject") || !strings.Contains(err.Error(), "labldap:probe-reject") {
		t.Fatalf("want server_reject with ACL id: %v", err)
	}
}

func TestShippedACIRuntimeCannotEscapeSuffix(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if err := runtimeBind(t, inst, "uid=rt,ou=people,dc=example,dc=test", "runtime-secret"); err != nil {
		t.Fatalf("runtime bind: %v", err)
	}
	cmd := exec.Command("docker", "exec", inst.Name,
		"ldapsearch", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "uid=rt,ou=people,dc=example,dc=test", "-w", "runtime-secret",
		"-b", "cn=config", "-s", "base", "dn")
	out, err := cmd.CombinedOutput()
	if strings.Contains(string(out), "dn: cn=config") {
		t.Fatalf("runtime read cn=config:\n%s", out)
	}
	if err == nil && strings.Contains(string(out), "nsslapd-") {
		t.Fatalf("runtime read cn=config attributes:\n%s", out)
	}
	mod := exec.Command("docker", "exec", "-i", inst.Name,
		"ldapmodify", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "uid=rt,ou=people,dc=example,dc=test", "-w", "runtime-secret")
	mod.Stdin = strings.NewReader("dn: cn=config\nchangetype: modify\nreplace: nsslapd-port\nnsslapd-port: 3389\n")
	mout, merr := mod.CombinedOutput()
	if merr == nil {
		t.Fatalf("runtime wrote cn=config:\n%s", mout)
	}
	still := ldapSearch(t, inst, "uid=rt,ou=people,dc=example,dc=test", "dn")
	if !strings.Contains(still, "uid=rt,ou=people,dc=example,dc=test") {
		t.Fatalf("runtime entry gone:\n%s", still)
	}
	before := ldapSearch(t, inst, "dc=example,dc=test", "aci")
	if out, err := execValidate(t, inst, guest); err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	after := ldapSearch(t, inst, "dc=example,dc=test", "aci")
	if before != after {
		t.Fatalf("validate mutated ACIs\nbefore=%s\nafter=%s", before, after)
	}
}

func aciField(err error, code string) bool {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	for _, f := range e.Fields() {
		if f.Path == "phase.aci" && f.Code == code {
			return true
		}
	}
	return false
}
