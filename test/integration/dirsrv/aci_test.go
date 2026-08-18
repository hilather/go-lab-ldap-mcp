//go:build integration

package dirsrv

import (
	"errors"
	"os"
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
	if !strings.Contains(compactACI(people), `targetattr!="aci"`) {
		t.Fatalf("people-write must deny aci:\n%s", people)
	}
	groups := ldapSearch(t, inst, "ou=groups,dc=example,dc=test", "aci")
	if !strings.Contains(groups, `acl "labldap:runtime-groups-write"`) {
		t.Fatalf("missing groups ACI:\n%s", groups)
	}
	if !strings.Contains(compactACI(groups), `targetattr!="aci"`) {
		t.Fatalf("groups-write must deny aci:\n%s", groups)
	}
	out2, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("re-apply: %v\n%s", err, out2)
	}
	if strings.Count(ldapSearch(t, inst, "dc=example,dc=test", "aci"), `acl "labldap:runtime-suffix-read"`) != 1 {
		t.Fatal("duplicate named ACI after re-apply")
	}
}

// invalidNamedACI is parseable enough to pass requireOwnedName but uses an
// unknown permission so 389 returns LDAP 21 (ACL Syntax Error).
const invalidNamedACI = `(target="ldap:///dc=example,dc=test")(targetattr="*")(version 3.0; acl "labldap:probe-reject"; allow (explode) userdn="ldap:///anyone";)`

func TestShippedACIServerReject(t *testing.T) {
	inst := Start(t)
	hostDir, guest := stageApply(t, inst, "dc=example,dc=test")
	bad := `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: reject }
spec:
  directory: { suffix: "dc=example,dc=test", allowRawACI: true }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  acls:
    - id: probe-reject
      rawACI: '` + invalidNamedACI + `'
`
	hostBad := filepath.Join(hostDir, "bad.yaml")
	if err := os.WriteFile(hostBad, []byte(withITEngine(bad)), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "cp", hostBad, inst.Name+":/tmp/labldap-apply/bad.yaml").CombinedOutput(); err != nil {
		t.Fatalf("cp bad.yaml: %v\n%s", err, out)
	}
	guest.Config = "/tmp/labldap-apply/bad.yaml"
	out, err := execApply(t, inst, guest, nil)
	t.Logf("shipped apply reject:\n%s", out)
	if err == nil {
		t.Fatalf("expected server_reject:\n%s", out)
	}
	if !strings.Contains(out, "phase.aci") || !strings.Contains(out, "server_reject") || !strings.Contains(out, "labldap:probe-reject") {
		t.Fatalf("want phase.aci server_reject labldap:probe-reject:\n%s", out)
	}

	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	inst.WriteCA(t, ca)
	_, rerr := ds389.Engine{}.ReconcileACIs(t.Context(), bootstrap.ACIRequest{
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
			Text:   invalidNamedACI,
		}},
	})
	if rerr == nil {
		t.Fatal("expected ReconcileACIs server_reject")
	}
	apperr.Assert(t, rerr).Code(apperr.CodeBootstrap).FieldPath("phase.aci")
	if !aciField(rerr, "server_reject") || !strings.Contains(rerr.Error(), "labldap:probe-reject") {
		t.Fatalf("want server_reject with ACL id: %v", rerr)
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

func compactACI(s string) string {
	return strings.Join(strings.Fields(s), " ")
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
