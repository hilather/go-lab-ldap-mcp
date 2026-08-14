//go:build integration

package dirsrv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestResetRecoversPartialStates(t *testing.T) {
	inst := Start(t)
	hostDir, guest := stageSeedApply(t, inst, seedYAML("merge"), seedCanary)
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out, seedCanary, inst.password))
	}

	addExtraPerson(t, inst, "uid=runtime-extra,ou=people,dc=example,dc=test")
	replaceGroupMembers(t, inst, "cn=staff,ou=groups,dc=example,dc=test", "uid=runtime-extra,ou=people,dc=example,dc=test")
	ldapDelete(t, inst, "uid=alice,ou=people,dc=example,dc=test")
	ldapDelete(t, inst, "cn=labldap-baseline,dc=example,dc=test")
	deleteNamedACI(t, inst, "ou=people,dc=example,dc=test", "labldap:runtime-people-write")

	resetYAML := seedYAML("reset")
	if err := os.WriteFile(filepath.Join(hostDir, "lab.yaml"), []byte(resetYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "cp", filepath.Join(hostDir, "lab.yaml"), inst.Name+":/tmp/labldap-apply/lab.yaml").CombinedOutput(); err != nil {
		t.Fatalf("cp reset yaml: %v\n%s", err, out)
	}
	out2, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("reset recover: %v\n%s", err, redactLogs(out2, seedCanary, inst.password))
	}
	assertNoCanary(t, inst, out2, seedCanary)
	if err := userBind(t, inst, "uid=alice,ou=people,dc=example,dc=test", seedCanary); err != nil {
		t.Fatalf("alice after reset: %v", err)
	}
	extra := ldapSearchAllowMissing(t, inst, "uid=runtime-extra,ou=people,dc=example,dc=test")
	if strings.Contains(extra, "uid=runtime-extra,ou=people,dc=example,dc=test") {
		t.Fatalf("reset left extra user:\n%s", extra)
	}
	staff := ldapSearch(t, inst, "cn=staff,ou=groups,dc=example,dc=test", "member")
	if !strings.Contains(staff, "uid=alice,ou=people,dc=example,dc=test") {
		t.Fatalf("staff after reset:\n%s", staff)
	}
	if strings.Contains(staff, "uid=runtime-extra") {
		t.Fatalf("staff still half-seeded after reset:\n%s", staff)
	}
	marker := ldapSearch(t, inst, "cn=labldap-baseline,dc=example,dc=test", "dn")
	if !strings.Contains(marker, "cn=labldap-baseline,dc=example,dc=test") {
		t.Fatalf("marker missing after reset:\n%s", marker)
	}
	peopleACI := ldapSearch(t, inst, "ou=people,dc=example,dc=test", "aci")
	if !strings.Contains(peopleACI, "labldap:runtime-people-write") {
		t.Fatalf("ACI missing after reset:\n%s", peopleACI)
	}
	rt := ldapSearch(t, inst, "uid=rt,ou=people,dc=example,dc=test", "dn")
	if !strings.Contains(rt, "uid=rt,ou=people,dc=example,dc=test") {
		t.Fatal("reset deleted runtime")
	}
}

func replaceGroupMembers(t *testing.T, inst *Instance, dn string, members ...string) {
	t.Helper()
	ldif := "dn: " + dn + `
changetype: modify
replace: member
`
	for _, m := range members {
		ldif += "member: " + m + "\n"
	}
	cmd := exec.Command("docker", "exec", "-i", inst.Name,
		"ldapmodify", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal())
	cmd.Stdin = strings.NewReader(ldif)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("replace members %s: %v\n%s", dn, err, out)
	}
}

func ldapDelete(t *testing.T, inst *Instance, dn string) {
	t.Helper()
	out, err := exec.Command("docker", "exec", inst.Name,
		"ldapdelete", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal(), dn).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such object") {
		t.Fatalf("ldapdelete %s: %v\n%s", dn, err, out)
	}
}

func deleteNamedACI(t *testing.T, inst *Instance, target, name string) {
	t.Helper()
	out, err := exec.Command("docker", "exec", inst.Name,
		"ldapsearch", "-x", "-LLL", "-o", "ldif-wrap=no", "-o", "tls_reqcert=never",
		"-H", "ldaps://127.0.0.1:3636",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal(),
		"-b", target, "-s", "base", "aci").CombinedOutput()
	if err != nil {
		t.Fatalf("search aci: %v\n%s", err, out)
	}
	var text string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "aci: ") && strings.Contains(line, name) {
			text = strings.TrimPrefix(line, "aci: ")
			break
		}
	}
	if text == "" {
		t.Fatalf("named ACI %s not found in %s:\n%s", name, target, out)
	}
	ldif := "dn: " + target + `
changetype: modify
delete: aci
aci: ` + text + `
`
	cmd := exec.Command("docker", "exec", "-i", inst.Name,
		"ldapmodify", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal())
	cmd.Stdin = strings.NewReader(ldif)
	if mout, merr := cmd.CombinedOutput(); merr != nil {
		t.Fatalf("delete aci %s: %v\n%s", name, merr, mout)
	}
}
