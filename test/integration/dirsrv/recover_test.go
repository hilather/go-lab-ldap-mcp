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

	d := inst.Dial(t)
	addExtraPerson(t, d, "uid=runtime-extra,ou=people,dc=example,dc=test")
	replaceGroupMembers(t, d, "cn=staff,ou=groups,dc=example,dc=test", "uid=runtime-extra,ou=people,dc=example,dc=test")
	ldapDelete(t, d, "uid=alice,ou=people,dc=example,dc=test")
	ldapDelete(t, d, "cn=labldap-baseline,dc=example,dc=test")
	deleteNamedACI(t, d, "ou=people,dc=example,dc=test", "labldap:runtime-people-write")

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
	if err := userBind(t, d, "uid=alice,ou=people,dc=example,dc=test", seedCanary); err != nil {
		t.Fatalf("alice after reset: %v", err)
	}
	extra := ldapSearchAllowMissing(t, d, "uid=runtime-extra,ou=people,dc=example,dc=test")
	if strings.Contains(extra, "uid=runtime-extra,ou=people,dc=example,dc=test") {
		t.Fatalf("reset left extra user:\n%s", extra)
	}
	staff := ldapSearch(t, d, "cn=staff,ou=groups,dc=example,dc=test", "member")
	if !strings.Contains(staff, "uid=alice,ou=people,dc=example,dc=test") {
		t.Fatalf("staff after reset:\n%s", staff)
	}
	if strings.Contains(staff, "uid=runtime-extra") {
		t.Fatalf("staff still half-seeded after reset:\n%s", staff)
	}
	marker := ldapSearch(t, d, "cn=labldap-baseline,dc=example,dc=test", "dn")
	if !strings.Contains(marker, "cn=labldap-baseline,dc=example,dc=test") {
		t.Fatalf("marker missing after reset:\n%s", marker)
	}
	peopleACI := ldapSearch(t, d, "ou=people,dc=example,dc=test", "aci")
	if !strings.Contains(peopleACI, "labldap:runtime-people-write") {
		t.Fatalf("ACI missing after reset:\n%s", peopleACI)
	}
	rt := ldapSearch(t, d, "uid=rt,ou=people,dc=example,dc=test", "dn")
	if !strings.Contains(rt, "uid=rt,ou=people,dc=example,dc=test") {
		t.Fatal("reset deleted runtime")
	}
}
