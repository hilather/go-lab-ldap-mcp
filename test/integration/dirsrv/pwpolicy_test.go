//go:build integration

package dirsrv

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestShippedApplyPwpolicyReadback(t *testing.T) {
	inst := Start(t)
	_, guest := stagePolicyApply(t, inst, policyYAML(12, 2, "24h", "1h", true, 3, "60s"))
	out, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	if !strings.Contains(out, `"phase": "pwpolicy"`) && !strings.Contains(out, `"phase":"pwpolicy"`) {
		t.Fatalf("missing pwpolicy phase:\n%s", out)
	}
	got := pwpolicyGet(t, inst, guest.PW)
	for _, want := range []string{
		`"passwordminlength":`, `"12"`,
		`"passwordinhistory":`, `"2"`,
		`"passwordhistory":`, `"on"`,
		`"passwordexp":`, `"on"`,
		`"passwordmaxage":`, `"86400"`,
		`"passwordwarning":`, `"3600"`,
		`"passwordlockout":`, `"on"`,
		`"passwordmaxfailure":`, `"3"`,
		`"passwordlockoutduration":`, `"60"`,
		`"passwordstoragescheme":`, `"PBKDF2-SHA256"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("read-back missing %s:\n%s", want, got)
		}
	}
}

func TestShippedApplyPwpolicyUnsupported(t *testing.T) {
	inst := Start(t)
	_, guest := stagePolicyApply(t, inst, policyYAML(1, 0, "0s", "0s", false, 0, "0s"))
	out, err := execApply(t, inst, guest, nil)
	if err == nil {
		t.Fatalf("expected unsupported minLength:\n%s", out)
	}
	if !strings.Contains(out, "phase.pwpolicy") || !strings.Contains(out, "unsupported_field") {
		t.Fatalf("want phase.pwpolicy unsupported_field:\n%s", out)
	}
}

func TestShippedPwpolicyEngineBehavior(t *testing.T) {
	inst := Start(t)
	_, guest := stagePolicyApply(t, inst, policyYAML(12, 2, "24h", "0s", true, 2, "60s"))
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	got := pwpolicyGet(t, inst, guest.PW)
	if !strings.Contains(got, `"passwordmaxage"`) || !strings.Contains(got, `"86400"`) {
		t.Fatalf("max-age not applied:\n%s", got)
	}
	if !strings.Contains(got, `"passwordminlength"`) || !strings.Contains(got, `"12"`) {
		t.Fatalf("min-length not applied:\n%s", got)
	}

	addProbeUser(t, inst, "LongEnoughPass1")
	allowSelfPassword(t, inst)
	// Short password must be rejected (min length).
	if out, err := userPasswd(t, inst, "uid=pwprobe,dc=example,dc=test", "LongEnoughPass1", "short"); err == nil {
		t.Fatalf("short password accepted:\n%s", out)
	}
	// History: rotate then reuse.
	if out, err := userPasswd(t, inst, "uid=pwprobe,dc=example,dc=test", "LongEnoughPass1", "LongEnoughPass2"); err != nil {
		t.Fatalf("first rotate: %v\n%s", err, out)
	}
	if out, err := userPasswd(t, inst, "uid=pwprobe,dc=example,dc=test", "LongEnoughPass2", "LongEnoughPass1"); err == nil {
		t.Fatalf("history allowed reuse:\n%s", out)
	}
	// Lockout: two failed binds then good password is refused.
	_ = userBind(t, inst, "uid=pwprobe,dc=example,dc=test", "wrong-password-aaa")
	_ = userBind(t, inst, "uid=pwprobe,dc=example,dc=test", "wrong-password-bbb")
	if err := userBind(t, inst, "uid=pwprobe,dc=example,dc=test", "LongEnoughPass2"); err == nil {
		t.Fatal("lockout did not reject a subsequent bind")
	}
}

func TestShippedValidateDoesNotMutatePwpolicy(t *testing.T) {
	inst := Start(t)
	_, guest := stagePolicyApply(t, inst, policyYAML(12, 0, "0s", "0s", false, 0, "0s"))
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("apply: %v\n%s", err, out)
	}
	before := pwpolicyGet(t, inst, guest.PW)
	if out, err := execValidate(t, inst, guest); err != nil {
		t.Fatalf("validate: %v\n%s", err, out)
	}
	after := pwpolicyGet(t, inst, guest.PW)
	if before != after {
		t.Fatalf("validate mutated policy\nbefore=%s\nafter=%s", before, after)
	}
}

func stagePolicyApply(t *testing.T, inst *Instance, yaml string) (string, applyGuest) {
	t.Helper()
	hostDir := t.TempDir()
	sec := filepath.Join(hostDir, "secrets")
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "runtime-ldap"), []byte("runtime-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(hostDir, "lab.yaml")
	if err := os.WriteFile(cfg, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	pw := filepath.Join(hostDir, "dm.pw")
	if err := os.WriteFile(pw, []byte(inst.Password().Reveal()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := shippedBootstrap(t)
	guestRoot := "/tmp/labldap-apply"
	if out, err := exec.Command("docker", "exec", inst.Name, "mkdir", "-p", guestRoot+"/secrets").CombinedOutput(); err != nil {
		t.Fatalf("mkdir: %v\n%s", err, out)
	}
	for _, c := range [][2]string{
		{bin, inst.Name + ":" + guestRoot + "/labldap-bootstrap"},
		{cfg, inst.Name + ":" + guestRoot + "/lab.yaml"},
		{pw, inst.Name + ":" + guestRoot + "/dm.pw"},
		{filepath.Join(sec, "runtime-ldap"), inst.Name + ":" + guestRoot + "/secrets/runtime-ldap"},
	} {
		if out, err := exec.Command("docker", "cp", c[0], c[1]).CombinedOutput(); err != nil {
			t.Fatalf("cp %s: %v\n%s", c[0], err, out)
		}
	}
	if out, err := exec.Command("docker", "exec", inst.Name, "chmod", "+x", guestRoot+"/labldap-bootstrap").CombinedOutput(); err != nil {
		t.Fatalf("chmod: %v\n%s", err, out)
	}
	return hostDir, applyGuest{
		Config: guestRoot + "/lab.yaml",
		PW:     guestRoot + "/dm.pw",
		CA:     "/etc/dirsrv/slapd-localhost/ca.crt",
		Bin:    guestRoot + "/labldap-bootstrap",
	}
}

func policyYAML(minLen, hist int, maxAge, warn string, lock bool, fails int, lockDur string) string {
	return fmt.Sprintf(`apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: pwp }
spec:
  directory: { suffix: "dc=example,dc=test" }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  passwordPolicy:
    minLength: %d
    historyCount: %d
    maxAge: %s
    warningAge: %s
    lockout: { enabled: %t, maxFailures: %d, lockoutDuration: %s }
    storageScheme: PBKDF2-SHA256
`, minLen, hist, maxAge, warn, lock, fails, lockDur)
}

func pwpolicyGet(t *testing.T, inst *Instance, pwfile string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", inst.Name,
		"dsconf", "-D", "cn=Directory Manager", "-y", pwfile, "-j",
		"localhost", "pwpolicy", "get").CombinedOutput()
	if err != nil {
		t.Fatalf("pwpolicy get: %v\n%s", err, out)
	}
	return string(out)
}

func addProbeUser(t *testing.T, inst *Instance, password string) {
	t.Helper()
	ldif := `dn: uid=pwprobe,dc=example,dc=test
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: probe
sn: probe
uid: pwprobe
userPassword: ` + password + `
`
	cmd := exec.Command("docker", "exec", "-i", inst.Name,
		"ldapadd", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal())
	cmd.Stdin = strings.NewReader(ldif)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapadd: %v\n%s", err, out)
	}
}

func allowSelfPassword(t *testing.T, inst *Instance) {
	t.Helper()
	ldif := `dn: dc=example,dc=test
changetype: modify
add: aci
aci: (targetattr="userPassword")(version 3.0; acl "self-pwd"; allow (write) userdn="ldap:///self";)
`
	cmd := exec.Command("docker", "exec", "-i", inst.Name,
		"ldapmodify", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal())
	cmd.Stdin = strings.NewReader(ldif)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("aci: %v\n%s", err, out)
	}
}

func userPasswd(t *testing.T, inst *Instance, dn, old, neu string) (string, error) {
	t.Helper()
	cmd := exec.Command("docker", "exec", inst.Name,
		"ldappasswd", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", dn, "-w", old, "-s", neu)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func userBind(t *testing.T, inst *Instance, dn, password string) error {
	t.Helper()
	cmd := exec.Command("docker", "exec", inst.Name,
		"ldapsearch", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", dn, "-w", password, "-s", "base", "-b", dn, "dn")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Logf("bind %s: %v\n%s", dn, err, out)
	}
	return err
}
