//go:build integration

package dirsrv

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/bootstrap"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/config/v1alpha1"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory/ds389"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

const seedCanary = "seed-canary-alice-12"

func TestShippedApplySeedBindAndMembership(t *testing.T) {
	inst := Start(t)
	hostDir, guest := stageSeedApply(t, inst, seedYAML("merge"), seedCanary)
	out1, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, redactLogs(out1, seedCanary, inst.password))
	}
	assertSeedPhase(t, out1)
	assertRemainingAfterSeed(t, out1)
	assertNoCanary(t, inst, out1, seedCanary)

	alice := ldapSearch(t, inst, "uid=alice,ou=people,dc=example,dc=test", "dn", "uid", "cn", "sn", "objectClass", "memberOf")
	if !strings.Contains(alice, "uid=alice,ou=people,dc=example,dc=test") {
		t.Fatalf("missing alice:\n%s", alice)
	}
	if !strings.Contains(alice, "sn: Seed") {
		t.Fatalf("sn override missing:\n%s", alice)
	}
	if strings.Contains(alice, "sn: runtime") {
		t.Fatalf("runtime sn leaked onto seed user:\n%s", alice)
	}
	if err := userBind(t, inst, "uid=alice,ou=people,dc=example,dc=test", seedCanary); err != nil {
		t.Fatalf("alice bind: %v", err)
	}

	staff := ldapSearch(t, inst, "cn=staff,ou=groups,dc=example,dc=test", "dn", "cn", "member", "objectClass")
	if !strings.Contains(staff, "cn=staff,ou=groups,dc=example,dc=test") {
		t.Fatalf("missing staff:\n%s", staff)
	}
	if !strings.Contains(staff, "member: uid=alice,ou=people,dc=example,dc=test") {
		t.Fatalf("staff members:\n%s", staff)
	}

	out2, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("re-apply: %v\n%s", err, redactLogs(out2, seedCanary, inst.password))
	}
	assertNoCanary(t, inst, out2, seedCanary)
	if strings.Count(ldapSearchChildren(t, inst, "ou=people,dc=example,dc=test"), "uid=alice,") != 1 {
		t.Fatal("duplicate alice after re-apply")
	}
	if err := userBind(t, inst, "uid=alice,ou=people,dc=example,dc=test", seedCanary); err != nil {
		t.Fatalf("alice bind after re-apply: %v", err)
	}

	addExtraPerson(t, inst, "uid=extra,ou=people,dc=example,dc=test")
	out3, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("merge re-apply: %v\n%s", err, redactLogs(out3, seedCanary, inst.password))
	}
	if !strings.Contains(ldapSearch(t, inst, "uid=extra,ou=people,dc=example,dc=test", "dn"), "uid=extra,ou=people,dc=example,dc=test") {
		t.Fatal("merge removed extra user")
	}

	before := ldapSearch(t, inst, "uid=alice,ou=people,dc=example,dc=test", "modifyTimestamp", "sn")
	vout, err := execValidate(t, inst, guest)
	if err != nil {
		t.Fatalf("validate: %v\n%s", err, redactLogs(vout, seedCanary, inst.password))
	}
	after := ldapSearch(t, inst, "uid=alice,ou=people,dc=example,dc=test", "modifyTimestamp", "sn")
	if before != after {
		t.Fatalf("validate mutated alice\nbefore=%s\nafter=%s", before, after)
	}
	if strings.Contains(ldapSearch(t, inst, "uid=extra,ou=people,dc=example,dc=test", "dn"), "uid=extra") == false {
		t.Fatal("validate removed extra")
	}

	resetYAML := seedYAML("reset")
	if err := os.WriteFile(filepath.Join(hostDir, "lab.yaml"), []byte(resetYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "cp", filepath.Join(hostDir, "lab.yaml"), inst.Name+":/tmp/labldap-apply/lab.yaml").CombinedOutput(); err != nil {
		t.Fatalf("cp reset yaml: %v\n%s", err, out)
	}
	out4, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("reset apply: %v\n%s", err, redactLogs(out4, seedCanary, inst.password))
	}
	extra := ldapSearchAllowMissing(t, inst, "uid=extra,ou=people,dc=example,dc=test")
	if strings.Contains(extra, "uid=extra,ou=people,dc=example,dc=test") {
		t.Fatalf("reset left extra user:\n%s", extra)
	}
	if err := userBind(t, inst, "uid=alice,ou=people,dc=example,dc=test", seedCanary); err != nil {
		t.Fatalf("alice bind after reset: %v", err)
	}
	rt := ldapSearch(t, inst, "uid=rt,ou=people,dc=example,dc=test", "dn")
	if !strings.Contains(rt, "uid=rt,ou=people,dc=example,dc=test") {
		t.Fatalf("reset deleted runtime:\n%s", rt)
	}
	assertNoCanary(t, inst, out4, seedCanary)
}

func TestShippedSeedPasswordFailureCompensates(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("tree apply: %v\n%s", err, out)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	inst.WriteCA(t, ca)
	pw := config.ResolvedSecret{Value: observability.Secret(seedCanary)}
	req := bootstrap.SeedRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:     "dc=example,dc=test",
			PeopleDN:   "ou=people,dc=example,dc=test",
			GroupsDN:   "ou=groups,dc=example,dc=test",
			RuntimeDN:  "uid=rt,ou=people,dc=example,dc=test",
			DMPassword: inst.Password(),
			LDAPURL:    "ldaps://" + inst.LDAPSAddr,
			CAFile:     ca,
			Host:       inst.Hostname(t),
			Write:      true,
		},
		StartupMode: v1alpha1.StartupMerge,
		Users: []config.NormalizedUser{{
			ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test",
			Enabled: true, Password: &pw, ObjectClasses: config.RequiredUserObjectClasses(),
		}},
	}
	eng := ds389.Engine{
		SeedPasswordReplace: func(dn, password string) error {
			if password == seedCanary {
				return errors.New("injected password-set failure")
			}
			return errors.New("unexpected password replace")
		},
	}
	_, err := eng.ReconcileSeed(t.Context(), req)
	if err == nil {
		t.Fatal("expected password_set")
	}
	apperr.Assert(t, err).Code(apperr.CodeBootstrap).FieldPath("phase.seed")
	if !seedField(err, "password_set") {
		t.Fatalf("want password_set: %v", err)
	}
	if strings.Contains(err.Error(), seedCanary) {
		t.Fatal("error leaked password")
	}
	got := ldapSearchAllowMissing(t, inst, "uid=alice,ou=people,dc=example,dc=test")
	if strings.Contains(got, "uid=alice,ou=people,dc=example,dc=test") {
		t.Fatalf("incomplete user left after compensation:\n%s", got)
	}
	if err := userBind(t, inst, "uid=alice,ou=people,dc=example,dc=test", seedCanary); err == nil {
		t.Fatal("incomplete user bound after password_set")
	}
}

func TestReconcileSeedPasswordSetOnEngine(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	if out, err := execApply(t, inst, guest, nil); err != nil {
		t.Fatalf("tree apply: %v\n%s", err, out)
	}
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	inst.WriteCA(t, ca)
	pw := config.ResolvedSecret{Value: observability.Secret(seedCanary)}
	req := bootstrap.SeedRequest{
		TreeRequest: bootstrap.TreeRequest{
			Suffix:     "dc=example,dc=test",
			PeopleDN:   "ou=people,dc=example,dc=test",
			GroupsDN:   "ou=groups,dc=example,dc=test",
			RuntimeDN:  "uid=rt,ou=people,dc=example,dc=test",
			DMPassword: inst.Password(),
			LDAPURL:    "ldaps://" + inst.LDAPSAddr,
			CAFile:     ca,
			Host:       inst.Hostname(t),
			Write:      true,
		},
		StartupMode: v1alpha1.StartupMerge,
		Users: []config.NormalizedUser{{
			ID: "alice", UID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test",
			Enabled: true, Password: &pw, ObjectClasses: config.RequiredUserObjectClasses(),
		}},
		Groups: []config.NormalizedGroup{{
			ID: "staff", DN: "cn=staff,ou=groups,dc=example,dc=test",
			Members: []config.MemberRef{{Kind: "user", ID: "alice", DN: "uid=alice,ou=people,dc=example,dc=test"}},
		}},
	}
	res, err := ds389.Engine{}.ReconcileSeed(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Created) == 0 {
		t.Fatalf("expected created: %+v", res)
	}
	if err := userBind(t, inst, "uid=alice,ou=people,dc=example,dc=test", seedCanary); err != nil {
		t.Fatalf("engine seed bind: %v", err)
	}
	res2, err := ds389.Engine{}.ReconcileSeed(t.Context(), req)
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Created) != 0 || len(res2.Matched) < 2 {
		t.Fatalf("idempotent res=%+v", res2)
	}
}

func seedYAML(mode string) string {
	return `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: seed }
spec:
  directory: { suffix: "dc=example,dc=test" }
  lifecycle: { startupMode: ` + mode + ` }
  transport: { ldaps: { enabled: true, port: 3636 } }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: alice
      uid: alice
      passwordFile: secrets/user-alice
      enabled: true
      attributes: { sn: Seed }
  groups:
    - id: staff
      members:
        - user: alice
  passwordPolicy:
    minLength: 12
    historyCount: 0
    maxAge: 0s
    warningAge: 0s
    lockout: { enabled: false, maxFailures: 0, lockoutDuration: 0s }
    storageScheme: PBKDF2-SHA256
`
}

func stageSeedApply(t *testing.T, inst *Instance, yaml, alicePW string) (string, applyGuest) {
	t.Helper()
	hostDir := t.TempDir()
	sec := filepath.Join(hostDir, "secrets")
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "runtime-ldap"), []byte("runtime-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "user-alice"), []byte(alicePW+"\n"), 0o600); err != nil {
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
		{filepath.Join(sec, "user-alice"), inst.Name + ":" + guestRoot + "/secrets/user-alice"},
	} {
		if out, err := exec.Command("docker", "cp", c[0], c[1]).CombinedOutput(); err != nil {
			t.Fatalf("cp %s: %v\n%s", c[0], err, redactLogs(string(out), inst.password, alicePW))
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

func addExtraPerson(t *testing.T, inst *Instance, dn string) {
	t.Helper()
	ldif := "dn: " + dn + `
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
cn: extra
sn: extra
uid: extra
`
	cmd := exec.Command("docker", "exec", "-i", inst.Name,
		"ldapadd", "-x", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal())
	cmd.Stdin = strings.NewReader(ldif)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ldapadd extra: %v\n%s", err, out)
	}
}

func ldapSearchAllowMissing(t *testing.T, inst *Instance, dn string) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", inst.Name,
		"ldapsearch", "-x", "-LLL", "-H", "ldaps://127.0.0.1:3636", "-o", "tls_reqcert=never",
		"-D", "cn=Directory Manager", "-w", inst.Password().Reveal(),
		"-b", dn, "-s", "base", "dn").CombinedOutput()
	if err != nil {
		return string(out)
	}
	return string(out)
}

func assertSeedPhase(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, `"phase": "seed"`) && !strings.Contains(out, `"phase":"seed"`) {
		t.Fatalf("missing seed phase:\n%s", out)
	}
}

func assertRemainingAfterSeed(t *testing.T, out string) {
	t.Helper()
	var sum struct {
		Remaining []string `json:"remaining"`
	}
	if err := decodeSummary(out, &sum); err != nil {
		t.Fatalf("summary: %v\n%s", err, out)
	}
	want := []string{"verify_runtime", "verify_app", "drift", "marker"}
	if strings.Join(sum.Remaining, ",") != strings.Join(want, ",") {
		t.Fatalf("remaining = %v, want %v", sum.Remaining, want)
	}
}

func seedField(err error, code string) bool {
	var e *apperr.Error
	if !errors.As(err, &e) {
		return false
	}
	for _, f := range e.Fields() {
		if f.Path == "phase.seed" && f.Code == code {
			return true
		}
	}
	return false
}

func decodeSummary(out string, dest any) error {
	idx := strings.LastIndex(out, `"command"`)
	if idx < 0 {
		return errors.New("no summary")
	}
	brace := strings.LastIndex(out[:idx], "{")
	if brace < 0 {
		return errors.New("no JSON object")
	}
	return json.Unmarshal([]byte(out[brace:]), dest)
}

func assertNoCanary(t *testing.T, inst *Instance, out, canary string) {
	t.Helper()
	if canary != "" && strings.Contains(out, canary) {
		t.Fatal("canary password leaked in apply output")
	}
	logs, _ := exec.Command("docker", "logs", inst.Name).CombinedOutput()
	if canary != "" && strings.Contains(string(logs), canary) {
		t.Fatal("canary password leaked in directory logs")
	}
}
