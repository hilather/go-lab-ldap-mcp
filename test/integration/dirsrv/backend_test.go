//go:build integration

package dirsrv

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

)

var (
	shippedOnce sync.Once
	shippedBin  string
	shippedErr  error
)

func shippedBootstrap(t *testing.T) string {
	t.Helper()
	shippedOnce.Do(func() {
		dir, err := os.MkdirTemp("", "labldap-bootstrap-")
		if err != nil {
			shippedErr = err
			return
		}
		shippedBin = filepath.Join(dir, "labldap-bootstrap")
		cmd := exec.Command("go", "build", "-o", shippedBin, "./cmd/labldap-bootstrap")
		cmd.Dir = moduleRootOrFatal(t)
		cmd.Env = append(os.Environ(), "GOTOOLCHAIN=go1.26.5")
		out, err := cmd.CombinedOutput()
		if err != nil {
			shippedErr = err
			t.Logf("build: %s", out)
		}
	})
	if shippedErr != nil {
		t.Fatal(shippedErr)
	}
	return shippedBin
}

func moduleRootOrFatal(t *testing.T) string {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func TestShippedApplyBackendFreshAndMatch(t *testing.T) {
	inst := Start(t)
	hostDir, guest := stageApply(t, inst, "dc=example,dc=test")
	_ = hostDir

	out1, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("fresh apply: %v\n%s", err, out1)
	}
	assertBackendPhaseOK(t, out1)
	if got := listSuffixes(t, inst); !strings.Contains(got, "dc=example,dc=test (userroot)") {
		t.Fatalf("after fresh: %s", got)
	}

	out2, err := execApply(t, inst, guest, nil)
	if err != nil {
		t.Fatalf("match apply: %v\n%s", err, out2)
	}
	assertBackendPhaseOK(t, out2)
	got := listSuffixes(t, inst)
	if !strings.Contains(got, "dc=example,dc=test (userroot)") {
		t.Fatalf("after match: %s", got)
	}
	if strings.Count(got, "(userroot)") != 1 {
		t.Fatalf("backend recreated: %s", got)
	}
}

func TestShippedApplyBackendConflict(t *testing.T) {
	inst := Start(t)
	_, guest := stageApply(t, inst, "dc=example,dc=test")
	// Pre-existing name with a different suffix.
	createBackend(t, inst, "userroot", "dc=other,dc=test")
	before := listSuffixes(t, inst)

	out, err := execApply(t, inst, guest, nil)
	if err == nil {
		t.Fatalf("conflict apply succeeded:\n%s", out)
	}
	if !strings.Contains(out, "phase.backend") || !strings.Contains(out, "conflict") {
		t.Fatalf("want phase.backend conflict, got:\n%s", out)
	}
	after := listSuffixes(t, inst)
	if after != before || !strings.Contains(after, "dc=other,dc=test (userroot)") {
		t.Fatalf("backend was repurposed: before=%s after=%s", before, after)
	}
	if strings.Contains(after, "dc=example,dc=test") {
		t.Fatal("conflict created the planned suffix")
	}
}

type applyGuest struct {
	Config string
	PW     string
	CA     string
	Bin    string
}

func stageApply(t *testing.T, inst *Instance, suffix string) (hostDir string, g applyGuest) {
	t.Helper()
	hostDir = t.TempDir()
	sec := filepath.Join(hostDir, "secrets")
	if err := os.Mkdir(sec, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sec, "runtime-ldap"), []byte("runtime-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(hostDir, "lab.yaml")
	src := "apiVersion: labldap.dev/v1alpha1\nkind: LabScenario\nmetadata: { name: be }\nspec:\n" +
		"  directory: { suffix: \"" + suffix + "\" }\n" +
		"  transport: { ldaps: { enabled: true, port: 3636 } }\n" +
		"  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }\n"
	if err := os.WriteFile(cfg, []byte(src), 0o600); err != nil {
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
	copies := [][2]string{
		{bin, inst.Name + ":" + guestRoot + "/labldap-bootstrap"},
		{cfg, inst.Name + ":" + guestRoot + "/lab.yaml"},
		{pw, inst.Name + ":" + guestRoot + "/dm.pw"},
		{filepath.Join(sec, "runtime-ldap"), inst.Name + ":" + guestRoot + "/secrets/runtime-ldap"},
	}
	for _, c := range copies {
		if out, err := exec.Command("docker", "cp", c[0], c[1]).CombinedOutput(); err != nil {
			t.Fatalf("docker cp %s: %v\n%s", c[0], err, redactLogs(string(out), inst.password))
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

func execApply(t *testing.T, inst *Instance, g applyGuest, extra []string) (string, error) {
	t.Helper()
	args := []string{
		"exec", inst.Name, g.Bin, "apply",
		"--config", g.Config,
		"--directory-manager-password-file", g.PW,
		"--ldap-url", "ldaps://127.0.0.1:3636",
		"--directory-ca-file", g.CA,
		"--directory-host", inst.Hostname(t),
		"--dsconf-instance", "localhost",
	}
	args = append(args, extra...)
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func assertBackendPhaseOK(t *testing.T, out string) {
	t.Helper()
	// stdout JSON is last object; look for backend phase.
	if !strings.Contains(out, `"phase": "backend"`) && !strings.Contains(out, `"phase":"backend"`) {
		t.Fatalf("missing backend phase:\n%s", out)
	}
	var sum struct {
		OK     bool `json:"ok"`
		Phases []struct {
			Phase string `json:"phase"`
			OK    bool   `json:"ok"`
		} `json:"phases"`
	}
	// JSON summary is written to stdout; docker CombinedOutput may include stderr logs.
	start := strings.LastIndex(out, "{")
	if start < 0 {
		t.Fatalf("no JSON in:\n%s", out)
	}
	// find matching start of the summary: last occurrence of "command"
	idx := strings.LastIndex(out, `"command"`)
	if idx < 0 {
		t.Fatalf("no summary:\n%s", out)
	}
	brace := strings.LastIndex(out[:idx], "{")
	if err := json.Unmarshal([]byte(out[brace:]), &sum); err != nil {
		// try from last top-level pretty JSON
		if err2 := json.Unmarshal([]byte(out[strings.LastIndex(out, "{\n"):]), &sum); err2 != nil {
			t.Fatalf("json: %v / %v\n%s", err, err2, out)
		}
	}
	if !sum.OK {
		t.Fatalf("summary not ok:\n%s", out)
	}
	found := false
	for _, p := range sum.Phases {
		if p.Phase == "backend" {
			found = true
			if !p.OK {
				t.Fatalf("backend not ok:\n%s", out)
			}
		}
	}
	if !found {
		t.Fatalf("backend phase missing:\n%s", out)
	}
}

func listSuffixes(t *testing.T, inst *Instance) string {
	t.Helper()
	out, err := exec.Command("docker", "exec", inst.Name,
		"dsconf", "-D", "cn=Directory Manager", "-y", "/tmp/labldap-apply/dm.pw", "-j",
		"localhost", "backend", "suffix", "list").CombinedOutput()
	if err != nil {
		t.Fatalf("suffix list: %v\n%s", err, out)
	}
	return string(out)
}

func createBackend(t *testing.T, inst *Instance, name, suffix string) {
	t.Helper()
	// password file may not exist yet; write one
	pw := inst.Password().Reveal()
	tmp := t.TempDir()
	hostpw := filepath.Join(tmp, "dm.pw")
	if err := os.WriteFile(hostpw, []byte(pw+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("docker", "cp", hostpw, inst.Name+":/tmp/conflict-dm.pw").CombinedOutput(); err != nil {
		t.Fatalf("cp pw: %v\n%s", err, out)
	}
	out, err := exec.Command("docker", "exec", inst.Name,
		"dsconf", "-D", "cn=Directory Manager", "-y", "/tmp/conflict-dm.pw",
		"localhost", "backend", "create",
		"--suffix", suffix, "--be-name", name, "--create-suffix").CombinedOutput()
	if err != nil {
		t.Fatalf("precreate: %v\n%s", err, out)
	}
}
