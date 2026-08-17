package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelp(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "json")
	for _, args := range [][]string{nil, {"help"}, {"--help"}, {"-h"}} {
		var stdout, stderr bytes.Buffer
		code := run(args, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("run(%v) exit %d, stderr=%q", args, code, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{"labldap-bootstrap", "Directory Manager", "secret file", "Usage:"} {
			if !strings.Contains(out, want) {
				t.Errorf("run(%v) help missing %q\n%s", args, want, out)
			}
		}
		logs := stderr.String()
		for _, want := range []string{`"component":"labldap-bootstrap"`, `"version":`} {
			if !strings.Contains(logs, want) {
				t.Errorf("run(%v) log missing %s\n%s", args, want, logs)
			}
		}
	}
}

func TestVersion(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"version"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "component=labldap-bootstrap") {
		t.Fatalf("version stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), `"component":"labldap-bootstrap"`) {
		t.Fatalf("version log = %q", stderr.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"serve"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "serve"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestApplyRejectsPasswordFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"apply", "--config", "x.yaml", "--directory-manager-password", "nope"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "password-file") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestPlanRequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d stderr=%s", code, stderr.String())
	}
}

// writeNativeScenario writes a valid scenario that selects engine: native,
// plus the lab-fixture secret files it references. It returns the directory
// and the config path.
func writeNativeScenario(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, val := range map[string]string{
		"runtime-ldap": "lab-fixture-runtime-password",
		"user-alice":   "lab-fixture-alice-password",
		"dm":           "lab-fixture-dm-password",
	} {
		if err := os.WriteFile(filepath.Join(dir, "secrets", name), []byte(val+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "native-lab.yaml")
	src := `
apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: native-lab }
spec:
  directory:
    suffix: "dc=example,dc=test"
    engine: native
  transport:
    ldaps: { enabled: true, port: 3636 }
  runtimeAccount: { id: rt, passwordFile: secrets/runtime-ldap }
  users:
    - id: alice
      passwordFile: secrets/user-alice
`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, path
}

// assertNoGate checks the post-T-146 behavior: engine: native is wired, so
// neither stdout nor stderr may carry the engine_not_available gate error,
// and no fixture secret may leak.
func assertNoGate(t *testing.T, stdout, stderr string) {
	t.Helper()
	for _, s := range []string{stdout, stderr} {
		if strings.Contains(s, "engine_not_available") {
			t.Fatalf("native engine hit the availability gate:\n%s", s)
		}
		if strings.Contains(s, "lab-fixture") {
			t.Fatalf("leaked secret: %s", s)
		}
	}
}

func TestPlanSucceedsOnNativeEngine(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "json")
	_, path := writeNativeScenario(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--config", path}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d, want 0; stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"engine": "native"`) {
		t.Fatalf("plan stdout missing compiled engine:\n%s", stdout.String())
	}
	assertNoGate(t, stdout.String(), stderr.String())
}

// Apply/validate with engine: native now pass the availability gate and run
// the wired native path; with no labldapd listening they fail in the wait
// phase (a dial timeout), not at the engine gate.
func TestApplyValidateRunNativePath(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "json")
	dir, path := writeNativeScenario(t)
	dmFile := filepath.Join(dir, "secrets", "dm")
	for _, cmd := range []string{"apply", "validate"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{cmd, "--config", path, "--directory-manager-password-file", dmFile, "--deadline", "1s"}, &stdout, &stderr)
		if code != 1 {
			t.Fatalf("%s exit %d, want 1; stderr=%s", cmd, code, stderr.String())
		}
		assertNoGate(t, stdout.String(), stderr.String())
		// load and wait ran: the failure is the wait dial, not the gate.
		if !strings.Contains(stdout.String(), `"phase": "wait"`) {
			t.Fatalf("%s did not reach the wait phase:\n%s", cmd, stdout.String())
		}
		if !strings.Contains(stderr.String(), "phase.wait") {
			t.Fatalf("%s stderr missing wait failure:\n%s", cmd, stderr.String())
		}
	}
}

func TestPlanSucceedsOnDefaultEngine(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "json")
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--config", "../../config/examples/example-lab.yaml"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"engine": "native"`) {
		t.Fatalf("plan stdout missing compiled engine:\n%s", stdout.String())
	}
}
