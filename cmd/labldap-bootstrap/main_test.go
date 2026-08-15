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

func assertNativeGate(t *testing.T, code int, stderr string) {
	t.Helper()
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr=%s", code, stderr)
	}
	for _, want := range []string{"spec.directory.engine", "engine_not_available", "M9", "engine: 389ds"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "lab-fixture") {
		t.Fatalf("leaked secret: %s", stderr)
	}
}

func TestPlanFailsClosedOnNativeEngine(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "json")
	_, path := writeNativeScenario(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"plan", "--config", path}, &stdout, &stderr)
	assertNativeGate(t, code, stderr.String())
	// plan performs no network I/O: the compiled plan is still printed and
	// the exit code stays non-zero for the unwired engine.
	if !strings.Contains(stdout.String(), `"engine": "native"`) {
		t.Fatalf("plan stdout missing compiled engine:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), "lab-fixture") {
		t.Fatalf("plan leaked secret: %s", stdout.String())
	}
}

func TestApplyValidateFailClosedOnNativeEngine(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "json")
	dir, path := writeNativeScenario(t)
	dmFile := filepath.Join(dir, "secrets", "dm")
	for _, cmd := range []string{"apply", "validate"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{cmd, "--config", path, "--directory-manager-password-file", dmFile}, &stdout, &stderr)
		assertNativeGate(t, code, stderr.String())
		// The gate fires before bootstrap.Run: no phase (wait/dial) ran.
		if !strings.Contains(stdout.String(), `"phases": []`) {
			t.Fatalf("%s ran phases despite the gate:\n%s", cmd, stdout.String())
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
	if !strings.Contains(stdout.String(), `"engine": "389ds"`) {
		t.Fatalf("plan stdout missing compiled engine:\n%s", stdout.String())
	}
}
