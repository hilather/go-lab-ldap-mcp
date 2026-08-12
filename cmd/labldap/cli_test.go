package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestConfigCLIExample(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "json")
	path := "../../config/examples/example-lab.yaml"
	for _, cmd := range []string{"validate", "normalize", "plan"} {
		var stdout, stderr bytes.Buffer
		code := run([]string{cmd, path}, &stdout, &stderr)
		if code != 0 {
			t.Fatalf("%s exit %d stderr=%s", cmd, code, stderr.String())
		}
		out := stdout.String()
		if strings.Contains(out, "lab-fixture-alice-password") || strings.Contains(out, "lab-fixture-admin-token") {
			t.Fatalf("%s leaked secret: %s", cmd, out)
		}
	}
	var a, b bytes.Buffer
	if run([]string{"plan", path}, &a, ioDiscard()) != 0 {
		t.Fatal(a.String())
	}
	if run([]string{"plan", path}, &b, ioDiscard()) != 0 {
		t.Fatal(b.String())
	}
	if a.String() != b.String() {
		t.Fatal("plan JSON not stable")
	}
}

func TestConfigCLIInvalid(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	var stdout, stderr bytes.Buffer
	code := run([]string{"validate", "../../test/fixtures/config/invalid/empty-group.yaml"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero")
	}
	if !strings.Contains(stderr.String(), "empty_group") {
		t.Fatalf("stderr = %s", stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{"validate", "../../test/fixtures/config/invalid/canary-unknown.yaml"}, &stdout, &stderr)
	if code == 0 {
		t.Fatal("expected non-zero")
	}
	if strings.Contains(stderr.String(), "super-secret-lab-token-value-32chars!!") {
		t.Fatalf("leaked canary: %s", stderr.String())
	}
}

type discard struct{}

func ioDiscard() *discard { return &discard{} }

func (*discard) Write(p []byte) (int, error) { return len(p), nil }
