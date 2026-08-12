package main

import (
	"bytes"
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
	code := run([]string{"apply"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "apply"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
