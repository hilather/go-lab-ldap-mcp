package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
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
		for _, want := range []string{"labldap", "control plane", "does not implement the LDAP wire protocol", "Usage:"} {
			if !strings.Contains(out, want) {
				t.Errorf("run(%v) help missing %q\n%s", args, want, out)
			}
		}
		if strings.Contains(out, `"component"`) {
			t.Fatalf("structured logs leaked onto stdout: %s", out)
		}
		logs := stderr.String()
		for _, want := range []string{`"component":"labldap"`, `"version":`} {
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
	out := stdout.String()
	if !strings.Contains(out, "component=labldap") || !strings.Contains(out, "version=") {
		t.Fatalf("version stdout = %q", out)
	}
	if !strings.Contains(stderr.String(), `"component":"labldap"`) {
		t.Fatalf("version log = %q", stderr.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	var stdout, stderr bytes.Buffer
	code := run([]string{"frobnicate"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown command "frobnicate"`) {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), "Usage:") {
		t.Fatalf("unknown-command output missing usage: %q", stderr.String())
	}
}

func TestServeRequiresFlag(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	var stdout, stderr bytes.Buffer
	code := run([]string{"serve"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	if strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("serve treated as unknown: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "--placeholder") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestMountTransportsMCPDisabled(t *testing.T) {
	rest := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("rest"))
	})
	h := mountTransports(rest, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("/mcp disabled without bearer = %d %s", rec.Code, rec.Body.String())
	}
	live := httptest.NewRecorder()
	h.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/health", nil))
	if live.Code != http.StatusOK || live.Body.String() != "rest" {
		t.Fatalf("rest = %d %s", live.Code, live.Body.String())
	}
}
