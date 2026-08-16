package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelp(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	for _, arg := range []string{"help", "--help", "-h"} {
		stdout.Reset()
		stderr.Reset()
		if code := run([]string{arg}, &stdout, &stderr); code != 0 {
			t.Fatalf("%s exit %d stderr=%s", arg, code, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{"labldapd", "serve", "version", "ADR-0009", "engine: native"} {
			if !strings.Contains(out, want) {
				t.Fatalf("%s help missing %q:\n%s", arg, want, out)
			}
		}
		if strings.Contains(out, "not ready until milestone M9") {
			t.Fatalf("%s help still says native is unready:\n%s", arg, out)
		}
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("version exit %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "component=labldapd") {
		t.Fatalf("version output = %q", stdout.String())
	}
}

func TestServeUnreadableConfig(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"serve", "--config", "no/such/lab.yaml",
		"--directory-manager-password-file", "also-missing",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("serve exit %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "labldapd serve:") {
		t.Fatalf("serve message = %q", stderr.String())
	}
}

func TestServeHelp(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"serve", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("serve --help exit %d stderr=%s", code, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{
		"--config", "--data-dir", "--listen", "--ldaps-listen",
		"--tls-cert-file", "--tls-key-file",
		"--directory-manager-password-file", "--health-listen",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("serve help missing %q:\n%s", want, out)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"bogus"}, &stdout, &stderr); code != 2 {
		t.Fatalf("unknown command exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestParseServeFlags(t *testing.T) {
	t.Parallel()
	f, err := parseServeFlags([]string{
		"--config", "lab.yaml",
		"--data-dir=/var/lib/labldapd",
		"--listen", "127.0.0.1:3389",
		"--ldaps-listen=127.0.0.1:3636",
		"--tls-cert-file", "cert.pem",
		"--tls-key-file=key.pem",
		"--directory-manager-password-file", "/run/secrets/dm",
		"--health-listen=127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("parseServeFlags: %v", err)
	}
	want := serveFlags{
		configPath:     "lab.yaml",
		dataDir:        "/var/lib/labldapd",
		listen:         "127.0.0.1:3389",
		ldapsListen:    "127.0.0.1:3636",
		tlsCertFile:    "cert.pem",
		tlsKeyFile:     "key.pem",
		dmPasswordFile: "/run/secrets/dm",
		healthListen:   "127.0.0.1:8080",
	}
	if f != want {
		t.Fatalf("flags = %+v, want %+v", f, want)
	}
	if _, err := parseServeFlags([]string{"--config"}); err == nil {
		t.Fatal("missing value should error")
	}
	if _, err := parseServeFlags([]string{"--bogus"}); err == nil {
		t.Fatal("unknown flag should error")
	}
	if _, err := parseServeFlags([]string{"--help"}); err != errServeHelp {
		t.Fatalf("--help err = %v", err)
	}
}
