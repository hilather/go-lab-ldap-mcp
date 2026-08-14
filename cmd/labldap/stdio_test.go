package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPStdioMissingCredentials(t *testing.T) {
	t.Setenv("LABLDAP_MCP_TOKEN", "")
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	var stdout, stderr bytes.Buffer
	code := run([]string{"mcp-stdio", "--config", "../../config/examples/example-lab.yaml"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d want 2, stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("protocol/logs on stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "missing credentials") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "lab-fixture") {
		t.Fatalf("leaked secret: %s", stderr.String())
	}
}

func TestMCPStdioRefusesCLIToken(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	var stdout, stderr bytes.Buffer
	code := run([]string{"mcp-stdio", "--config", "x.yaml", "--token", "lab-cli-token-value-32xxxxxxxx"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stderr.String(), "lab-cli-token-value-32xxxxxxxx") {
		t.Fatal("token echoed")
	}
}

func TestMCPStdioHelpOnStderr(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	var stdout, stderr bytes.Buffer
	code := run([]string{"mcp-stdio", "--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d %s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("help leaked to stdout: %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "LABLDAP_MCP_TOKEN") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestLoadStdioTokenFile(t *testing.T) {
	t.Setenv("LABLDAP_MCP_TOKEN", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("  lab-file-token-value-32xxxxxxxx\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := loadStdioToken(stdioFlags{tokenFile: path})
	if err != nil || got != "lab-file-token-value-32xxxxxxxx" {
		t.Fatalf("%q %v", got, err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadStdioToken(stdioFlags{tokenFile: empty}); err == nil {
		t.Fatal("empty token file")
	}
}
