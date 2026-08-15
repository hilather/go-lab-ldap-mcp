package main

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/auth"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
)

func TestGeneratedManagementCertificate(t *testing.T) {
	cert, err := generatedManagementCertificate()
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("empty cert")
	}
}

func TestParseServeFlags(t *testing.T) {
	t.Setenv("LABLDAP_LDAP_URL", "")
	t.Setenv("LABLDAP_DIRECTORY_CA_FILE", "")
	t.Setenv("LABLDAP_DIRECTORY_HOST", "")
	f, err := parseServeFlags([]string{"--config", "x.yaml", "--ldap-url", "ldaps://127.0.0.1:3636", "--directory-ca-file", "/ca.pem", "--directory-host", "dir.example"})
	if err != nil {
		t.Fatal(err)
	}
	if f.configPath != "x.yaml" || f.ldapURL != "ldaps://127.0.0.1:3636" || f.caFile != "/ca.pem" || f.dirHost != "dir.example" {
		t.Fatalf("%+v", f)
	}
	if _, err := parseServeFlags(nil); err == nil {
		t.Fatal("expected required")
	}
	if _, err := parseServeFlags([]string{"--placeholder"}); err != nil {
		t.Fatal(err)
	}
	if _, err := parseServeFlags([]string{"--help"}); err != errServeHelp {
		t.Fatalf("help: %v", err)
	}
}

func TestLDAPClientConfigFromExample(t *testing.T) {
	path := filepath.Join("..", "..", "config", "examples", "example-lab.yaml")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	built, err := compileControl(context.Background(), path)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	_ = src
	cfg, err := ldapClientConfig(built, serveFlags{ldapURL: "ldaps://127.0.0.1:3636", caFile: "/tmp/ca.pem", dirHost: "localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Address != "127.0.0.1:3636" || cfg.Transport != directory.TransportLDAPS {
		t.Fatalf("%+v", cfg)
	}
	if cfg.BindDN == "" || cfg.CAFile != "/tmp/ca.pem" || cfg.ServerName != "localhost" {
		t.Fatalf("%+v", cfg)
	}
	if cfg.BindPassword.Reveal() == "" {
		t.Fatal("runtime password missing")
	}
}

func TestServeWiresCompiledRateLimits(t *testing.T) {
	path := filepath.Join("..", "..", "config", "examples", "example-lab.yaml")
	built, err := compileControl(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	opt, _, closer, err := serverOptionsFromCompiled(built, serveFlags{ldapURL: "ldaps://127.0.0.1:1", caFile: "/tmp/ca.pem"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if closer != nil {
		t.Cleanup(closer)
	}
	if opt.Limiter == nil {
		t.Fatal("HTTP limiter unset")
	}
	// Compiled bind-test budget is 10/min; the 11th identical key must deny.
	for i := 0; i < 10; i++ {
		if !opt.Limiter.Allow("bind:actor:admin") {
			t.Fatalf("allowed key denied at %d", i)
		}
	}
	if opt.Limiter.Allow("bind:actor:admin") {
		t.Fatal("compiled bind-test budget not enforced")
	}
}

func TestWarnInsecureLab(t *testing.T) {
	var buf strings.Builder
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	warnInsecureLab(log, false)
	if buf.Len() != 0 {
		t.Fatalf("unexpected warning: %s", buf.String())
	}
	warnInsecureLab(log, true)
	if !strings.Contains(buf.String(), "insecureLabMode") {
		t.Fatalf("missing warning: %s", buf.String())
	}
}

func TestLoopbackListenWiresHostAllowList(t *testing.T) {
	path := filepath.Join("..", "..", "config", "examples", "example-lab.yaml")
	built, err := compileControl(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	opt, _, closer, err := serverOptionsFromCompiled(built, serveFlags{ldapURL: "ldaps://127.0.0.1:1", caFile: "/tmp/ca.pem"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if closer != nil {
		t.Cleanup(closer)
	}
	if len(opt.AllowedHosts) == 0 {
		t.Fatal("example-lab listens on 127.0.0.1 and must set Host allow-list")
	}
}

func TestComposeBindAllWiresHostAllowList(t *testing.T) {
	hosts := publishedHosts("0.0.0.0:8443")
	if !auth.HostAllowed("127.0.0.1:8443", hosts) || auth.HostAllowed("evil.test", hosts) {
		t.Fatalf("compose 0.0.0.0 listen hosts = %v", hosts)
	}
}

// writeNativeScenario writes a valid scenario that selects engine: native,
// plus the lab-fixture secret files it references. It returns the config path.
func writeNativeScenario(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "secrets"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, val := range map[string]string{
		"runtime-ldap": "lab-fixture-runtime-password",
		"user-alice":   "lab-fixture-alice-password",
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
	return path
}

func assertNativeGateError(t *testing.T, stderr string) {
	t.Helper()
	for _, want := range []string{"spec.directory.engine", "engine_not_available", "M9", "engine: 389ds"} {
		if !strings.Contains(stderr, want) {
			t.Fatalf("stderr missing %q:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "lab-fixture") {
		t.Fatalf("leaked secret: %s", stderr)
	}
}

func TestServeFailsClosedOnNativeEngine(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	t.Setenv("LABLDAP_LDAP_URL", "")
	t.Setenv("LABLDAP_DIRECTORY_CA_FILE", "")
	t.Setenv("LABLDAP_DIRECTORY_HOST", "")
	path := writeNativeScenario(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"serve", "--config", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr=%s", code, stderr.String())
	}
	assertNativeGateError(t, stderr.String())
}

func TestMCPStdioFailsClosedOnNativeEngine(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	t.Setenv("LABLDAP_LDAP_URL", "")
	t.Setenv("LABLDAP_DIRECTORY_CA_FILE", "")
	t.Setenv("LABLDAP_DIRECTORY_HOST", "")
	t.Setenv("LABLDAP_MCP_TOKEN", "lab-fixture-admin-token")
	path := writeNativeScenario(t)
	var stdout, stderr bytes.Buffer
	code := run([]string{"mcp-stdio", "--config", path}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1; stderr=%s", code, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("protocol/logs on stdout: %q", stdout.String())
	}
	assertNativeGateError(t, stderr.String())
}
