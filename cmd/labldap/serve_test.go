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

// TestCompileControlAllowsNativeEngine covers the T-146 gate for both
// serving entry points (serve and mcp-stdio share compileControl):
// engine: native is wired now, so the scenario compiles and passes
// RequireAvailableEngine instead of failing closed. The runtime needs no
// engine branch: it is ds389.Runtime over ldapclient pointed at the
// configured LDAP URL in both modes.
func TestCompileControlAllowsNativeEngine(t *testing.T) {
	path := writeNativeScenario(t)
	built, err := compileControl(context.Background(), path)
	if err != nil {
		t.Fatalf("compileControl(native): %v", err)
	}
	if built.Engine.Engine != "native" {
		t.Fatalf("engine = %q", built.Engine.Engine)
	}

	// The serve composition root builds against a native scenario without a
	// live daemon (lazy pool; readiness stays false until a dial succeeds).
	opt, _, closer, err := serverOptionsFromCompiled(built, serveFlags{ldapURL: "ldaps://127.0.0.1:1", caFile: "/tmp/ca.pem"}, nil)
	if err != nil {
		t.Fatalf("serverOptionsFromCompiled(native): %v", err)
	}
	if closer != nil {
		t.Cleanup(closer)
	}
	if opt.Ready == nil || opt.Ready() {
		t.Fatal("readiness must stay false without a reachable engine")
	}
}

// TestControlPlaneNeverLoadsDirectoryManagerSecret asserts the privilege
// split (ADR-0008 decision 5) on the native path: the long-running control
// has no DM credential surface at all — no flag, no scenario field — and
// binds only the restricted runtime account.
func TestControlPlaneNeverLoadsDirectoryManagerSecret(t *testing.T) {
	t.Setenv("LABLDAP_LDAP_URL", "")
	t.Setenv("LABLDAP_DIRECTORY_CA_FILE", "")
	t.Setenv("LABLDAP_DIRECTORY_HOST", "")
	// Structural: neither serve nor mcp-stdio accepts a DM password flag.
	for _, args := range [][]string{
		{"serve", "--placeholder", "--directory-manager-password-file", "/tmp/dm"},
		{"mcp-stdio", "--config", "x.yaml", "--directory-manager-password-file", "/tmp/dm"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 {
			t.Fatalf("run(%v) exit %d, want 2 (unknown flag): %s", args, code, stderr.String())
		}
	}

	path := writeNativeScenario(t)
	built, err := compileControl(context.Background(), path)
	if err != nil {
		t.Fatalf("compileControl(native): %v", err)
	}
	cfg, err := ldapClientConfig(built, serveFlags{ldapURL: "ldaps://127.0.0.1:3636", caFile: "/tmp/ca.pem", dirHost: "directory"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BindDN == "cn=Directory Manager" {
		t.Fatal("control plane must never bind as Directory Manager")
	}
	if cfg.BindDN != built.Normalized.Runtime.DN {
		t.Fatalf("BindDN = %q, want runtime account %q", cfg.BindDN, built.Normalized.Runtime.DN)
	}
	if got := cfg.BindPassword.Reveal(); got != "lab-fixture-runtime-password" {
		t.Fatalf("BindPassword is not the runtime account secret")
	}
}

// TestMCPStdioNativeEnginePassesGate: mcp-stdio no longer rejects
// engine: native at the config layer; with no compiled token matching, it
// fails later at credential lookup (exit 2), never with
// engine_not_available, and stdout stays protocol-clean.
func TestMCPStdioNativeEnginePassesGate(t *testing.T) {
	t.Setenv("LABLDAP_LOG_FORMAT", "text")
	t.Setenv("LABLDAP_LDAP_URL", "")
	t.Setenv("LABLDAP_DIRECTORY_CA_FILE", "")
	t.Setenv("LABLDAP_DIRECTORY_HOST", "")
	t.Setenv("LABLDAP_MCP_TOKEN", "lab-fixture-admin-token")
	path := writeNativeScenario(t)
	var stdout, stderr bytes.Buffer
	// The CA file satisfies lazy pool validation (presence only; nothing
	// dials). The run must pass the engine gate and fail later at token
	// lookup — never with engine_not_available.
	code := run([]string{"mcp-stdio", "--config", path, "--directory-ca-file", "/tmp/ca.pem"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("exit %d, want 2 (invalid token against the compiled registry); stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "invalid credentials") {
		t.Fatalf("stderr = %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "engine_not_available") {
		t.Fatalf("native hit the availability gate: %s", stderr.String())
	}
	if strings.Contains(stderr.String(), "lab-fixture-") {
		t.Fatalf("leaked secret: %s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("protocol/logs on stdout: %q", stdout.String())
	}
}
