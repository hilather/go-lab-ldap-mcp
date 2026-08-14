package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateSANsAndPermissions(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := generate(dir, "directory", false, true, &out); err != nil {
		t.Fatal(err)
	}
	p := paths(dir)
	if strings.Contains(out.String(), "BEGIN") || strings.Contains(out.String(), "PRIVATE") {
		t.Fatalf("private key material printed: %s", out.String())
	}
	for _, f := range RuntimeTrustFiles(dir) {
		if f != p.CACert {
			t.Fatalf("runtime trust set %v", RuntimeTrustFiles(dir))
		}
	}
	for _, secret := range []string{p.CAKey, p.DirectoryKey, p.ManagementKey} {
		for _, rt := range RuntimeTrustFiles(dir) {
			if rt == secret {
				t.Fatalf("private key %s is in runtime trust set", secret)
			}
		}
		st, err := os.Stat(secret)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", secret, st.Mode().Perm())
		}
	}

	certPEM := readFile(t, p.DirectoryCert)
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		t.Fatal("directory.crt not PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("directory"); err != nil {
		t.Fatalf("SAN directory: %v", err)
	}
	if err := cert.VerifyHostname("localhost"); err != nil {
		t.Fatalf("SAN localhost: %v", err)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("SAN 127.0.0.1: %v", err)
	}
	if err := cert.VerifyHostname("not-the-server.example"); err == nil {
		t.Fatal("wrong SAN must fail")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(readFile(t, p.CACert))) {
		t.Fatal("ca.crt")
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "directory", Roots: pool}); err != nil {
		t.Fatalf("verify with lab CA: %v", err)
	}
	wrong := x509.NewCertPool()
	wrong.AddCert(selfCA(t))
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "directory", Roots: wrong}); err == nil {
		t.Fatal("wrong CA must fail")
	}

	out.Reset()
	if err := generate(dir, "directory", false, false, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "skipped") {
		t.Fatalf("expected skip: %s", out.String())
	}
}

func TestRuntimeTrustOmitsCAKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tls")
	var out bytes.Buffer
	if err := generate(dir, "directory", false, false, &out); err != nil {
		t.Fatal(err)
	}
	for _, f := range RuntimeTrustFiles(dir) {
		if strings.HasSuffix(f, "ca.key") || strings.HasSuffix(f, ".key") {
			t.Fatalf("runtime file %s looks like a private key", f)
		}
		raw := readFile(t, f)
		if strings.Contains(raw, "PRIVATE KEY") {
			t.Fatalf("runtime file %s contains a private key", f)
		}
	}
}

func TestRunHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if !strings.Contains(stdout.String(), "labldap-setup-tls") {
		t.Fatalf("%s", stdout.String())
	}
}

func selfCA(t *testing.T) *x509.Certificate {
	t.Helper()
	dir := t.TempDir()
	var out bytes.Buffer
	if err := generate(dir, "other", false, false, &out); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(readFile(t, paths(dir).CACert)))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPublishRefusesLabCAPath(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := generate(dir, "directory", false, false, &out); err != nil {
		t.Fatal(err)
	}
	if !overwritesLabCA(filepath.Join(dir, "ca.crt")) {
		t.Fatal("ca.crt + ca.key must be treated as lab CA")
	}
	if overwritesLabCA(filepath.Join(dir, "instance-ca.crt")) {
		t.Fatal("instance-ca.crt is not the lab CA")
	}
	err := publishInstanceCA(t.Context(), filepath.Join(dir, "ca.crt"), "x", "directory", nil, &out)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite lab CA") {
		t.Fatalf("err=%v", err)
	}
}

func TestComposePassthroughEnvIncludesOverlayVars(t *testing.T) {
	want := map[string]string{
		"LABLDAP_DIRECTORY_ENVFILE": "/tmp/labldap-directory.env",
		"LABLDAP_DM_PASSWORD_FILE":  "/tmp/labldap-dm.pw",
		"LABLDAP_SECRETS_DIR":       "/tmp/labldap-secrets",
		"LABLDAP_TLS_CA":            "/tmp/labldap-ca.crt",
		"LABLDAP_SCENARIO_FILE":     "/tmp/labldap-scenario.yaml",
	}
	for k, v := range want {
		t.Setenv(k, v)
	}
	got := map[string]string{}
	for _, kv := range composePassthroughEnv() {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		got[k] = v
	}
	for _, key := range composeOverlayEnv {
		if got[key] != want[key] {
			t.Fatalf("%s = %q, want %q", key, got[key], want[key])
		}
	}
}

func TestImportDefaultsToPersistentOverlay(t *testing.T) {
	got := defaultImportComposeFiles()
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "compose.persistent.yaml") {
		t.Fatalf("import default files = %v", got)
	}
	if strings.Contains(joined, "compose.ephemeral.yaml") {
		t.Fatal("import must not default to the ephemeral overlay")
	}
}

func TestVolumeOptsDetectTmpfs(t *testing.T) {
	if !volumeOptsAreTmpfs(map[string]string{"type": "tmpfs"}) {
		t.Fatal("tmpfs")
	}
	if volumeOptsAreTmpfs(map[string]string{"type": "ext4"}) || volumeOptsAreTmpfs(nil) {
		t.Fatal("non-tmpfs")
	}
}

func TestLeafLoadsAsTLSCert(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	if err := generate(dir, "directory", false, false, &out); err != nil {
		t.Fatal(err)
	}
	p := paths(dir)
	if _, err := tls.LoadX509KeyPair(p.DirectoryCert, p.DirectoryKey); err != nil {
		t.Fatal(err)
	}
}
