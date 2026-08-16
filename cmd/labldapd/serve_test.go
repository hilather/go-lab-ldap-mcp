package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver"
	"github.com/hilather/go-lab-ldap-mcp/internal/ldapserver/store"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

// dmCanary is the Directory Manager password used across serve tests; the
// redaction assertions scan every captured log byte for it.
const dmCanary = "dm-canary-7f3b9c-never-logged"

// minimalScenario is plaintext-only so the daemon needs no TLS material;
// insecureLabMode keeps the config validator happy without LDAPS/StartTLS.
const minimalScenario = `apiVersion: labldap.dev/v1alpha1
kind: LabScenario
metadata: { name: t143 }
spec:
  directory: { engine: native, suffix: "dc=example,dc=test" }
  transport:
    insecureLabMode: true
    ldap: { enabled: true, port: 3389 }
    ldaps: { enabled: false, port: 3636 }
    startTLS: false
    allowCleartextBind: true
    allowAnonymousBind: false
  runtimeAccount: { id: rt, passwordFile: /nonexistent/runtime-ldap }
  passwordPolicy:
    minLength: 9
    historyCount: 3
    maxAge: 24h
    lockout: { enabled: true, maxFailures: 4, lockoutDuration: 15m }
    storageScheme: PBKDF2-SHA256
`

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String()
}

// testDaemonFixture returns flags for a plaintext daemon on ephemeral ports
// plus the log buffer. The canary password is the DM secret.
func testDaemonFixture(t *testing.T) (serveFlags, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	logs := &bytes.Buffer{}
	f := serveFlags{
		configPath:     writeFile(t, dir, "lab.yaml", minimalScenario),
		dataDir:        filepath.Join(dir, "data"),
		listen:         freeAddr(t),
		ldapsListen:    "",
		dmPasswordFile: writeFile(t, dir, "dm.secret", dmCanary+"\n"),
		healthListen:   freeAddr(t),
	}
	return f, logs
}

func testLogger(logs *bytes.Buffer) *slog.Logger {
	return observability.NewLogger(logs, observability.FormatFromEnv(), observability.CurrentBuild("labldapd"))
}

// stopDaemon mirrors block()'s shutdown path for tests that drove
// startDaemon directly.
func stopDaemon(t *testing.T, d *daemon) {
	t.Helper()
	d.stopHealth(context.Background())
	d.stopServe()
	<-d.serveDone
	if err := d.server.Close(); err != nil {
		t.Fatalf("server close: %v", err)
	}
}

func TestServeRequiresConfigAndDMFile(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer

	// No --config at all.
	if code := run([]string{"serve"}, &stdout, &stderr); code != 1 {
		t.Fatalf("serve without flags exit %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "--config is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	// Config present, DM password file flag missing: the acceptance case.
	// The protocol listener must never start; prove it by rebinding the
	// exact address afterwards.
	dir := t.TempDir()
	cfg := writeFile(t, dir, "lab.yaml", minimalScenario)
	ldapAddr := freeAddr(t)
	stderr.Reset()
	code := run([]string{
		"serve", "--config", cfg,
		"--data-dir", filepath.Join(dir, "data"),
		"--listen", ldapAddr, "--ldaps-listen=",
		"--health-listen=",
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("serve without DM file exit %d, want 1", code)
	}
	msg := stderr.String()
	if !strings.Contains(msg, "directoryManager.passwordFile") || !strings.Contains(msg, "required") {
		t.Fatalf("stderr = %q", msg)
	}
	ln, err := net.Listen("tcp", ldapAddr)
	if err != nil {
		t.Fatalf("LDAP address %s still bound after failed startup: %v", ldapAddr, err)
	}
	_ = ln.Close()

	// DM flag present but the file does not exist: still no listener.
	stderr.Reset()
	code = run([]string{
		"serve", "--config", cfg,
		"--data-dir", filepath.Join(dir, "data2"),
		"--listen", ldapAddr, "--ldaps-listen=",
		"--health-listen=",
		"--directory-manager-password-file", filepath.Join(dir, "absent.secret"),
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("serve with unreadable DM file exit %d, want 1", code)
	}
	ln, err = net.Listen("tcp", ldapAddr)
	if err != nil {
		t.Fatalf("LDAP address %s still bound after failed startup: %v", ldapAddr, err)
	}
	_ = ln.Close()
}

func TestServeRejectsNonNativeEngine(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	scenario := strings.Replace(minimalScenario, "engine: native", "engine: 389ds", 1)
	cfg := writeFile(t, dir, "lab.yaml", scenario)
	dm := writeFile(t, dir, "dm.secret", dmCanary)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"serve", "--config", cfg,
		"--data-dir", filepath.Join(dir, "data"),
		"--listen", freeAddr(t), "--ldaps-listen=", "--health-listen=",
		"--directory-manager-password-file", dm,
	}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "engine_not_native") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestDaemonLifecycleHealthAndRedaction(t *testing.T) {
	t.Parallel()
	f, logs := testDaemonFixture(t)
	log := testLogger(logs)

	d, err := startDaemon(context.Background(), f, log)
	if err != nil {
		t.Fatalf("startDaemon: %v", err)
	}
	if d.server.LDAPAddr() == nil {
		t.Fatal("LDAP listener not bound")
	}
	if d.server.LDAPSAddr() != nil {
		t.Fatal("LDAPS listener bound unexpectedly")
	}

	// Health answers 200 once serving.
	healthURL := "http://" + d.HealthAddr().String() + "/health"
	resp, err := http.Get(healthURL)
	if err != nil {
		t.Fatalf("health GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ok") {
		t.Fatalf("health = %d %q", resp.StatusCode, body)
	}

	// Graceful shutdown through block(): cancel the parent context and
	// expect a clean nil return.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.block(ctx, log) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("block returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("graceful shutdown timed out")
	}

	// Listeners are gone after shutdown.
	if conn, err := net.DialTimeout("tcp", f.listen, 500*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatal("LDAP listener still open after shutdown")
	}
	if _, err := http.Get(healthURL); err == nil {
		t.Fatal("health listener still open after shutdown")
	}

	// Redaction: the canary DM password must appear nowhere, and the
	// lifecycle must have logged structured lines.
	out := logs.String()
	if strings.Contains(out, dmCanary) {
		t.Fatalf("logs leaked the Directory Manager password:\n%s", out)
	}
	for _, want := range []string{"engine plan applied", "dc=example,dc=test", "listeners bound", "shutdown requested", "shutdown complete"} {
		if !strings.Contains(out, want) {
			t.Fatalf("logs missing %q:\n%s", want, out)
		}
	}
}

func TestDaemonTLSListener(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certFile, keyFile := writeSelfSignedCert(t, dir)
	f, logs := testDaemonFixture(t)
	f.tlsCertFile = certFile
	f.tlsKeyFile = keyFile
	f.ldapsListen = freeAddr(t)
	f.healthListen = ""

	d, err := startDaemon(context.Background(), f, testLogger(logs))
	if err != nil {
		t.Fatalf("startDaemon: %v", err)
	}
	defer func() { stopDaemon(t, d) }()
	if d.server.LDAPSAddr() == nil {
		t.Fatal("LDAPS listener not bound")
	}
	// The TLS listener must complete a handshake.
	conn, err := tls.Dial("tcp", d.server.LDAPSAddr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("LDAPS handshake: %v", err)
	}
	_ = conn.Close()
}

func TestServeTLSRequiredButMaterialMissing(t *testing.T) {
	t.Parallel()
	f, logs := testDaemonFixture(t)
	f.ldapsListen = freeAddr(t) // TLS-bearing listener without cert/key.
	f.healthListen = ""
	_, err := startDaemon(context.Background(), f, testLogger(logs))
	if err == nil {
		t.Fatal("expected TLS material error")
	}
	var ae *apperr.Error
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T), want apperr", err, err)
	}
	found := false
	for _, fld := range ae.Fields() {
		if fld.Path == "tls.certFile" && fld.Code == "required" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fields = %#v", ae.Fields())
	}
}

func TestServerOptionsMapping(t *testing.T) {
	t.Parallel()
	f, _ := testDaemonFixture(t)
	compiled, err := compileEnginePlan(context.Background(), f.configPath)
	if err != nil {
		t.Fatalf("compileEnginePlan: %v", err)
	}
	if compiled.Engine.Suffix != "dc=example,dc=test" {
		t.Fatalf("suffix = %q", compiled.Engine.Suffix)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "labldapd.bolt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	plugins, err := enginePlugins(compiled)
	if err != nil {
		t.Fatalf("enginePlugins: %v", err)
	}
	// memberof + referint objects; account-disable is enforced in the bind
	// path, not as a plugin value.
	if len(plugins) != 2 {
		t.Fatalf("plugins = %d, want 2 (memberof, referint)", len(plugins))
	}

	dm := dmIdentity([]byte(dmCanary))
	if !dm.VerifyPassword([]byte(dmCanary)) {
		t.Fatal("DM verifier rejected the correct password")
	}
	if dm.VerifyPassword([]byte("wrong")) {
		t.Fatal("DM verifier accepted a wrong password")
	}
	if dm.DN != directoryManagerDN {
		t.Fatalf("DM DN = %q", dm.DN)
	}

	opts, err := serverOptions(compiled, f, nil, dm, plugins, st, testLogger(&bytes.Buffer{}))
	if err != nil {
		t.Fatalf("serverOptions: %v", err)
	}
	if opts.Suffix != "dc=example,dc=test" {
		t.Errorf("Suffix = %q", opts.Suffix)
	}
	if opts.LDAPAddress != f.listen || opts.LDAPSAddress != "" {
		t.Errorf("addresses = %q/%q", opts.LDAPAddress, opts.LDAPSAddress)
	}
	if !opts.AllowCleartextBind || opts.AllowStartTLS || opts.AllowAnonymousBind {
		t.Errorf("transport flags = cleartext:%v starttls:%v anon:%v",
			opts.AllowCleartextBind, opts.AllowStartTLS, opts.AllowAnonymousBind)
	}
	pp := opts.PasswordPolicy
	if pp == nil {
		t.Fatal("PasswordPolicy nil")
	}
	if pp.MinLength != 9 || pp.HistoryCount != 3 || pp.MaxAge != 24*time.Hour {
		t.Errorf("policy = %+v", pp)
	}
	if pp.MaxFailures != 4 || pp.LockoutDuration != 15*time.Minute {
		t.Errorf("lockout = %d/%v", pp.MaxFailures, pp.LockoutDuration)
	}
	if pp.StorageScheme != "PBKDF2-SHA256" {
		t.Errorf("scheme = %q (raw pass-through; ldapserver canonicalizes)", pp.StorageScheme)
	}
	if len(opts.ACITexts) == 0 {
		t.Error("ACITexts empty; runtime ACIs must reach the server")
	}
	if opts.NestedGroups != compiled.Normalized.NestedGroups {
		t.Errorf("NestedGroups = %v, want %v", opts.NestedGroups, compiled.Normalized.NestedGroups)
	}
	if opts.Store == nil || opts.Schema == nil || opts.Codec == nil {
		t.Error("store/schema/codec not wired")
	}
	if opts.DirectoryManager.DN != directoryManagerDN {
		t.Error("DM identity not wired")
	}
}

func TestEngineStatePublish(t *testing.T) {
	t.Parallel()
	f, _ := testDaemonFixture(t)
	compiled, err := compileEnginePlan(context.Background(), f.configPath)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "labldapd.bolt"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()

	ctx := context.Background()
	if err := publishEngineState(ctx, st, engineStateEntry(compiled)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	// Republish takes the Replace path without error (idempotent restart).
	if err := publishEngineState(ctx, st, engineStateEntry(compiled)); err != nil {
		t.Fatalf("republish: %v", err)
	}

	dn, err := config.ParseDN(configEntryDN)
	if err != nil {
		t.Fatal(err)
	}
	var entry *ldapserver.Entry
	if err := st.View(ctx, func(tx ldapserver.ReadTx) error {
		e, err := tx.Entry(ctx, dn)
		if err != nil {
			return err
		}
		entry = e
		return nil
	}); err != nil {
		t.Fatalf("read cn=config: %v", err)
	}

	got := map[string][]string{}
	for _, a := range entry.Attributes {
		for _, v := range a.Values {
			got[a.Name] = append(got[a.Name], string(v))
		}
	}
	want := map[string][]string{
		attrEngine:             {engineName},
		attrEngineSuffix:       {"dc=example,dc=test"},
		attrPasswordScheme:     {"PBKDF2-SHA256"}, // canonical form
		attrPasswordMinLength:  {"9"},
		attrPasswordHistory:    {"3"},
		attrPasswordMaxAge:     {"86400"},
		attrLockoutEnabled:     {"on"},
		attrLockoutMaxFailures: {"4"},
		attrLockoutDuration:    {"900"},
	}
	for k, vs := range want {
		if len(got[k]) != 1 || got[k][0] != vs[0] {
			t.Errorf("%s = %v, want %v", k, got[k], vs)
		}
	}
	if len(got[attrPlugins]) == 0 {
		t.Error("plugin list empty")
	}
	joined := strings.Join(got[attrPlugins], ",")
	if !strings.Contains(joined, "memberof") || !strings.Contains(joined, "referint") || !strings.Contains(joined, "account-disable") {
		t.Errorf("plugins = %v", got[attrPlugins])
	}
}

func TestParseServeFlagsDefaults(t *testing.T) {
	t.Parallel()
	f, err := parseServeFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if f.dataDir != defaultDataDir || f.listen != defaultLDAPListen ||
		f.ldapsListen != defaultLDAPSListen || f.healthListen != defaultHealthListen {
		t.Fatalf("defaults = %+v", f)
	}
	// Explicit empty values disable listeners.
	f, err = parseServeFlags([]string{"--listen=", "--ldaps-listen=", "--health-listen="})
	if err != nil {
		t.Fatal(err)
	}
	if f.listen != "" || f.ldapsListen != "" || f.healthListen != "" {
		t.Fatalf("disabled listeners = %+v", f)
	}
}

// writeSelfSignedCert generates a throwaway ECDSA certificate for the
// daemon's TLS listener tests.
func writeSelfSignedCert(t *testing.T, dir string) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "labldapd-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}
