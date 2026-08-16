package ldapserver

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// tlsFixture wraps the repo's CA helper (tools/setuptls, T-113) instead of
// minting certificates ad hoc: the test invokes the same CLI the lab uses,
// pointed at a per-test temp dir. Keys stay on disk under t.TempDir and are
// removed with the test; nothing secret is embedded in the repo or logged.
type tlsFixture struct {
	dir string
}

// newTLSFixture runs `setuptls generate --host host` into a temp dir and
// returns the material paths. The directory certificate carries SANs for
// host, "localhost", and 127.0.0.1 (see tools/setuptls).
func newTLSFixture(t *testing.T, host string) *tlsFixture {
	t.Helper()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "run", "./tools/setuptls", "generate",
		"--dir", dir, "--host", host)
	cmd.Dir = moduleRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("setuptls generate: %v\n%s", err, out)
	}
	// The helper must print file paths only, never key material.
	if bytes.Contains(out, []byte("PRIVATE KEY")) {
		t.Fatalf("setuptls leaked key material to output:\n%s", out)
	}
	return &tlsFixture{dir: dir}
}

// moduleRoot locates the repository root so the setuptls CLI resolves
// regardless of the package directory the test binary runs in.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above test directory")
		}
		dir = parent
	}
}

// serverConfig builds the server-side tls.Config from the fixture. Tests
// deliberately omit MinVersion here for one case so the constructor floor
// is exercised; the config is cloned by New, so this stays caller-owned.
func (f *tlsFixture) serverConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(f.dir+"/directory.crt", f.dir+"/directory.key")
	if err != nil {
		t.Fatalf("load directory keypair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// clientConfig trusts the fixture CA and pins the expected server name.
func (f *tlsFixture) clientConfig(t *testing.T, serverName string) *tls.Config {
	t.Helper()
	caPEM, err := os.ReadFile(filepath.Join(f.dir, "ca.crt"))
	if err != nil {
		t.Fatalf("read ca.crt: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("ca.crt did not parse")
	}
	return &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}
}

// serveTLS starts a server from bindOptions with the caller's mutations and
// waits for every configured listener to bind. It returns the server plus
// the bound cleartext and LDAPS addresses ("" when disabled).
func serveTLS(t *testing.T, mutate func(*Options)) (*Server, string, string) {
	t.Helper()
	opts := bindOptions(t)
	if mutate != nil {
		mutate(&opts)
	}
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-serveErr; err != nil {
			t.Errorf("Serve: %v", err)
		}
		_ = s.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		ldapReady := s.opts.LDAPAddress == "" || s.LDAPAddr() != nil
		ldapsReady := s.opts.LDAPSAddress == "" || s.LDAPSAddr() != nil
		if ldapReady && ldapsReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("listeners did not bind in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
	var ldapAddr, ldapsAddr string
	if a := s.LDAPAddr(); a != nil {
		ldapAddr = a.String()
	}
	if a := s.LDAPSAddr(); a != nil {
		ldapsAddr = a.String()
	}
	return s, ldapAddr, ldapsAddr
}

// dialTLS opens a TLS client connection speaking the real BER codec.
func dialTLS(t *testing.T, addr string, cfg *tls.Config) *ldapTestClient {
	t.Helper()
	d := &net.Dialer{Timeout: 5 * time.Second}
	nc, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		t.Fatalf("tls dial: %v", err)
	}
	c := &ldapTestClient{t: t, conn: nc, codec: NewBERCodec(BERCodecOptions{})}
	t.Cleanup(func() { _ = c.conn.Close() })
	return c
}

// serverConnTLS reports whether the server has marked at least one
// connection as TLS. Poll-based because the accept loop registers the conn
// asynchronously.
func serverConnTLS(t *testing.T, s *Server) bool {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.connsMu.Lock()
		for c := range s.conns {
			if c.isTLS {
				s.connsMu.Unlock()
				return true
			}
		}
		s.connsMu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

func TestLDAPSSucceedsWithCorrectTrustAndName(t *testing.T) {
	t.Parallel()
	fix := newTLSFixture(t, "localhost")
	_, _, ldapsAddr := serveTLS(t, func(o *Options) {
		o.LDAPAddress = ""
		o.LDAPSAddress = "127.0.0.1:0"
		o.TLSConfig = fix.serverConfig(t)
	})
	if ldapsAddr == "" {
		t.Fatal("LDAPS listener did not bind")
	}
	cl := dialTLS(t, ldapsAddr, fix.clientConfig(t, "localhost"))
	state := cl.conn.(*tls.Conn).ConnectionState()
	if state.Version < tls.VersionTLS12 {
		t.Fatalf("negotiated TLS version %x, want >= 1.2", state.Version)
	}
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("LDAPS bind = %v", res)
	}
}

func TestLDAPSWrongCAFailsClosed(t *testing.T) {
	t.Parallel()
	serverFix := newTLSFixture(t, "localhost")
	_, _, ldapsAddr := serveTLS(t, func(o *Options) {
		o.LDAPAddress = ""
		o.LDAPSAddress = "127.0.0.1:0"
		o.TLSConfig = serverFix.serverConfig(t)
	})
	// A client anchored on a different CA must fail the handshake.
	otherFix := newTLSFixture(t, "localhost")
	d := &net.Dialer{Timeout: 5 * time.Second}
	nc, err := tls.DialWithDialer(d, "tcp", ldapsAddr, otherFix.clientConfig(t, "localhost"))
	if err == nil {
		_ = nc.Close()
		t.Fatal("handshake with wrong CA trust unexpectedly succeeded")
	}
	// Fail closed but not fail dead: a properly anchored client still binds.
	cl := dialTLS(t, ldapsAddr, serverFix.clientConfig(t, "localhost"))
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind after wrong-CA attempt = %v", res)
	}
}

func TestLDAPSWrongNameFailsClosed(t *testing.T) {
	t.Parallel()
	fix := newTLSFixture(t, "localhost")
	_, _, ldapsAddr := serveTLS(t, func(o *Options) {
		o.LDAPAddress = ""
		o.LDAPSAddress = "127.0.0.1:0"
		o.TLSConfig = fix.serverConfig(t)
	})
	d := &net.Dialer{Timeout: 5 * time.Second}
	nc, err := tls.DialWithDialer(d, "tcp", ldapsAddr, fix.clientConfig(t, "not-the-directory.example.test"))
	if err == nil {
		_ = nc.Close()
		t.Fatal("handshake with wrong server name unexpectedly succeeded")
	}
}

func TestTLSConfigFloorRaisedWithoutMutatingCaller(t *testing.T) {
	t.Parallel()
	fix := newTLSFixture(t, "localhost")
	caller := fix.serverConfig(t)
	// Deliberately weak caller config: the constructor must raise the floor.
	caller.MinVersion = tls.VersionTLS10
	_, _, ldapsAddr := serveTLS(t, func(o *Options) {
		o.LDAPAddress = ""
		o.LDAPSAddress = "127.0.0.1:0"
		o.TLSConfig = caller
	})
	if caller.MinVersion != tls.VersionTLS10 {
		t.Fatal("New mutated the caller's TLS config")
	}
	// A TLS 1.1-only client must be refused on the wire.
	weak := fix.clientConfig(t, "localhost")
	weak.MinVersion = tls.VersionTLS10
	weak.MaxVersion = tls.VersionTLS11
	d := &net.Dialer{Timeout: 5 * time.Second}
	nc, err := tls.DialWithDialer(d, "tcp", ldapsAddr, weak)
	if err == nil {
		_ = nc.Close()
		t.Fatal("TLS 1.1-only client unexpectedly negotiated")
	}
	// A modern client still connects.
	cl := dialTLS(t, ldapsAddr, fix.clientConfig(t, "localhost"))
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind after floor check = %v", res)
	}
}

// TestTLSNoSecretsLogged drives LDAPS and StartTLS paths with a capturing
// logger and asserts neither the bind password nor any private-key PEM
// material appears in the log stream.
func TestTLSNoSecretsLogged(t *testing.T) {
	t.Parallel()
	fix := newTLSFixture(t, "localhost")
	var buf bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(&lockedWriter{mu: &logMu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	const password = "tls-redaction-fixture-password"
	opts := bindOptions(t)
	opts.Logger = logger
	// Seed the secret-bearing user so both a failing and a succeeding path
	// handle the password.
	ctx := context.Background()
	if err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		e := NewEntry("uid=carol,ou=people,dc=example,dc=test",
			StringAttribute("objectClass", "top", "person"),
			StringAttribute("uid", "carol"),
			StringAttribute("sn", "Carol"),
			StringAttribute("userPassword", password))
		return tx.Add(ctx, e)
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, ldapAddr, ldapsAddr := serveTLS(t, func(o *Options) {
		*o = opts
		o.LDAPAddress = "127.0.0.1:0"
		o.LDAPSAddress = "127.0.0.1:0"
		o.TLSConfig = fix.serverConfig(t)
		o.AllowStartTLS = true
	})

	// LDAPS: wrong password then right password.
	cl := dialTLS(t, ldapsAddr, fix.clientConfig(t, "localhost"))
	bindResult(t, cl, "uid=carol,ou=people,dc=example,dc=test", password+"-wrong")
	if res := bindResult(t, cl, "uid=carol,ou=people,dc=example,dc=test", password); res.Code != ResultSuccess {
		t.Fatalf("LDAPS bind = %v", res)
	}
	_ = cl.conn.Close()

	// StartTLS on the cleartext listener, then bind.
	plain := dialTestClient(t, ldapAddr)
	id := plain.send(&ExtendedRequest{Name: OIDStartTLS})
	m := plain.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	resp, ok := m.Op.(*ExtendedResponse)
	if !ok || resp.Result.Code != ResultSuccess {
		t.Fatalf("StartTLS = %#v", m.Op)
	}
	startTLSClient(t, plain, fix.clientConfig(t, "localhost"))
	if res := bindResult(t, plain, "uid=carol,ou=people,dc=example,dc=test", password); res.Code != ResultSuccess {
		t.Fatalf("post-StartTLS bind = %v", res)
	}

	// A failed handshake (wrong CA) exercises the server error path.
	otherFix := newTLSFixture(t, "localhost")
	d := &net.Dialer{Timeout: 5 * time.Second}
	if nc, err := tls.DialWithDialer(d, "tcp", ldapsAddr, otherFix.clientConfig(t, "localhost")); err == nil {
		_ = nc.Close()
		t.Fatal("wrong-CA handshake unexpectedly succeeded")
	}

	logMu.Lock()
	out := buf.String()
	logMu.Unlock()
	if strings.Contains(out, password) {
		t.Fatalf("log contains bind password:\n%s", out)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Fatalf("log contains PEM key marker:\n%s", out)
	}
	// Spot-check a distinctive middle line of the server key PEM.
	keyPEM, err := os.ReadFile(filepath.Join(fix.dir, "directory.key"))
	if err != nil {
		t.Fatalf("read directory.key: %v", err)
	}
	lines := strings.Split(string(keyPEM), "\n")
	if len(lines) > 4 {
		probe := lines[2]
		if probe != "" && strings.Contains(out, probe) {
			t.Fatalf("log contains private-key material:\n%s", out)
		}
	}
}
