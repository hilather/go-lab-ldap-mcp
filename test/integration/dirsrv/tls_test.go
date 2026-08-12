//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLDAPSTrustAndName(t *testing.T) {
	mat := generateTLS(t, "localhost")
	if len(mat.CACertPEM) == 0 || len(mat.WrongCAPEM) == 0 {
		t.Fatal("generateTLS returned empty PEMs")
	}

	inst := Start(t)
	caPEM := extractInstanceCA(t, inst)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("instance CA")
	}
	host := instanceHostname(t, inst)
	d := &net.Dialer{Timeout: 8 * time.Second}
	cfg := &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
	var conn *tls.Conn
	var err error
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = tls.DialWithDialer(d, "tcp", inst.LDAPSAddr, cfg)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("expected LDAPS success with instance CA and name %q: %v", host, err)
	}
	if conn.ConnectionState().PeerCertificates == nil {
		t.Fatal("no peer certificates")
	}
	_ = conn.Close()

	wrong := x509.NewCertPool()
	if !wrong.AppendCertsFromPEM(mat.WrongCAPEM) {
		t.Fatal("wrong ca")
	}
	_, err = tls.DialWithDialer(d, "tcp", inst.LDAPSAddr, &tls.Config{
		RootCAs:    wrong,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		t.Fatal("wrong CA must fail closed")
	}

	_, err = tls.DialWithDialer(d, "tcp", inst.LDAPSAddr, &tls.Config{
		RootCAs:    pool,
		ServerName: "not-the-server.example",
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		t.Fatal("wrong name must fail closed")
	}
}

func extractInstanceCA(t *testing.T, inst *Instance) []byte {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "ca.crt")
	out, err := exec.Command("docker", "cp", inst.Name+":/etc/dirsrv/slapd-localhost/ca.crt", dest).CombinedOutput()
	if err != nil {
		t.Fatalf("docker cp ca.crt: %v\n%s", err, redactLogs(string(out), inst.password))
	}
	b, err := os.ReadFile(dest)
	if err != nil || len(b) == 0 {
		t.Fatalf("empty instance CA: %v", err)
	}
	return b
}

func instanceHostname(t *testing.T, inst *Instance) string {
	t.Helper()
	out, err := exec.Command("docker", "inspect", "-f", "{{.Config.Hostname}}", inst.Name).Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}
