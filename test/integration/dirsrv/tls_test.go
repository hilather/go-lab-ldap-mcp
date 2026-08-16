//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

func TestLDAPSTrustAndName(t *testing.T) {
	// T-148 parametrized (Contract C2: wrong CA and wrong server name fail
	// closed on both engines). 389 imports the test CA via dsctl; the native
	// fixture serves the same material directly (Delta D2: no admin plane).
	var ldapsAddr string
	var mat *TLSMaterial
	if itEngine(t) == EngineNative {
		n := startNative(t, seedYAML("merge"))
		ldapsAddr = n.LDAPSAddr
		mat = n.mat
	} else {
		mat = generateTLS(t, "localhost")
		inst := Start(t)
		inst.ImportTLS(t, mat)
		ldapsAddr = inst.LDAPSAddr
	}
	if len(mat.CACertPEM) == 0 || len(mat.WrongCAPEM) == 0 {
		t.Fatal("generateTLS returned empty PEMs")
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mat.CACertPEM) {
		t.Fatal("generated CA")
	}
	d := &net.Dialer{Timeout: 8 * time.Second}
	cfg := &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
	var conn *tls.Conn
	var err error
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = tls.DialWithDialer(d, "tcp", ldapsAddr, cfg)
		if err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("expected LDAPS success with generated CA and name localhost: %v", err)
	}
	peers := conn.ConnectionState().PeerCertificates
	if len(peers) == 0 {
		t.Fatal("no peer certificates")
	}
	if err := peers[0].VerifyHostname("localhost"); err != nil {
		t.Fatalf("peer SAN missing localhost: %v", err)
	}
	if peers[0].Issuer.CommonName != "labldap-test-ca" {
		t.Fatalf("peer issuer = %q, want generated test CA", peers[0].Issuer.CommonName)
	}
	_ = conn.Close()

	wrong := x509.NewCertPool()
	if !wrong.AppendCertsFromPEM(mat.WrongCAPEM) {
		t.Fatal("wrong ca")
	}
	_, err = tls.DialWithDialer(d, "tcp", ldapsAddr, &tls.Config{
		RootCAs:    wrong,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		t.Fatal("wrong CA must fail closed")
	}

	_, err = tls.DialWithDialer(d, "tcp", ldapsAddr, &tls.Config{
		RootCAs:    pool,
		ServerName: "not-the-server.example",
		MinVersion: tls.VersionTLS12,
	})
	if err == nil {
		t.Fatal("wrong name must fail closed")
	}
}
