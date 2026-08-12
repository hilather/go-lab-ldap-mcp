package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"testing"
)

func TestGeneratedSANCert(t *testing.T) {
	mat := generateTLS(t, "ldap.lab.test")
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(mat.CACertPEM) {
		t.Fatal("ca")
	}
	crtPath := filepath.Join(mat.Dir, "server.crt")
	cert, err := tls.LoadX509KeyPair(crtPath, filepath.Join(mat.Dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("empty cert")
	}
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.VerifyHostname("ldap.lab.test"); err != nil {
		t.Fatalf("SAN missing ldap.lab.test: %v", err)
	}
	if err := parsed.VerifyHostname("localhost"); err != nil {
		t.Fatalf("SAN missing localhost: %v", err)
	}
	opts := x509.VerifyOptions{DNSName: "ldap.lab.test", Roots: pool}
	if _, err := parsed.Verify(opts); err != nil {
		t.Fatalf("cert not trusted by generated CA: %v", err)
	}
}
