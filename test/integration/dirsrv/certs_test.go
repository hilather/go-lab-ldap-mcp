package dirsrv

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
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

func TestTLSMaterialAuthorityKeyIdentifier(t *testing.T) {
	mat := generateTLS(t, "localhost")
	caBlock, _ := pem.Decode(mat.CACertPEM)
	if caBlock == nil {
		t.Fatal("CA certificate is not PEM")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	serverPEM, err := os.ReadFile(filepath.Join(mat.Dir, "server.crt"))
	if err != nil {
		t.Fatal(err)
	}
	leafBlock, _ := pem.Decode(serverPEM)
	if leafBlock == nil {
		t.Fatal("server certificate is not PEM")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.SubjectKeyId) == 0 || !bytes.Equal(leaf.AuthorityKeyId, ca.SubjectKeyId) {
		t.Fatal("server certificate must identify its issuing CA for strict TLS verification")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
}
