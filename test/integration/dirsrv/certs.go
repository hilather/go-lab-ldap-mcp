package dirsrv

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TLSMaterial is a test-only CA plus a server cert. Private keys stay on disk
// and must not be logged.
type TLSMaterial struct {
	Dir        string
	CACertPEM  []byte
	ServerName string
	WrongCAPEM []byte
}

func generateTLS(t testing.TB, serverName string) *TLSMaterial {
	t.Helper()
	dir := t.TempDir()
	caKey := mustRSA(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          bigInt(t),
		Subject:               pkix.Name{CommonName: "labldap-test-ca", Organization: []string{"LabLDAP test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	srvKey := mustRSA(t)
	srvTmpl := &x509.Certificate{
		SerialNumber: bigInt(t),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{serverName, "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER})
	keyDER := x509.MarshalPKCS1PrivateKey(srvKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(filepath.Join(dir, "ca"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(dir, "ca", "ca.crt"), caPEM, 0o644)
	mustWrite(t, filepath.Join(dir, "server.crt"), srvPEM, 0o644)
	mustWrite(t, filepath.Join(dir, "server.key"), keyPEM, 0o600)
	mustWrite(t, filepath.Join(dir, "pwdfile.txt"), []byte("labldap-nss-pin\n"), 0o600)

	wrongKey := mustRSA(t)
	wrongTmpl := *caTmpl
	wrongTmpl.Subject.CommonName = "labldap-wrong-ca"
	wrongTmpl.SerialNumber = bigInt(t)
	wrongDER, err := x509.CreateCertificate(rand.Reader, &wrongTmpl, &wrongTmpl, &wrongKey.PublicKey, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongDER})

	return &TLSMaterial{
		Dir:        dir,
		CACertPEM:  caPEM,
		ServerName: serverName,
		WrongCAPEM: wrongPEM,
	}
}

func mustRSA(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func bigInt(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustWrite(t testing.TB, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
}
