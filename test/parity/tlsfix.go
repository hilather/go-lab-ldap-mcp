package parity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// tlsFixture carries a self-signed CA, a server certificate for
// "localhost", and ready-made client/server tls.Config values. Both
// engines present a certificate from the same CA so transport parity
// checks (C2) are symmetric; wrongCA holds an unrelated CA for the
// negative trust probes.
type tlsFixture struct {
	caPEM   []byte
	certPEM []byte
	keyPEM  []byte

	server *tls.Config
	client *tls.Config
	wrong  *tls.Config
}

func makeTLSFixture(t *testing.T) *tlsFixture {
	t.Helper()
	caPEM, caKey, caCert := makeCA(t, "labldap parity CA")
	serverCert, serverKey := makeServerCert(t, caCert, caKey)
	wrongCAPEM, _, _ := makeCA(t, "labldap parity WRONG CA")

	serverTLS, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatalf("parity: server key pair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("parity: CA pool did not accept generated CA")
	}
	wrongPool := x509.NewCertPool()
	if !wrongPool.AppendCertsFromPEM(wrongCAPEM) {
		t.Fatal("parity: wrong CA pool did not accept generated CA")
	}
	return &tlsFixture{
		caPEM:   caPEM,
		certPEM: serverCert,
		keyPEM:  serverKey,
		server: &tls.Config{
			Certificates: []tls.Certificate{serverTLS},
			MinVersion:   tls.VersionTLS12,
		},
		client: &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12},
		wrong:  &tls.Config{RootCAs: wrongPool, ServerName: "localhost", MinVersion: tls.VersionTLS12},
	}
}

func makeCA(t *testing.T, cn string) (pemBytes []byte, key *ecdsa.PrivateKey, cert *x509.Certificate) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("parity: CA key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatalf("parity: CA cert: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parity: parse CA cert: %v", err)
	}
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, k, cert
}

func makeServerCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("parity: server key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &k.PublicKey, caKey)
	if err != nil {
		t.Fatalf("parity: server cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("parity: marshal server key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
