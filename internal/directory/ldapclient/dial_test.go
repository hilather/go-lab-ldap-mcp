package ldapclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"

	"github.com/hilather/go-lab-ldap-mcp/internal/apperr"
	"github.com/hilather/go-lab-ldap-mcp/internal/directory"
	"github.com/hilather/go-lab-ldap-mcp/internal/observability"
)

func TestRefuseCleartextBindDoesNotDial(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	got := make(chan struct{}, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			got <- struct{}{}
			_ = c.Close()
		}
	}()
	_, err = Dial(t.Context(), Config{
		Address:      ln.Addr().String(),
		Transport:    directory.TransportLDAP,
		BindDN:       "cn=Directory Manager",
		BindPassword: observability.Secret("x"),
	})
	if err == nil {
		t.Fatal("expected cleartext refusal")
	}
	apperr.Assert(t, err).Code(apperr.CodeDirectory)
	if !hasField(err, directory.FieldForbidden) {
		t.Fatalf("want forbidden, got %v", err)
	}
	select {
	case <-got:
		t.Fatal("simple bind must not dial before TLS protection")
	case <-time.After(80 * time.Millisecond):
	}
}

func TestConnectTLSTrustAndName(t *testing.T) {
	t.Parallel()
	mat := writeTestCerts(t, "localhost")
	addr, stop := serveTLS(t, mat.cert)
	t.Cleanup(stop)

	ok := Config{
		Address:    addr,
		Transport:  directory.TransportLDAPS,
		CAFile:     mat.caFile,
		ServerName: "localhost",
	}
	c, err := Connect(t.Context(), ok)
	if err != nil {
		t.Fatalf("correct TLS: %v", err)
	}
	_ = c.Close()

	wrongCA := ok
	wrongCA.CAFile = mat.wrongCA
	if _, err := Connect(t.Context(), wrongCA); err == nil {
		t.Fatal("wrong CA must fail closed")
	} else if !hasField(err, directory.FieldForbidden) {
		t.Fatalf("wrong CA: %v", err)
	}

	wrongName := ok
	wrongName.ServerName = "not-the-server.example"
	if _, err := Connect(t.Context(), wrongName); err == nil {
		t.Fatal("wrong name must fail closed")
	} else if !hasField(err, directory.FieldForbidden) {
		t.Fatalf("wrong name: %v", err)
	}
}

func TestInsecureSkipVerifyFailClosed(t *testing.T) {
	t.Parallel()
	_, err := Connect(t.Context(), Config{
		Address:            "127.0.0.1:1",
		Transport:          directory.TransportLDAPS,
		InsecureSkipVerify: true,
	})
	if err == nil {
		t.Fatal("expected fail closed")
	}
	if !hasField(err, directory.FieldForbidden) {
		t.Fatalf("%v", err)
	}
}

func TestMissingCAFailClosed(t *testing.T) {
	t.Parallel()
	_, err := Connect(t.Context(), Config{
		Address:   "127.0.0.1:1",
		Transport: directory.TransportLDAPS,
	})
	if err == nil {
		t.Fatal("expected missing CA")
	}
	if !hasField(err, directory.FieldForbidden) {
		t.Fatalf("%v", err)
	}
}

func TestConnectSilentPeerTimesOut(t *testing.T) {
	t.Parallel()
	mat := writeTestCerts(t, "localhost")
	addr, stop := serveSilent(t)
	t.Cleanup(stop)

	for _, tr := range []directory.Transport{directory.TransportLDAPS, directory.TransportStartTLS} {
		tr := tr
		t.Run(string(tr), func(t *testing.T) {
			t.Parallel()
			start := time.Now()
			_, err := Connect(context.Background(), Config{
				Address:     addr,
				Transport:   tr,
				CAFile:      mat.caFile,
				ServerName:  "localhost",
				DialTimeout: 300 * time.Millisecond,
			})
			elapsed := time.Since(start)
			if err == nil {
				t.Fatal("silent peer must fail")
			}
			if elapsed > 2*time.Second {
				t.Fatalf("%s hung for %v", tr, elapsed)
			}
		})
	}
}

func TestConnectStartTLSWrongName(t *testing.T) {
	t.Parallel()
	mat := writeTestCerts(t, "localhost")
	addr, stop := serveStartTLS(t, mat.cert)
	t.Cleanup(stop)

	_, err := Connect(t.Context(), Config{
		Address:     addr,
		Transport:   directory.TransportStartTLS,
		CAFile:      mat.caFile,
		ServerName:  "not-the-server.example",
		DialTimeout: 2 * time.Second,
	})
	if err == nil {
		t.Fatal("wrong name must fail closed")
	}
	apperr.Assert(t, err).Code(apperr.CodeDirectory).Retryable(false)
	if !hasField(err, directory.FieldForbidden) {
		t.Fatalf("want forbidden, got %v", err)
	}
}

func TestConnectCancelUnreachable(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(40*time.Millisecond, cancel)
	_, err := Connect(ctx, Config{
		Address:            "192.0.2.1:1",
		Transport:          directory.TransportLDAP,
		AllowCleartextBind: true,
		DialTimeout:        5 * time.Second,
	})
	if err == nil {
		t.Fatal("expected cancel")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("want canceled, got %v", err)
	}
}

type testCerts struct {
	caFile  string
	wrongCA string
	cert    tls.Certificate
}

func writeTestCerts(t *testing.T, serverName string) testCerts {
	t.Helper()
	caKey := mustKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "labldap-unit-ca"},
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
	srvKey := mustKey(t)
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{serverName},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, caTmpl, &srvKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := mustKey(t)
	wrongTmpl := *caTmpl
	wrongTmpl.Subject.CommonName = "labldap-wrong-ca"
	wrongTmpl.SerialNumber = big.NewInt(3)
	wrongDER, err := x509.CreateCertificate(rand.Reader, &wrongTmpl, &wrongTmpl, &wrongKey.PublicKey, wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	wrongFile := filepath.Join(dir, "wrong.pem")
	mustWrite(t, caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	mustWrite(t, wrongFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: wrongDER}))
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srvDER}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(srvKey)}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return testCerts{caFile: caFile, wrongCA: wrongFile, cert: cert}
}

func serveSilent(t *testing.T) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				select {
				case <-done:
				case <-time.After(5 * time.Second):
				}
			}(c)
		}
	}()
	return ln.Addr().String(), func() { close(done); _ = ln.Close() }
}

func serveStartTLS(t *testing.T, cert tls.Certificate) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				pkt, err := ber.ReadPacket(c)
				if err != nil || len(pkt.Children) == 0 {
					return
				}
				var msgid int64
				switch v := pkt.Children[0].Value.(type) {
				case int64:
					msgid = v
				case int:
					msgid = int64(v)
				}
				resp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
				resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgid, "MessageID"))
				ext := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedResponse, nil, "Extended Response")
				ext.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
				ext.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
				ext.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
				resp.AppendChild(ext)
				_, _ = c.Write(resp.Bytes())
				tc := tls.Server(c, &tls.Config{
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
				})
				_ = tc.Handshake()
				buf := make([]byte, 512)
				_, _ = tc.Read(buf)
			}(c)
		}
	}()
	return ln.Addr().String(), func() { close(done); _ = ln.Close() }
}

func serveTLS(t *testing.T, cert tls.Certificate) (addr string, stop func()) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				buf := make([]byte, 512)
				_, _ = c.Read(buf)
				_ = c.Close()
			}(c)
		}
	}()
	return ln.Addr().String(), func() { close(done); _ = ln.Close() }
}

func mustKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
