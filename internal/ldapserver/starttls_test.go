package ldapserver

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// startTLSClient upgrades a connected test client after the server accepted
// the StartTLS extended request.
func startTLSClient(t *testing.T, c *ldapTestClient, cfg *tls.Config) {
	t.Helper()
	tlsConn := tls.Client(c.conn, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	c.conn = tlsConn
}

// doStartTLS sends the extended request and expects the given result code.
func doStartTLS(t *testing.T, cl *ldapTestClient) Result {
	t.Helper()
	id := cl.send(&ExtendedRequest{Name: OIDStartTLS})
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	resp, ok := m.Op.(*ExtendedResponse)
	if !ok {
		t.Fatalf("op = %T, want ExtendedResponse", m.Op)
	}
	if resp.Name != "" {
		t.Fatalf("StartTLS response name = %q, want empty (RFC 4511 4.14.2)", resp.Name)
	}
	return resp.Result
}

func TestStartTLSUpgradesThenBinds(t *testing.T) {
	t.Parallel()
	fix := newTLSFixture(t, "localhost")
	s, ldapAddr, _ := serveTLS(t, func(o *Options) {
		o.LDAPAddress = "127.0.0.1:0"
		o.LDAPSAddress = ""
		o.AllowCleartextBind = false
		o.AllowStartTLS = true
		o.TLSConfig = fix.serverConfig(t)
	})
	cl := dialTestClient(t, ldapAddr)

	// Pre-StartTLS the require-secure-binds gate rejects a simple bind.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultConfidentialityRequired {
		t.Fatalf("pre-StartTLS bind = %v, want confidentialityRequired", res)
	}
	// The upgrade itself must be anonymous-safe and succeed.
	if res := doStartTLS(t, cl); res.Code != ResultSuccess {
		t.Fatalf("StartTLS = %v", res)
	}
	startTLSClient(t, cl, fix.clientConfig(t, "localhost"))

	// The same connection is now TLS: the bind succeeds and the server-side
	// conn flipped its transport flag.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("post-StartTLS bind = %v", res)
	}
	if !serverConnTLS(t, s) {
		t.Fatal("server conn not marked TLS after StartTLS")
	}
}

func TestStartTLSDisabledRefusedAndConnSurvives(t *testing.T) {
	t.Parallel()
	_, ldapAddr, _ := serveTLS(t, func(o *Options) {
		o.LDAPAddress = "127.0.0.1:0"
		o.LDAPSAddress = ""
		o.AllowCleartextBind = false
		// No TLSConfig, AllowStartTLS off.
	})
	cl := dialTestClient(t, ldapAddr)
	if res := doStartTLS(t, cl); res.Code != ResultUnwillingToPerform {
		t.Fatalf("StartTLS (disabled) = %v, want unwillingToPerform", res)
	}
	// The refusal must not tear down the connection.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultConfidentialityRequired {
		t.Fatalf("post-refusal bind = %v, want confidentialityRequired (conn alive)", res)
	}
}

func TestStartTLSOnTLSRefused(t *testing.T) {
	t.Parallel()
	fix := newTLSFixture(t, "localhost")
	_, ldapAddr, ldapsAddr := serveTLS(t, func(o *Options) {
		o.LDAPAddress = "127.0.0.1:0"
		o.LDAPSAddress = "127.0.0.1:0"
		o.AllowCleartextBind = false
		o.AllowStartTLS = true
		o.TLSConfig = fix.serverConfig(t)
	})

	// LDAPS: already TLS, StartTLS is refused.
	tlsCl := dialTLS(t, ldapsAddr, fix.clientConfig(t, "localhost"))
	if res := doStartTLS(t, tlsCl); res.Code != ResultUnwillingToPerform {
		t.Fatalf("StartTLS over LDAPS = %v, want unwillingToPerform", res)
	}

	// Upgraded connection: a second StartTLS is refused the same way.
	cl := dialTestClient(t, ldapAddr)
	if res := doStartTLS(t, cl); res.Code != ResultSuccess {
		t.Fatalf("first StartTLS = %v", res)
	}
	startTLSClient(t, cl, fix.clientConfig(t, "localhost"))
	if res := doStartTLS(t, cl); res.Code != ResultUnwillingToPerform {
		t.Fatalf("second StartTLS = %v, want unwillingToPerform", res)
	}
	// Still functional after the refusal.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind after second-StartTLS refusal = %v", res)
	}
}

func TestStartTLSRequestValueRejected(t *testing.T) {
	t.Parallel()
	fix := newTLSFixture(t, "localhost")
	_, ldapAddr, _ := serveTLS(t, func(o *Options) {
		o.LDAPAddress = "127.0.0.1:0"
		o.LDAPSAddress = ""
		o.AllowStartTLS = true
		o.TLSConfig = fix.serverConfig(t)
	})
	cl := dialTestClient(t, ldapAddr)
	// RFC 4511 4.14.1 defines the StartTLS request with an absent value.
	id := cl.send(&ExtendedRequest{Name: OIDStartTLS, Value: []byte("unexpected")})
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	resp, ok := m.Op.(*ExtendedResponse)
	if !ok || resp.Result.Code != ResultProtocolError {
		t.Fatalf("StartTLS with value = %#v, want protocolError", m.Op)
	}
	// The connection is not upgraded; a cleartext request still parses.
	if res := bindResult(t, cl, "", ""); res.Code != ResultUnwillingToPerform {
		t.Fatalf("bind after rejected StartTLS = %v, want unwillingToPerform (anonymous off)", res)
	}
}

func TestStartTLSHandshakeFailureClosesConnection(t *testing.T) {
	t.Parallel()
	fix := newTLSFixture(t, "localhost")
	_, ldapAddr, _ := serveTLS(t, func(o *Options) {
		o.LDAPAddress = "127.0.0.1:0"
		o.LDAPSAddress = ""
		o.AllowStartTLS = true
		o.TLSConfig = fix.serverConfig(t)
	})
	cl := dialTestClient(t, ldapAddr)
	if res := doStartTLS(t, cl); res.Code != ResultSuccess {
		t.Fatalf("StartTLS = %v", res)
	}
	// Speak garbage instead of a TLS ClientHello: the handshake fails and
	// the server must close the connection (RFC 4513 3.1.2).
	if _, err := cl.conn.Write([]byte("not-a-tls-client-hello")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	_ = cl.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := cl.codec.ReadMessage(context.Background(), cl.conn)
	if err == nil {
		t.Fatal("read after failed handshake succeeded; want close")
	}
	if errors.Is(err, io.EOF) || isNetErr(err) {
		return
	}
	t.Fatalf("read after failed handshake = %v, want EOF or net error", err)
}

func isNetErr(err error) bool {
	var nerr net.Error
	return errors.As(err, &nerr)
}
