package ldapserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveTestServer starts a Server on an ephemeral loopback port and returns
// it plus the bound address. The server stops when the test ends.
func serveTestServer(t *testing.T, mutate func(*Options)) (*Server, string) {
	t.Helper()
	return serveTestServerFrom(t, testOptions(), mutate)
}

// serveTestServerFrom starts from an explicit Options base so tests can
// pre-populate the fake store before serving.
func serveTestServerFrom(t *testing.T, opts Options, mutate func(*Options)) (*Server, string) {
	t.Helper()
	opts.LDAPAddress = "127.0.0.1:0"
	opts.Codec = NewBERCodec(BERCodecOptions{})
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
	for s.LDAPAddr() == nil {
		if time.Now().After(deadline) {
			t.Fatal("listener did not bind in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
	return s, s.LDAPAddr().String()
}

// ldapTestClient is a minimal wire client backed by the real BERCodec; it
// exists only in tests.
type ldapTestClient struct {
	t      *testing.T
	conn   net.Conn
	codec  *BERCodec
	nextID int64
}

func dialTestClient(t *testing.T, addr string) *ldapTestClient {
	t.Helper()
	nc, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	c := &ldapTestClient{t: t, conn: nc, codec: NewBERCodec(BERCodecOptions{})}
	t.Cleanup(func() { _ = c.conn.Close() })
	return c
}

func (c *ldapTestClient) send(op Operation) int64 {
	c.t.Helper()
	c.nextID++
	if err := c.codec.WriteMessage(context.Background(), c.conn, &Message{ID: c.nextID, Op: op}); err != nil {
		c.t.Fatalf("write: %v", err)
	}
	return c.nextID
}

func (c *ldapTestClient) recv() *Message {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	m, err := c.codec.ReadMessage(context.Background(), c.conn)
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	return m
}

func TestServeBindStubOverTCP(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServer(t, nil)
	cl := dialTestClient(t, addr)
	id := cl.send(&BindRequest{Version: 3, Name: "cn=Directory Manager", Password: []byte("test-password")})
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	resp, ok := m.Op.(*BindResponse)
	if !ok {
		t.Fatalf("op = %T, want BindResponse", m.Op)
	}
	// The dispatch lifecycle test only needs a well-formed result; the
	// default policy here is cleartext-disabled (C3).
	if resp.Result.Code != ResultConfidentialityRequired {
		t.Fatalf("code = %v, want confidentialityRequired", resp.Result.Code)
	}
}

func TestServeDefaultAddressIsLoopback(t *testing.T) {
	t.Parallel()
	opts := testOptions()
	opts.LDAPAddress = ":0"
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := s.opts.LDAPAddress; !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("LDAPAddress = %q, want loopback-pinned", got)
	}
}

func TestServeGracefulShutdownClosesBlockedConn(t *testing.T) {
	t.Parallel()
	opts := testOptions()
	opts.LDAPAddress = "127.0.0.1:0"
	opts.Codec = NewBERCodec(BERCodecOptions{})
	opts.Limits.ShutdownTimeout = time.Second
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- s.Serve(ctx) }()
	deadline := time.Now().Add(5 * time.Second)
	for s.LDAPAddr() == nil {
		if time.Now().After(deadline) {
			t.Fatal("listener did not bind in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
	nc, err := net.DialTimeout("tcp", s.LDAPAddr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer nc.Close()
	// The client never speaks: Serve cancellation must close the blocked
	// read within the shutdown budget.
	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("Serve: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	_ = nc.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := nc.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection still open after shutdown")
	}
	_ = s.Close()
}

func TestServeMaxConnectionsNotice(t *testing.T) {
	t.Parallel()
	s, addr := serveTestServer(t, func(o *Options) {
		o.Limits.MaxConnections = 1
	})
	first, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial 1: %v", err)
	}
	defer first.Close()
	// Wait until the server has registered the first connection so the
	// ceiling is actually reached when the second client dials.
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.connsMu.Lock()
		n := len(s.conns)
		s.connsMu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("server did not register first connection in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
	nc, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer nc.Close()
	codec := NewBERCodec(BERCodecOptions{})
	_ = nc.SetReadDeadline(time.Now().Add(2 * time.Second))
	m, err := codec.ReadMessage(context.Background(), nc)
	if err != nil {
		// Closed without a readable notice is acceptable (best effort).
		return
	}
	resp, ok := m.Op.(*ExtendedResponse)
	if !ok || resp.Result.Code != ResultBusy {
		t.Fatalf("notice = %#v, want busy ExtendedResponse", m.Op)
	}
	if resp.Name != OIDNoticeOfDisconnection {
		t.Fatalf("notice name = %q", resp.Name)
	}
}

func TestConnOutstandingOpsLimit(t *testing.T) {
	t.Parallel()
	s, err := New(testOptions())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	s.opts.Limits.MaxOutstandingOps = 2
	c := s.newConn(context.Background(), nil, false)
	// Fill the semaphore.
	c.sem <- struct{}{}
	c.sem <- struct{}{}
	select {
	case c.sem <- struct{}{}:
		t.Fatal("semaphore admitted beyond MaxOutstandingOps")
	default:
	}
}

func TestConnAbandonCancelsInflight(t *testing.T) {
	t.Parallel()
	s, err := New(testOptions())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := s.newConn(context.Background(), nil, false)
	opCtx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	if !c.registerInflight(42, cancel) {
		t.Fatal("register failed")
	}
	c.abandon(42)
	select {
	case <-opCtx.Done():
	default:
		t.Fatal("abandon did not cancel the in-flight op")
	}
	// Abandoning an unknown ID is a no-op (RFC 4511 4.11).
	c.abandon(99)
	// A duplicate in-flight registration is rejected.
	if !c.registerInflight(7, cancel) {
		t.Fatal("register 7 failed")
	}
	if c.registerInflight(7, cancel) {
		t.Fatal("duplicate message ID admitted")
	}
}

// TestServeRedaction proves a bind password never reaches the log, even on
// the error paths around it.
func TestServeRedaction(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	var logMu sync.Mutex
	logger := slog.New(slog.NewTextHandler(&lockedWriter{mu: &logMu, w: &buf}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	secret := "s3cret-fixture-password"
	_, addr := serveTestServer(t, func(o *Options) { o.Logger = logger })
	cl := dialTestClient(t, addr)
	cl.send(&BindRequest{Version: 3, Name: "uid=alice,ou=people,dc=example,dc=test", Password: []byte(secret)})
	m := cl.recv()
	if _, ok := m.Op.(*BindResponse); !ok {
		t.Fatalf("op = %T, want BindResponse", m.Op)
	}
	// Follow with garbage to force a malformed-PDU notice path, then close.
	if _, err := cl.conn.Write([]byte{0x30, 0x03, 0x02, 0x01}); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_ = cl.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, err := cl.codec.ReadMessage(context.Background(), cl.conn); err != nil {
			break
		}
	}
	logMu.Lock()
	out := buf.String()
	logMu.Unlock()
	if strings.Contains(out, secret) {
		t.Fatalf("log contains bind password:\n%s", out)
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  io.Writer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestServeUnbindClosesConnection(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServer(t, nil)
	cl := dialTestClient(t, addr)
	cl.send(&UnbindRequest{})
	_ = cl.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := cl.codec.ReadMessage(context.Background(), cl.conn)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read after unbind = %v, want EOF", err)
	}
}

func TestServeMalformedPDUNotice(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServer(t, nil)
	cl := dialTestClient(t, addr)
	// A well-formed frame claiming to be a SearchRequest but with a
	// truncated body: decode fails with ErrMalformedPDU and the server
	// answers with a protocol-error notice of disconnection.
	if _, err := cl.conn.Write([]byte{0x30, 0x08, 0x02, 0x01, 0x01, 0x63, 0x03, 0x04, 0x00, 0x0a}); err != nil {
		t.Fatalf("write: %v", err)
	}
	m := cl.recv()
	resp, ok := m.Op.(*ExtendedResponse)
	if !ok {
		t.Fatalf("op = %T, want ExtendedResponse notice", m.Op)
	}
	if resp.Result.Code != ResultProtocolError {
		t.Fatalf("notice code = %v, want protocolError", resp.Result.Code)
	}
	if resp.Name != OIDNoticeOfDisconnection {
		t.Fatalf("notice name = %q", resp.Name)
	}
	// The connection is closed after the notice.
	_ = cl.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := cl.codec.ReadMessage(context.Background(), cl.conn)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read after notice = %v, want EOF", err)
	}
}
