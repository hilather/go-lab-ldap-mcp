package ldapserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"testing"
	"time"
)

// dmIdentity returns a Directory Manager identity whose verifier compares
// in constant time, mirroring how cmd/labldapd builds it from a file.
func dmIdentity(password string) Identity {
	return Identity{
		DN: "cn=Directory Manager",
		VerifyPassword: func(pw []byte) bool {
			return subtle.ConstantTimeCompare(pw, []byte(password)) == 1
		},
	}
}

// bindOptions returns Options with a seeded store: suffix, people
// container, and one user with a plaintext userPassword (hash verification
// lands in T-134; the bind path compares through the same seam).
func bindOptions(t *testing.T) Options {
	t.Helper()
	opts := testOptions()
	opts.AllowCleartextBind = true
	opts.DirectoryManager = dmIdentity("dm-fixture-password")
	opts.Codec = NewBERCodec(BERCodecOptions{})
	ctx := context.Background()
	if err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		for _, e := range []*Entry{
			NewEntry("dc=example,dc=test", StringAttribute("objectClass", "top", "domain")),
			NewEntry("ou=people,dc=example,dc=test", StringAttribute("objectClass", "top", "organizationalUnit")),
			NewEntry("uid=alice,ou=people,dc=example,dc=test",
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "alice"),
				StringAttribute("sn", "Adams"),
				StringAttribute("userPassword", "alice-fixture-password")),
		} {
			if err := tx.Add(ctx, e); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return opts
}

func bindResult(t *testing.T, cl *ldapTestClient, name, password string) Result {
	t.Helper()
	id := cl.send(&BindRequest{Version: 3, Name: name, Password: []byte(password)})
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	resp, ok := m.Op.(*BindResponse)
	if !ok {
		t.Fatalf("op = %T, want BindResponse", m.Op)
	}
	return resp.Result
}

func TestBindValidUser(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind = %v", res)
	}
}

func TestBindWrongPassword(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "wrong"); res.Code != ResultInvalidCredentials {
		t.Fatalf("bind = %v, want invalidCredentials", res)
	}
}

func TestBindUnknownUserIndistinguishable(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)
	unknown := bindResult(t, cl, "uid=ghost,ou=people,dc=example,dc=test", "whatever")
	wrong := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "wrong")
	if unknown.Code != ResultInvalidCredentials || wrong.Code != ResultInvalidCredentials {
		t.Fatalf("codes = %v / %v, want both invalidCredentials (C3)", unknown.Code, wrong.Code)
	}
	if unknown.DiagnosticMessage != wrong.DiagnosticMessage {
		t.Fatalf("diagnostics differ: %q vs %q", unknown.DiagnosticMessage, wrong.DiagnosticMessage)
	}
}

func TestBindDirectoryManagerSetsBypassACI(t *testing.T) {
	t.Parallel()
	opts := bindOptions(t)
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := s.newConn(context.Background(), nil, false)
	req := &BindRequest{Version: 3, Name: "cn=Directory Manager", Password: []byte("dm-fixture-password")}
	res, ok := s.authenticate(context.Background(), c, req)
	if !ok || res.Code != ResultSuccess {
		t.Fatalf("dm bind = %v, %v", res, ok)
	}
	subj := c.subject()
	if subj.Anonymous || subj.DN.String() != "cn=Directory Manager" || !subj.BypassACI {
		t.Fatalf("subject = %+v, want DM with BypassACI (ADR-0009 decision 13)", subj)
	}
	// Wrong DM password must not bypass.
	c2 := s.newConn(context.Background(), nil, false)
	res, ok = s.authenticate(context.Background(), c2, &BindRequest{Version: 3, Name: "cn=Directory Manager", Password: []byte("wrong")})
	if ok || res.Code != ResultInvalidCredentials {
		t.Fatalf("bad dm bind = %v, %v", res, ok)
	}
	if c2.subject().BypassACI {
		t.Fatal("failed DM bind set BypassACI")
	}
}

func TestBindAnonymousGated(t *testing.T) {
	t.Parallel()
	// Default off (C3): 53 per 389-observed behavior (see handleBind).
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "", ""); res.Code != ResultUnwillingToPerform {
		t.Fatalf("anonymous bind = %v, want unwillingToPerform", res)
	}
	// Enabled: succeeds and leaves the anonymous subject.
	_, addr2 := serveTestServerFrom(t, bindOptions(t), func(o *Options) { o.AllowAnonymousBind = true })
	cl2 := dialTestClient(t, addr2)
	if res := bindResult(t, cl2, "", ""); res.Code != ResultSuccess {
		t.Fatalf("anonymous bind (enabled) = %v", res)
	}
}

func TestBindCleartextRequiresOptIn(t *testing.T) {
	t.Parallel()
	opts := bindOptions(t)
	opts.AllowCleartextBind = false
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultConfidentialityRequired {
		t.Fatalf("cleartext bind = %v, want confidentialityRequired (C2)", res)
	}
}

func TestBindVersionRejected(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)
	id := cl.send(&BindRequest{Version: 2, Name: "uid=alice,ou=people,dc=example,dc=test", Password: []byte("x")})
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d", m.ID)
	}
	if resp := m.Op.(*BindResponse); resp.Result.Code != ResultProtocolError {
		t.Fatalf("v2 bind = %v, want protocolError", resp.Result)
	}
}

func TestBindPasswordZeroedAfterAuthentication(t *testing.T) {
	t.Parallel()
	opts := bindOptions(t)
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c := s.newConn(context.Background(), nil, false)
	pw := []byte("alice-fixture-password")
	msg := &Message{ID: 1, Op: &BindRequest{Version: 3, Name: "uid=alice,ou=people,dc=example,dc=test", Password: pw}}
	if keep := s.handleBind(context.Background(), c, msg, msg.Op.(*BindRequest)); !keep {
		t.Fatal("connection closed after valid bind")
	}
	if msg.Op.(*BindRequest).Password != nil {
		t.Fatal("password slice still attached after ZeroSecrets")
	}
	for _, b := range pw {
		if b != 0 {
			t.Fatal("password bytes not zeroed")
		}
	}
}

func TestBindAuthBudgetClosesConnection(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), func(o *Options) {
		o.Limits.MaxAuthAttempts = 2
	})
	cl := dialTestClient(t, addr)
	bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "wrong-1")
	bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "wrong-2")
	// The second failure hits the budget: the server sends a notice of
	// disconnection and closes.
	m := cl.recv()
	resp, ok := m.Op.(*ExtendedResponse)
	if !ok || resp.Name != OIDNoticeOfDisconnection || resp.Result.Code != ResultUnwillingToPerform {
		t.Fatalf("notice = %#v", m.Op)
	}
	_ = cl.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := cl.codec.ReadMessage(context.Background(), cl.conn)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read after budget close = %v, want EOF", err)
	}
}

// TestBindThenAbandonCancelsInflight drives the wire path: register a
// blocked in-flight op server-side, abandon it from the client, and prove
// the worker's context is canceled.
func TestBindThenAbandonCancelsInflight(t *testing.T) {
	t.Parallel()
	s, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "cn=Directory Manager", "dm-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind: %v", res)
	}
	// Grab the server-side conn and register a synthetic in-flight op.
	deadline := time.Now().Add(5 * time.Second)
	var sc *conn
	for time.Now().Before(deadline) {
		s.connsMu.Lock()
		for c := range s.conns {
			sc = c
		}
		s.connsMu.Unlock()
		if sc != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if sc == nil {
		t.Fatal("server-side connection not found")
	}
	opCtx, cancel := context.WithCancel(sc.ctx)
	defer cancel()
	if !sc.registerInflight(77, cancel) {
		t.Fatal("register failed")
	}
	cl.send(&AbandonRequest{MessageID: 77})
	select {
	case <-opCtx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("abandon did not cancel in-flight op")
	}
}

func TestBindUnbindClosesAfterBind(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "cn=Directory Manager", "dm-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind: %v", res)
	}
	cl.send(&UnbindRequest{})
	_ = cl.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := cl.codec.ReadMessage(context.Background(), cl.conn); !errors.Is(err, io.EOF) {
		t.Fatalf("read after unbind = %v, want EOF", err)
	}
}
