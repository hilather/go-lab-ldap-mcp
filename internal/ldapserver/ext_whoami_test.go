package ldapserver

import (
	"testing"
)

// whoami sends one WhoAmI extended request with no controls.
func whoami(t *testing.T, cl *ldapTestClient, req *ExtendedRequest) *ExtendedResponse {
	t.Helper()
	id := cl.sendRaw(req, nil)
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	resp, ok := m.Op.(*ExtendedResponse)
	if !ok {
		t.Fatalf("op = %T, want ExtendedResponse", m.Op)
	}
	return resp
}

// TestWhoAmIBound: after a simple bind, WhoAmI returns the bound DN in
// authzId "dn:" form (T-142 acceptance).
func TestWhoAmIBound(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)

	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind = %v", res)
	}
	resp := whoami(t, cl, &ExtendedRequest{Name: OIDWhoAmI})
	if resp.Result.Code != ResultSuccess {
		t.Fatalf("whoami = %v", resp.Result)
	}
	if resp.Name != "" {
		t.Fatalf("responseName = %q, want absent (RFC 4532)", resp.Name)
	}
	want := "dn:uid=alice,ou=people,dc=example,dc=test"
	if got := string(resp.Value); got != want {
		t.Fatalf("authzId = %q, want %q", got, want)
	}
}

// TestWhoAmIDirectoryManager: the DM identity reports its configured DN.
func TestWhoAmIDirectoryManager(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)

	if res := bindResult(t, cl, "cn=Directory Manager", "dm-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("dm bind = %v", res)
	}
	resp := whoami(t, cl, &ExtendedRequest{Name: OIDWhoAmI})
	if resp.Result.Code != ResultSuccess {
		t.Fatalf("whoami = %v", resp.Result)
	}
	if got := string(resp.Value); got != "dn:cn=Directory Manager" {
		t.Fatalf("authzId = %q, want dn:cn=Directory Manager", got)
	}
}

// TestWhoAmIAnonymous: a fresh (pre-bind) connection gets the empty
// authzId (T-142 acceptance), and rebinding anonymous resets to it.
func TestWhoAmIAnonymous(t *testing.T) {
	t.Parallel()
	opts := bindOptions(t)
	opts.AllowAnonymousBind = true
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)

	resp := whoami(t, cl, &ExtendedRequest{Name: OIDWhoAmI})
	if resp.Result.Code != ResultSuccess {
		t.Fatalf("whoami = %v", resp.Result)
	}
	if len(resp.Value) != 0 {
		t.Fatalf("anonymous authzId = %q, want empty", resp.Value)
	}

	// Bind then rebind anonymous: the identity resets (RFC 4511 4.2.1),
	// so WhoAmI must again return empty.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind = %v", res)
	}
	if res := bindResult(t, cl, "", ""); res.Code != ResultSuccess {
		t.Fatalf("anonymous rebind = %v", res)
	}
	resp = whoami(t, cl, &ExtendedRequest{Name: OIDWhoAmI})
	if resp.Result.Code != ResultSuccess || len(resp.Value) != 0 {
		t.Fatalf("post-rebind whoami = %v, value %q; want success with empty authzId", resp.Result, resp.Value)
	}
}

// TestWhoAmIRequestValueRejected: RFC 4532 defines no request value.
func TestWhoAmIRequestValueRejected(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)

	resp := whoami(t, cl, &ExtendedRequest{Name: OIDWhoAmI, Value: []byte("x")})
	if resp.Result.Code != ResultProtocolError {
		t.Fatalf("whoami with value = %v, want protocolError", resp.Result)
	}
}

// TestWhoAmIUnknownExtendedOp: unrecognized extended OIDs still fail
// protocolError and are not confused with the now-implemented WhoAmI.
func TestWhoAmIUnknownExtendedOp(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)
	cl := dialTestClient(t, addr)

	resp := whoami(t, cl, &ExtendedRequest{Name: "1.3.6.1.4.1.99999.1"})
	if resp.Result.Code != ResultProtocolError {
		t.Fatalf("unknown extended op = %v, want protocolError", resp.Result)
	}
}
