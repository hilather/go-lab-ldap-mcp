package ldapserver

import (
	"fmt"
	"testing"
)

// assertionControl encodes an RFC 4528 control value: a BER SearchFilter.
func assertionControl(t *testing.T, f Filter, critical bool) Control {
	t.Helper()
	pkt, err := encodeFilter(f, 0)
	if err != nil {
		t.Fatalf("encode assertion filter: %v", err)
	}
	return Control{OID: OIDAssertion, Critical: critical, Value: pkt.Bytes()}
}

// modifyWithControls sends one Modify with attached controls.
func modifyWithControls(t *testing.T, cl *ldapTestClient, req *ModifyRequest, controls ...Control) Result {
	t.Helper()
	id := cl.sendRaw(req, controls)
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	resp, ok := m.Op.(*ModifyResponse)
	if !ok {
		t.Fatalf("op = %T, want ModifyResponse", m.Op)
	}
	return resp.Result
}

// TestModifyAssertionMatch: a matching assertion allows the modify and the
// write commits (T-141 acceptance).
func TestModifyAssertionMatch(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	dn := "uid=alice,ou=people,dc=example,dc=test"

	res := modifyWithControls(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("description", "conditional write")},
	}}, assertionControl(t, &FilterEquality{Attr: "cn", Value: []byte("alice adams")}, true))
	if res.Code != ResultSuccess {
		t.Fatalf("matching assertion: %v, want success", res)
	}
	e, err := fetchEntry(t, opts, dn)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := e.Values("description"); len(got) != 1 || string(got[0]) != "conditional write" {
		t.Fatalf("description = %q", got)
	}
}

// TestModifyAssertionFail: a failing assertion does not apply the write
// and returns assertionFailed (122) (T-141 acceptance).
func TestModifyAssertionFail(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	dn := "uid=alice,ou=people,dc=example,dc=test"

	res := modifyWithControls(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("description", "must not land")},
	}}, assertionControl(t, &FilterEquality{Attr: "cn", Value: []byte("someone else")}, true))
	if res.Code != ResultAssertionFailed {
		t.Fatalf("failing assertion: %v, want assertionFailed(122)", res)
	}
	if res.DiagnosticMessage == "" {
		t.Fatal("assertionFailed should carry a static diagnostic")
	}
	e, err := fetchEntry(t, opts, dn)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := e.Values("description"); len(got) != 0 {
		t.Fatalf("write applied despite failed assertion: %q", got)
	}
}

// TestModifyAssertionConcurrent: N racing conditional replaces of the same
// attribute commit at most once — the assertion and the write are one
// Store.Update transaction (T-141 acceptance; T-130 atomicity pattern).
func TestModifyAssertionConcurrent(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	dn := "uid=alice,ou=people,dc=example,dc=test"

	const racers = 6
	ids := map[int64]bool{}
	for i := 0; i < racers; i++ {
		id := cl.sendRaw(&ModifyRequest{DN: dn, Changes: []ModifyChange{
			{Op: ModifyReplace, Attr: StringAttribute("cn", fmt.Sprintf("Alice Racer %d", i))},
		}}, []Control{assertionControl(t, &FilterEquality{Attr: "cn", Value: []byte("Alice Adams")}, true)})
		ids[id] = true
	}
	successes, failed := 0, 0
	for range racers {
		m := cl.recv()
		resp, ok := m.Op.(*ModifyResponse)
		if !ok {
			t.Fatalf("op = %T, want ModifyResponse", m.Op)
		}
		if !ids[m.ID] {
			t.Fatalf("unexpected response id %d", m.ID)
		}
		switch resp.Result.Code {
		case ResultSuccess:
			successes++
		case ResultAssertionFailed:
			failed++
		default:
			t.Fatalf("racer result = %v", resp.Result)
		}
	}
	if successes != 1 || failed != racers-1 {
		t.Fatalf("concurrent assertions: %d succeeded, %d failed; want exactly 1 success, %d assertionFailed",
			successes, failed, racers-1)
	}
}

// TestModifyAssertionControlMalformed: missing, malformed, and duplicated
// control values fail protocolError before any write.
func TestModifyAssertionControlMalformed(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, writeOptions(t, nil), nil)
	cl := dialTestClient(t, addr)
	dn := "uid=alice,ou=people,dc=example,dc=test"
	req := func() *ModifyRequest {
		return &ModifyRequest{DN: dn, Changes: []ModifyChange{
			{Op: ModifyReplace, Attr: StringAttribute("description", "x")},
		}}
	}

	// Absent value.
	if res := modifyWithControls(t, cl, req(), Control{OID: OIDAssertion, Critical: true}); res.Code != ResultProtocolError {
		t.Fatalf("valueless assertion: %v, want protocolError", res)
	}
	// Value that is not a filter (a SEQUENCE, not a context-class CHOICE).
	if res := modifyWithControls(t, cl, req(), Control{OID: OIDAssertion, Critical: true, Value: []byte{0x30, 0x00}}); res.Code != ResultProtocolError {
		t.Fatalf("malformed assertion: %v, want protocolError", res)
	}
	// Duplicated control.
	ctrl := assertionControl(t, &FilterPresent{Attr: "cn"}, true)
	if res := modifyWithControls(t, cl, req(), ctrl, ctrl); res.Code != ResultProtocolError {
		t.Fatalf("duplicate assertion: %v, want protocolError", res)
	}
}

// TestAssertionControlScope: the control is honored on Modify at either
// criticality; a critical assertion on another operation fails
// unavailableCriticalExtension, and a non-critical one is ignored (RFC
// 4511 section 4.1.11).
func TestAssertionControlScope(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, nil)
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	dn := "uid=alice,ou=people,dc=example,dc=test"

	// Non-critical failing assertion on Modify is still honored.
	res := modifyWithControls(t, cl, &ModifyRequest{DN: dn, Changes: []ModifyChange{
		{Op: ModifyReplace, Attr: StringAttribute("description", "must not land")},
	}}, assertionControl(t, &FilterEquality{Attr: "cn", Value: []byte("nope")}, false))
	if res.Code != ResultAssertionFailed {
		t.Fatalf("non-critical failing assertion: %v, want assertionFailed", res)
	}

	// Critical assertion on Search: cannot be silently ignored (C9).
	_, done, _ := searchFull(t, cl, &SearchRequest{
		BaseDN: dn, Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	}, assertionControl(t, &FilterPresent{Attr: "cn"}, true))
	if done.Result.Code != ResultUnavailableCriticalExtension {
		t.Fatalf("critical assertion on search: %v, want unavailableCriticalExtension", done.Result)
	}

	// Non-critical assertion on Search: ignored, search proceeds.
	entries, done, _ := searchFull(t, cl, &SearchRequest{
		BaseDN: dn, Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	}, assertionControl(t, &FilterEquality{Attr: "cn", Value: []byte("nope")}, false))
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("non-critical assertion on search: %v, %d entries", done.Result, len(entries))
	}
}
