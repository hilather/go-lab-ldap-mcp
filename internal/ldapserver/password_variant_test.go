package ldapserver

import (
	"bytes"
	"strings"
	"testing"
)

func modifyAlice(t *testing.T, cl *ldapTestClient, changes ...ModifyChange) Result {
	t.Helper()
	id := cl.send(&ModifyRequest{DN: "uid=alice,ou=people,dc=example,dc=test", Changes: changes})
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

func assertNoPlainVariant(t *testing.T, e *Entry, name, plain string) {
	t.Helper()
	vals := e.Values(name)
	if len(vals) == 0 {
		t.Fatalf("%s missing", name)
	}
	for _, v := range vals {
		if !isPreHashed(v) || bytes.Contains(v, []byte(plain)) {
			t.Fatalf("%s stored as %q, want a hash", name, v)
		}
	}
}

func TestPolicyHashesVariantPasswordSpellings(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	opts := policyOptions(t, clock, func(p *PasswordPolicy) { p.HistoryCount = 3 })
	s, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	if res := addAlice(t, cl, "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("add: %v", res)
	}
	before := readAlice(t, s)
	changedBefore := string(before.Values("pwdChangedTime")[0])

	// Modify that only adds an optioned spelling: the canonical value is
	// unchanged, which used to return before any hashing.
	if res := modifyAlice(t, cl, ModifyChange{Op: ModifyAdd, Attr: Attribute{Name: "userPassword;lang-en", Values: [][]byte{[]byte("variant-canary-1")}}}); res.Code != ResultSuccess {
		t.Fatalf("modify add variant: %v", res)
	}
	clock.Advance(1)
	if res := modifyAlice(t, cl, ModifyChange{Op: ModifyAdd, Attr: Attribute{Name: "2.5.4.35", Values: [][]byte{[]byte("variant-canary-2")}}}); res.Code != ResultSuccess {
		t.Fatalf("modify add oid: %v", res)
	}
	e := readAlice(t, s)
	assertNoPlainVariant(t, e, "userPassword;lang-en", "variant-canary-1")
	assertNoPlainVariant(t, e, "2.5.4.35", "variant-canary-2")
	if got := string(e.Values("pwdChangedTime")[0]); got != changedBefore {
		t.Fatalf("variant write stamped pwdChangedTime %s (was %s)", got, changedBefore)
	}
	if len(e.Values("passwordHistory")) != 0 {
		t.Fatal("variant write recorded password history")
	}
	// Variant values never authenticate; the canonical password still does.
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "variant-canary-1"); res.Code != ResultInvalidCredentials {
		t.Fatalf("bind with variant value = %v, want invalidCredentials", res)
	}
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("canonical bind = %v", res)
	}
	bindDM(t, cl)

	// Same request removes the canonical password and adds a variant: the
	// password-removed branch must not skip the variant hashing.
	if res := modifyAlice(t, cl,
		ModifyChange{Op: ModifyDelete, Attr: Attribute{Name: "userPassword"}},
		ModifyChange{Op: ModifyReplace, Attr: Attribute{Name: "userPassword;x-b", Values: [][]byte{[]byte("variant-canary-3")}}},
	); res.Code != ResultSuccess {
		t.Fatalf("delete canonical + add variant: %v", res)
	}
	e = readAlice(t, s)
	assertNoPlainVariant(t, e, "userPassword;x-b", "variant-canary-3")
	if len(e.Values("userPassword")) != 0 {
		t.Fatal("canonical userPassword should be gone")
	}
	// A pre-hashed variant passes through unchanged (D3).
	pre := e.Values("userPassword;x-b")[0]
	if res := modifyAlice(t, cl, ModifyChange{Op: ModifyReplace, Attr: Attribute{Name: "userPassword;x-c", Values: [][]byte{pre}}}); res.Code != ResultSuccess {
		t.Fatalf("pre-hashed variant: %v", res)
	}
	if got := readAlice(t, s).Values("userPassword;x-c"); len(got) != 1 || !bytes.Equal(got[0], pre) {
		t.Fatalf("pre-hashed variant rewritten: %q", got)
	}
}

func TestPolicyHashesVariantPasswordOnAdd(t *testing.T) {
	t.Parallel()
	clock := newTestNow()
	opts := policyOptions(t, clock, nil)
	s, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	bindDM(t, cl)
	id := cl.send(&AddRequest{
		DN: "uid=alice,ou=people,dc=example,dc=test",
		Attributes: []Attribute{
			StringAttribute("objectClass", "top", "person"),
			StringAttribute("uid", "alice"),
			StringAttribute("cn", "Alice Adams"),
			StringAttribute("sn", "Adams"),
			StringAttribute("USERPASSWORD;lang-en", "variant-canary-add"),
		},
	})
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	if resp, ok := m.Op.(*AddResponse); !ok || resp.Result.Code != ResultSuccess {
		t.Fatalf("add = %#v", m.Op)
	}
	e := readAlice(t, s)
	assertNoPlainVariant(t, e, "userPassword;lang-en", "variant-canary-add")
	if len(e.Values("pwdChangedTime")) != 0 {
		t.Fatal("variant-only add stamped pwdChangedTime")
	}
	for _, a := range e.Attributes {
		for _, v := range a.Values {
			if strings.Contains(string(v), "variant-canary-add") {
				t.Fatalf("plaintext canary stored under %s", a.Name)
			}
		}
	}
}
