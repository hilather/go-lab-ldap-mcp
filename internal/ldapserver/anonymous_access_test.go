package ldapserver

import (
	"context"
	"testing"
)

// TestAnonymousOffRefusesUnauthenticatedOps: when AllowAnonymousBind is
// off (production default), pre-bind directory operations fail closed
// with inappropriateAuthentication (48), matching pinned 389 (KD-6 /
// D21 / D24). StartTLS is not in this table — it is handled in the
// read loop and stays legal pre-bind.
func TestAnonymousOffRefusesUnauthenticatedOps(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), nil)

	cases := []struct {
		name string
		op   Operation
	}{
		{"search-suffix", &SearchRequest{
			BaseDN: "dc=example,dc=test", Scope: ScopeBaseObject,
			Filter: &FilterPresent{Attr: "objectClass"},
		}},
		{"search-rootdse", &SearchRequest{
			BaseDN: "", Scope: ScopeBaseObject,
			Filter: &FilterPresent{Attr: "objectClass"},
		}},
		{"search-subschema", &SearchRequest{
			BaseDN: SubschemaDN, Scope: ScopeBaseObject,
			Filter: &FilterPresent{Attr: "objectClass"},
		}},
		{"compare", &CompareRequest{
			DN: "uid=alice,ou=people,dc=example,dc=test", Attr: "uid", Value: []byte("alice"),
		}},
		{"add", &AddRequest{
			DN: "uid=eve,ou=people,dc=example,dc=test",
			Attributes: []Attribute{
				StringAttribute("objectClass", "top", "person"),
				StringAttribute("uid", "eve"),
				StringAttribute("sn", "Eve"),
			},
		}},
		{"modify", &ModifyRequest{
			DN:      "uid=alice,ou=people,dc=example,dc=test",
			Changes: []ModifyChange{{Op: ModifyReplace, Attr: StringAttribute("description", "x")}},
		}},
		{"delete", &DeleteRequest{DN: "uid=alice,ou=people,dc=example,dc=test"}},
		{"modifydn", &ModifyDNRequest{DN: "uid=alice,ou=people,dc=example,dc=test", NewRDN: "uid=alice2", DeleteOldRDN: true}},
		{"whoami", &ExtendedRequest{Name: OIDWhoAmI}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cl := dialTestClient(t, addr)
			if got := unauthOpCode(t, cl, tc.op); got != ResultInappropriateAuthentication {
				t.Fatalf("code = %v, want inappropriateAuthentication", got)
			}
		})
	}
}

// TestAnonymousOffAllowsBoundSearch: a successful simple bind still
// searches the suffix, Root DSE, and subschema when anonymous is off.
func TestAnonymousOffAllowsBoundSearch(t *testing.T) {
	t.Parallel()
	opts := bindOptions(t)
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		return true, nil
	}}
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("bind = %v", res)
	}
	for _, req := range []*SearchRequest{
		{BaseDN: "dc=example,dc=test", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"}},
		{BaseDN: "", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"}},
		{BaseDN: SubschemaDN, Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"}},
	} {
		entries, done := search(t, cl, req)
		if done.Result.Code != ResultSuccess || len(entries) != 1 {
			t.Fatalf("bound search base=%q: %v, %d entries", req.BaseDN, done.Result, len(entries))
		}
	}
}

// TestAnonymousOnAllowsRootDSE: when the flag is on, pre-bind Root DSE
// (and subschema) remain readable — the current intended anonymous-on
// behavior.
func TestAnonymousOnAllowsRootDSE(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, bindOptions(t), func(o *Options) { o.AllowAnonymousBind = true })
	cl := dialTestClient(t, addr)
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("anonymous-on root dse = %v, %d entries", done.Result, len(entries))
	}
	entries, done = search(t, cl, &SearchRequest{
		BaseDN: SubschemaDN, Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("anonymous-on subschema = %v, %d entries", done.Result, len(entries))
	}
}

// TestAnonymousOffStartTLSStillWorks: StartTLS must stay legal before
// bind when anonymous access is off. The upgraded connection is still
// unauthenticated until a successful bind.
func TestAnonymousOffStartTLSStillWorks(t *testing.T) {
	t.Parallel()
	fix := newTLSFixture(t, "localhost")
	_, ldapAddr, _ := serveTLS(t, func(o *Options) {
		o.LDAPAddress = "127.0.0.1:0"
		o.LDAPSAddress = ""
		o.AllowCleartextBind = false
		o.AllowAnonymousBind = false
		o.AllowStartTLS = true
		o.TLSConfig = fix.serverConfig(t)
	})
	cl := dialTestClient(t, ldapAddr)
	if res := doStartTLS(t, cl); res.Code != ResultSuccess {
		t.Fatalf("StartTLS = %v", res)
	}
	startTLSClient(t, cl, fix.clientConfig(t, "localhost"))

	_, done := search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultInappropriateAuthentication {
		t.Fatalf("post-StartTLS pre-bind search = %v, want inappropriateAuthentication", done.Result)
	}

	if res := bindResult(t, cl, "uid=alice,ou=people,dc=example,dc=test", "alice-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("post-StartTLS bind = %v", res)
	}
	entries, done := search(t, cl, &SearchRequest{
		BaseDN: "", Scope: ScopeBaseObject, Filter: &FilterPresent{Attr: "objectClass"},
	})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("bound Root DSE after StartTLS = %v, %d entries", done.Result, len(entries))
	}
}

// unauthOpCode sends one request on a fresh connection and returns its
// LDAP result code. Search uses SearchResultDone; every other dispatched
// op has a single result-bearing response.
func unauthOpCode(t *testing.T, cl *ldapTestClient, op Operation) ResultCode {
	t.Helper()
	if req, ok := op.(*SearchRequest); ok {
		_, done := search(t, cl, req)
		return done.Result.Code
	}
	id := cl.send(op)
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	switch r := m.Op.(type) {
	case *AddResponse:
		return r.Result.Code
	case *ModifyResponse:
		return r.Result.Code
	case *DeleteResponse:
		return r.Result.Code
	case *ModifyDNResponse:
		return r.Result.Code
	case *CompareResponse:
		return r.Result.Code
	case *ExtendedResponse:
		return r.Result.Code
	default:
		t.Fatalf("unexpected op %T", m.Op)
		return 0
	}
}
