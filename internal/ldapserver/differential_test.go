package ldapserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// This file is the T-149 differential harness: one scripted sequence of
// valid LDAP PDUs is fed to the native engine and — when a pinned 389 DS
// container is available — to the 389 oracle, and the normalized results
// are compared step by step (parity contract section 5 rule 3: result
// code, normalized DN set, normalized attribute sets with secrets
// stripped). A divergence that is not a logged Delta is a gating failure.
//
// Lanes:
//
//   - TestDifferentialNativeSequence always runs. It drives the full
//     sequence against the in-process native server and pins every
//     expected outcome exactly, so a native regression fails hermetically
//     (go test ./... stays Docker-free).
//   - TestDifferential389Oracle runs only when LABLDAP_DIFF_389=1 and the
//     pinned 389 image (deploy/docker/dirsrv.digest) is startable. It
//     configures the container the way LabLDAP does for the compared
//     surface (anonymous access off), seeds both engines with the same
//     wire-level data, replays the identical PDU sequence, and compares.
//
// Compared per step: LDAP result code, folded+sorted entry DN set, and —
// for base searches — attribute sets with secrets and engine-specific
// surface stripped (userPassword, aci, operational attrs, nsMemberOf;
// memberOf and runtime-ACI parity belong to the test/parity lane, T-147).
// Diagnostic message text is never compared (contract section 5 rule 4).

// diffOracleEnv gates the 389 leg. Docker work under plain "go test ./..."
// must be opt-in so the hermetic suite stays fast and green.
const diffOracleEnv = "LABLDAP_DIFF_389"

// diffOutcome is one step's normalized, comparable result.
type diffOutcome struct {
	code    ResultCode
	dns     []string            // folded + sorted search-entry DNs
	attrs   map[string][]string // attr -> folded sorted values (secret/engine surface stripped)
	opAttrs []string            // operational attrs present (names only, folded, sorted)
	ext     *string             // extended response value (WhoAmI)
}

// diffStep is one scripted exchange. delta names the accepted Delta ID
// from docs/design/parity-delta-log.md when the engines intentionally
// differ on this step; an unexpected difference fails the oracle test.
type diffStep struct {
	name  string
	delta string
	run   func(t *testing.T, s *diffSession) diffOutcome
}

// diffSession drives one engine under comparison.
type diffSession struct {
	t      *testing.T
	addr   string
	dmPass string
}

// dial opens a fresh client connection to the engine under test.
func (s *diffSession) dial() *ldapTestClient {
	return dialTestClient(s.t, s.addr)
}

// bindResultOn binds on a fresh connection and returns the result code.
func (s *diffSession) bindCode(name, password string) diffOutcome {
	cl := s.dial()
	return diffOutcome{code: bindResult(s.t, cl, name, password).Code}
}

// bindDM returns a connection bound as Directory Manager.
func (s *diffSession) bindDM() *ldapTestClient {
	cl := s.dial()
	if res := bindResult(s.t, cl, "cn=Directory Manager", s.dmPass); res.Code != ResultSuccess {
		s.t.Fatalf("DM bind: %v", res)
	}
	return cl
}

// diffSeedEntries is the shared fixture tree, added over the wire as
// Directory Manager so both engines run their real write paths (schema
// gate, plugins, operational attributes). No real credentials.
func diffSeedEntries() []*AddRequest {
	return []*AddRequest{
		{DN: "ou=people,dc=example,dc=test", Attributes: []Attribute{
			{Name: "objectClass", Values: [][]byte{[]byte("top"), []byte("organizationalUnit")}},
			{Name: "ou", Values: [][]byte{[]byte("people")}},
		}},
		{DN: "ou=groups,dc=example,dc=test", Attributes: []Attribute{
			{Name: "objectClass", Values: [][]byte{[]byte("top"), []byte("organizationalUnit")}},
			{Name: "ou", Values: [][]byte{[]byte("groups")}},
		}},
		{DN: "uid=alice,ou=people,dc=example,dc=test", Attributes: []Attribute{
			{Name: "objectClass", Values: [][]byte{[]byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("inetOrgPerson")}},
			{Name: "uid", Values: [][]byte{[]byte("alice")}},
			{Name: "cn", Values: [][]byte{[]byte("Alice Adams")}},
			{Name: "sn", Values: [][]byte{[]byte("Adams")}},
			{Name: "userPassword", Values: [][]byte{[]byte("alice-diff-fixture")}},
		}},
		{DN: "uid=bob,ou=people,dc=example,dc=test", Attributes: []Attribute{
			{Name: "objectClass", Values: [][]byte{[]byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("inetOrgPerson")}},
			{Name: "uid", Values: [][]byte{[]byte("bob")}},
			{Name: "cn", Values: [][]byte{[]byte("Bob Brown")}},
			{Name: "sn", Values: [][]byte{[]byte("Brown")}},
			{Name: "userPassword", Values: [][]byte{[]byte("bob-diff-fixture")}},
		}},
		{DN: "cn=admins,ou=groups,dc=example,dc=test", Attributes: []Attribute{
			{Name: "objectClass", Values: [][]byte{[]byte("top"), []byte("groupOfNames")}},
			{Name: "cn", Values: [][]byte{[]byte("admins")}},
			{Name: "member", Values: [][]byte{[]byte("uid=alice,ou=people,dc=example,dc=test")}},
		}},
	}
}

// seedDiffEngine adds the fixture tree as DM. The suffix root must already
// exist on both engines (native seeds it in Options; 389 gets it from
// dsconf backend create --create-suffix).
func seedDiffEngine(s *diffSession) {
	cl := s.bindDM()
	for _, add := range diffSeedEntries() {
		id := cl.send(add)
		m := cl.recv()
		resp, ok := m.Op.(*AddResponse)
		if !ok {
			s.t.Fatalf("add %s: op = %T", add.DN, m.Op)
		}
		// entryAlreadyExists keeps the seed idempotent across shared runs.
		if resp.Result.Code != ResultSuccess && resp.Result.Code != ResultEntryAlreadyExists {
			s.t.Fatalf("add %s: %v (id %d)", add.DN, resp.Result, id)
		}
	}
}

// diffStripAttrs are removed from attribute comparison: credentials, the
// 389 auto-installed suffix ACI, server-owned operational attrs (compared
// as presence flags), and the memberOf surface (memberOf parity, including
// the nsMemberOf object-class marker, is the T-147 lane and needs the 389
// memberOf plugin enabled, which this minimal oracle deliberately does
// not do).
var diffStripAttrs = map[string]bool{
	"userpassword":      true,
	"aci":               true,
	"memberof":          true,
	"nsmemberof":        true,
	"createtimestamp":   true,
	"modifytimestamp":   true,
	"modifiersname":     true,
	"entryuuid":         true,
	"creatorsname":      true,
	"subschemasubentry": true,
	// 389-specific operational attrs surfaced by "+" on entries. Engine
	// surface under the D6 principle (the ledger records them); native
	// honestly omits what it does not implement.
	"entrydn":    true,
	"dsentrydn":  true,
	"entryid":    true,
	"parentid":   true,
	"nsuniqueid": true,
}

// diffOperationalAttrs are recorded as present-names-only.
var diffOperationalAttrs = map[string]bool{
	"createtimestamp": true,
	"modifytimestamp": true,
	"entryuuid":       true,
}

// normEntries folds a search result into comparable form.
func normEntries(entries []*SearchResultEntry) (dns []string) {
	for _, e := range entries {
		d, err := config.ParseDN(e.DN)
		if err != nil {
			dns = append(dns, "!unparseable!"+strings.ToLower(e.DN))
			continue
		}
		dns = append(dns, d.FoldedKey())
	}
	sort.Strings(dns)
	return dns
}

// normAttrs folds one entry's attributes into comparable form.
func normAttrs(attrs []Attribute) (out map[string][]string, opAttrs []string) {
	out = map[string][]string{}
	opSeen := map[string]bool{}
	for _, a := range attrs {
		name := strings.ToLower(a.Name)
		if diffOperationalAttrs[name] && !opSeen[name] {
			opSeen[name] = true
			opAttrs = append(opAttrs, name)
		}
		if diffStripAttrs[name] {
			continue
		}
		vals := make([]string, 0, len(a.Values))
		for _, v := range a.Values {
			val := strings.ToLower(strings.Join(strings.Fields(string(v)), " "))
			if name == "objectclass" && val == "nsmemberof" {
				continue // memberOf marker class: T-147 lane, stripped above for attrs
			}
			vals = append(vals, val)
		}
		sort.Strings(vals)
		out[name] = vals
	}
	sort.Strings(opAttrs)
	return out, opAttrs
}

// searchOutcome runs one search and normalizes entries + done code.
func searchOutcome(t *testing.T, cl *ldapTestClient, req *SearchRequest, controls ...Control) diffOutcome {
	t.Helper()
	entries, done, _ := searchFull(t, cl, req, controls...)
	return diffOutcome{code: done.Result.Code, dns: normEntries(entries)}
}

// baseAttrOutcome runs a base search and normalizes the single entry's
// attribute sets (values compared, engine surface stripped).
func baseAttrOutcome(t *testing.T, cl *ldapTestClient, base string, attrs []string) diffOutcome {
	t.Helper()
	entries, done, _ := searchFull(t, cl, &SearchRequest{
		BaseDN: base, Scope: ScopeBaseObject,
		Filter: &FilterPresent{Attr: "objectClass"}, Attributes: attrs,
	})
	o := diffOutcome{code: done.Result.Code}
	if len(entries) == 1 {
		o.attrs, o.opAttrs = normAttrs(entries[0].Attributes)
		if d, err := config.ParseDN(entries[0].DN); err == nil {
			o.dns = []string{d.FoldedKey()}
		}
	}
	return o
}

// simpleOpOutcome sends one request and folds the single response code.
func simpleOpOutcome(t *testing.T, cl *ldapTestClient, op Operation, controls ...Control) diffOutcome {
	t.Helper()
	id := cl.sendRaw(op, controls)
	m := cl.recv()
	if m.ID != id {
		t.Fatalf("response id = %d, want %d", m.ID, id)
	}
	switch resp := m.Op.(type) {
	case *ModifyResponse:
		return diffOutcome{code: resp.Result.Code}
	case *AddResponse:
		return diffOutcome{code: resp.Result.Code}
	case *DeleteResponse:
		return diffOutcome{code: resp.Result.Code}
	case *ModifyDNResponse:
		return diffOutcome{code: resp.Result.Code}
	case *CompareResponse:
		return diffOutcome{code: resp.Result.Code}
	case *ExtendedResponse:
		o := diffOutcome{code: resp.Result.Code}
		if resp.Value != nil {
			v := string(resp.Value)
			o.ext = &v
		}
		return o
	case *SearchResultDone:
		return diffOutcome{code: resp.Result.Code}
	default:
		t.Fatalf("unexpected op %T", m.Op)
		return diffOutcome{}
	}
}

// diffSequence is the canned valid-PDU sequence run against both engines.
// Steps are ordered: pre-auth probes first (each on a fresh connection),
// then the DM-bound directory phase.
func diffSequence() []diffStep {
	return []diffStep{
		// CAND-1 adjudicated 2026-08-15: 389 returns 48, native 53 (D9).
		{name: "anon-bind-disabled", delta: "D9", run: func(t *testing.T, s *diffSession) diffOutcome {
			return s.bindCode("", "")
		}},
		// 389 returns invalidCredentials(49) for an LDAPv2 bind; native is
		// strict RFC 4511 protocolError(2) (D10).
		{name: "bind-version-2", delta: "D10", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.dial()
			id := cl.send(&BindRequest{Version: 2, Name: "uid=alice,ou=people,dc=example,dc=test", Password: []byte("x")})
			m := cl.recv()
			if m.ID != id {
				t.Fatalf("response id = %d", m.ID)
			}
			return diffOutcome{code: m.Op.(*BindResponse).Result.Code}
		}},
		{name: "bind-unknown-user", run: func(t *testing.T, s *diffSession) diffOutcome {
			return s.bindCode("uid=ghost,ou=people,dc=example,dc=test", "whatever")
		}},
		{name: "bind-wrong-password", run: func(t *testing.T, s *diffSession) diffOutcome {
			return s.bindCode("uid=alice,ou=people,dc=example,dc=test", "wrong")
		}},
		{name: "bind-user-ok", run: func(t *testing.T, s *diffSession) diffOutcome {
			return s.bindCode("uid=alice,ou=people,dc=example,dc=test", "alice-diff-fixture")
		}},
		{name: "bind-malformed-dn", delta: "D8", run: func(t *testing.T, s *diffSession) diffOutcome {
			// Native folds a syntactically invalid bind DN into
			// invalidCredentials so the bind path cannot probe DN syntax;
			// the oracle answers invalidDNSyntax.
			return s.bindCode("not a dn", "x")
		}},
		// CAND-20 adjudicated 2026-08-15 (D13): 389 renders the bound
		// authzId as "dn: <case-folded dn>" (space, normalized); native
		// emits "dn:<as-bound dn>".
		{name: "whoami-bound", delta: "D13", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return simpleOpOutcome(t, cl, &ExtendedRequest{Name: OIDWhoAmI})
		}},
		// CAND-20 anonymous case (D14): with anonymous access disabled, 389
		// refuses the WhoAmI op itself (48); native succeeds with an empty
		// authzId.
		{name: "whoami-anonymous", delta: "D14", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.dial()
			return simpleOpOutcome(t, cl, &ExtendedRequest{Name: OIDWhoAmI})
		}},
		{name: "search-base-missing", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return searchOutcome(t, cl, &SearchRequest{
				BaseDN: "uid=ghost,ou=people,dc=example,dc=test", Scope: ScopeBaseObject,
				Filter: &FilterPresent{Attr: "objectClass"},
			})
		}},
		{name: "search-sub-equality", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return searchOutcome(t, cl, &SearchRequest{
				BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
				Filter: &FilterEquality{Attr: "uid", Value: []byte("alice")},
			})
		}},
		{name: "search-sub-equality-folded", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return searchOutcome(t, cl, &SearchRequest{
				BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
				Filter: &FilterEquality{Attr: "cn", Value: []byte("ALICE ADAMS")},
			})
		}},
		{name: "search-sub-approx", run: func(t *testing.T, s *diffSession) diffOutcome {
			// CAND-2 adjudicated: 389 evaluates approxMatch as equality
			// for attributes without an approximate rule; native folds to
			// equality deliberately. Contract behavior.
			cl := s.bindDM()
			return searchOutcome(t, cl, &SearchRequest{
				BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
				Filter: &FilterApproxMatch{Attr: "uid", Value: []byte("ALICE")},
			})
		}},
		{name: "search-onelevel", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return searchOutcome(t, cl, &SearchRequest{
				BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeSingleLevel,
				Filter: &FilterPresent{Attr: "objectClass"},
			})
		}},
		{name: "search-present-member", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return searchOutcome(t, cl, &SearchRequest{
				BaseDN: "ou=groups,dc=example,dc=test", Scope: ScopeWholeSubtree,
				Filter: &FilterPresent{Attr: "member"},
			})
		}},
		{name: "search-substring", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return searchOutcome(t, cl, &SearchRequest{
				BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
				Filter: &FilterSubstrings{Attr: "cn", Initial: []byte("ali")},
			})
		}},
		{name: "search-and-or-not", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return searchOutcome(t, cl, &SearchRequest{
				BaseDN: "dc=example,dc=test", Scope: ScopeWholeSubtree,
				Filter: &FilterAnd{Children: []Filter{
					&FilterEquality{Attr: "objectClass", Value: []byte("inetOrgPerson")},
					&FilterNot{Child: &FilterEquality{Attr: "uid", Value: []byte("bob")}},
				}},
			})
		}},
		{name: "search-client-sizelimit", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			entries, done, _ := searchFull(t, cl, &SearchRequest{
				BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeWholeSubtree,
				SizeLimit: 1,
				Filter:    &FilterPresent{Attr: "objectClass"},
			})
			// Which single entry a size-capped search returns is engine
			// order, not Contract; compare the code and the count only.
			return diffOutcome{code: done.Result.Code, dns: []string{fmt.Sprintf("count=%d", len(entries))}}
		}},
		{name: "search-base-attrs", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return baseAttrOutcome(t, cl, "uid=alice,ou=people,dc=example,dc=test", []string{"*", "+"})
		}},
		{name: "compare-true", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return simpleOpOutcome(t, cl, &CompareRequest{
				DN: "uid=alice,ou=people,dc=example,dc=test", Attr: "uid", Value: []byte("alice"),
			})
		}},
		{name: "compare-false", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return simpleOpOutcome(t, cl, &CompareRequest{
				DN: "uid=alice,ou=people,dc=example,dc=test", Attr: "uid", Value: []byte("nope"),
			})
		}},
		{name: "compare-missing-entry", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return simpleOpOutcome(t, cl, &CompareRequest{
				DN: "uid=ghost,ou=people,dc=example,dc=test", Attr: "uid", Value: []byte("x"),
			})
		}},
		{name: "modify-replace-missing-attr", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return simpleOpOutcome(t, cl, &ModifyRequest{
				DN:      "uid=alice,ou=people,dc=example,dc=test",
				Changes: []ModifyChange{{Op: ModifyReplace, Attr: Attribute{Name: "description"}}},
			})
		}},
		// CAND-3 adjudicated 2026-08-15: engines agree (noSuchAttribute);
		// the step stays untagged as Contract behavior.
		{name: "modify-delete-missing-attr", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return simpleOpOutcome(t, cl, &ModifyRequest{
				DN:      "uid=alice,ou=people,dc=example,dc=test",
				Changes: []ModifyChange{{Op: ModifyDelete, Attr: Attribute{Name: "description"}}},
			})
		}},
		// CAND-4 adjudicated 2026-08-15: 389 affectsMultipleDSAs(71),
		// native unwillingToPerform(53) (D11).
		{name: "modifydn-cross-suffix", delta: "D11", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return simpleOpOutcome(t, cl, &ModifyDNRequest{
				DN: "uid=alice,ou=people,dc=example,dc=test", NewRDN: "uid=alice",
				DeleteOldRDN: false, NewSuperior: "dc=other,dc=test",
			})
		}},
		{name: "add-schema-violation", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return simpleOpOutcome(t, cl, &AddRequest{
				DN: "uid=nosn,ou=people,dc=example,dc=test",
				Attributes: []Attribute{
					{Name: "objectClass", Values: [][]byte{[]byte("top"), []byte("person"), []byte("organizationalPerson"), []byte("inetOrgPerson")}},
					{Name: "uid", Values: [][]byte{[]byte("nosn")}},
					{Name: "cn", Values: [][]byte{[]byte("No SN")}},
				},
			})
		}},
		{name: "add-duplicate", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			add := diffSeedEntries()[2] // alice
			_ = cl.send(add)
			m := cl.recv()
			return diffOutcome{code: m.Op.(*AddResponse).Result.Code}
		}},
		{name: "unknown-critical-control", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			return searchOutcome(t, cl, &SearchRequest{
				BaseDN: "dc=example,dc=test", Scope: ScopeBaseObject,
				Filter: &FilterPresent{Attr: "objectClass"},
			}, Control{OID: "1.2.3.4.5.6.7", Critical: true, Value: []byte("x")})
		}},
		// CAND-18 adjudicated 2026-08-15: 389 accepts a tampered cookie
		// (success — no integrity protection); native's HMAC-signed cookie
		// fails closed with unwillingToPerform(53) (D12).
		{name: "paged-tampered-cookie", delta: "D12", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.bindDM()
			req := &SearchRequest{
				BaseDN: "ou=people,dc=example,dc=test", Scope: ScopeWholeSubtree,
				Filter: &FilterPresent{Attr: "objectClass"},
			}
			first := Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(1, nil)}
			_, done, ctrl := searchFull(t, cl, req, first)
			if done.Result.Code != ResultSuccess {
				t.Fatalf("first page: %v", done.Result)
			}
			cookie := decodePagedCookie(t, ctrl)
			if len(cookie) == 0 {
				t.Fatal("first page returned no continuation cookie")
			}
			tampered := append([]byte(nil), cookie...)
			tampered[0] ^= 0xff
			second := Control{OID: OIDSimplePagedResults, Value: encodePagedCookie(1, tampered)}
			_, done2, _ := searchFull(t, cl, req, second)
			return diffOutcome{code: done2.Result.Code}
		}},
		{name: "unbind-closes", run: func(t *testing.T, s *diffSession) diffOutcome {
			cl := s.dial()
			cl.send(&UnbindRequest{})
			_ = cl.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err := cl.codec.ReadMessage(context.Background(), cl.conn)
			if errors.Is(err, io.EOF) {
				return diffOutcome{code: ResultSuccess}
			}
			t.Fatalf("read after unbind = %v, want EOF", err)
			return diffOutcome{}
		}},
	}
}

// diffOutcomeEqual compares comparable fields. ext values are compared by
// exact string only when both engines returned a value.
func diffOutcomeEqual(a, b diffOutcome) bool {
	return a.code == b.code &&
		reflect.DeepEqual(a.dns, b.dns) &&
		reflect.DeepEqual(a.attrs, b.attrs) &&
		reflect.DeepEqual(a.opAttrs, b.opAttrs) &&
		reflect.DeepEqual(a.ext, b.ext)
}

// TestDifferentialNativeSequence pins every step's outcome against the
// in-process native engine. It is the hermetic half of the gate: any
// native behavior change on the scripted surface fails here, oracle or no
// oracle. Expectations marked with a delta ID mirror the ledger in
// docs/design/parity-delta-log.md.
func TestDifferentialNativeSequence(t *testing.T) {
	s, addr := diffNativeServer(t, NewFakeStore())
	defer func() { _ = s.Close() }()
	seedDiffEngine(&diffSession{t: t, addr: addr, dmPass: diffDMFixturePassword})

	want := map[string]diffOutcome{
		"anon-bind-disabled":  {code: ResultUnwillingToPerform},
		"bind-version-2":      {code: ResultProtocolError},
		"bind-unknown-user":   {code: ResultInvalidCredentials},
		"bind-wrong-password": {code: ResultInvalidCredentials},
		"bind-user-ok":        {code: ResultSuccess},
		"bind-malformed-dn":   {code: ResultInvalidCredentials}, // D8
		"whoami-bound":        {code: ResultSuccess, ext: strPtr("dn:cn=Directory Manager")},
		// Anonymous WhoAmI: native emits a present, zero-length responseValue
		// (RFC 4532), which decodes indistinguishably from absent; the
		// CAND-20 adjudication step tags any 389-visible rendering.
		"whoami-anonymous":           {code: ResultSuccess},
		"search-base-missing":        {code: ResultNoSuchObject},
		"search-sub-equality":        {code: ResultSuccess, dns: []string{"uid=alice,ou=people,dc=example,dc=test"}},
		"search-sub-equality-folded": {code: ResultSuccess, dns: []string{"uid=alice,ou=people,dc=example,dc=test"}},
		"search-sub-approx":          {code: ResultSuccess, dns: []string{"uid=alice,ou=people,dc=example,dc=test"}},
		"search-onelevel": {code: ResultSuccess, dns: []string{
			"uid=alice,ou=people,dc=example,dc=test", "uid=bob,ou=people,dc=example,dc=test",
		}},
		"search-present-member":   {code: ResultSuccess, dns: []string{"cn=admins,ou=groups,dc=example,dc=test"}},
		"search-substring":        {code: ResultSuccess, dns: []string{"uid=alice,ou=people,dc=example,dc=test"}},
		"search-and-or-not":       {code: ResultSuccess, dns: []string{"uid=alice,ou=people,dc=example,dc=test"}},
		"search-client-sizelimit": {code: ResultSizeLimitExceeded, dns: []string{"count=1"}},
		// search-base-attrs is validated by assertNativeBaseAttrs below;
		// the entry only reserves the name.
		"search-base-attrs":           {},
		"compare-true":                {code: ResultCompareTrue},
		"compare-false":               {code: ResultCompareFalse},
		"compare-missing-entry":       {code: ResultNoSuchObject},
		"modify-replace-missing-attr": {code: ResultSuccess},
		"modify-delete-missing-attr":  {code: ResultNoSuchAttribute},    // CAND-3
		"modifydn-cross-suffix":       {code: ResultUnwillingToPerform}, // CAND-4
		"add-schema-violation":        {code: ResultObjectClassViolation},
		"add-duplicate":               {code: ResultEntryAlreadyExists},
		"unknown-critical-control":    {code: ResultUnavailableCriticalExtension},
		"paged-tampered-cookie":       {code: ResultUnwillingToPerform}, // CAND-18
		"unbind-closes":               {code: ResultSuccess},
	}
	sess := &diffSession{t: t, addr: addr, dmPass: diffDMFixturePassword}
	for _, step := range diffSequence() {
		t.Run(step.name, func(t *testing.T) {
			got := step.run(t, sess)
			w, ok := want[step.name]
			if !ok {
				t.Fatalf("no pinned expectation for step %q", step.name)
			}
			if step.name == "search-base-attrs" {
				assertNativeBaseAttrs(t, got)
				return
			}
			if !diffOutcomeEqual(got, w) {
				t.Fatalf("native outcome = %+v, want %+v", got, w)
			}
		})
	}
}

// assertNativeBaseAttrs pins the attribute surface of a seeded person.
func assertNativeBaseAttrs(t *testing.T, got diffOutcome) {
	t.Helper()
	if got.code != ResultSuccess {
		t.Fatalf("base search: %v", got.code)
	}
	want := map[string][]string{
		"objectclass": {"inetorgperson", "organizationalperson", "person", "top"},
		"uid":         {"alice"},
		"cn":          {"alice adams"},
		"sn":          {"adams"},
	}
	if !reflect.DeepEqual(got.attrs, want) {
		t.Fatalf("attrs = %v, want %v", got.attrs, want)
	}
	for _, op := range []string{"createtimestamp", "entryuuid", "modifytimestamp"} {
		found := false
		for _, name := range got.opAttrs {
			if name == op {
				found = true
			}
		}
		if !found {
			t.Fatalf("operational attr %s missing from +/* selection: %v", op, got.opAttrs)
		}
	}
}

// diffDMFixturePassword is the fixture Directory Manager password for both
// engines. Not a real credential.
const diffDMFixturePassword = "dm-diff-fixture-password"

func strPtr(s string) *string { return &s }

// diffNativeServer starts the native leg: a production-shaped server
// (standard schema, memberOf + refint plugins, DM identity, cleartext
// binds allowed to match the oracle's loopback lane) over the real BER
// codec. The suffix root is seeded directly; everything else goes over
// the wire.
func diffNativeServer(t *testing.T, st Store) (*Server, string) {
	t.Helper()
	schema, err := StandardSchema()
	if err != nil {
		t.Fatalf("StandardSchema: %v", err)
	}
	mo, err := NewMemberOfPlugin("dc=example,dc=test", false)
	if err != nil {
		t.Fatalf("memberof: %v", err)
	}
	ri, err := NewRefIntPlugin("dc=example,dc=test")
	if err != nil {
		t.Fatalf("refint: %v", err)
	}
	opts := testOptions()
	opts.Schema = schema
	opts.Store = st
	opts.Plugins = []Plugin{mo, ri}
	opts.AllowCleartextBind = true
	opts.DirectoryManager = dmIdentity(diffDMFixturePassword)
	// DM bypasses ACI; no other ACIs exist on either engine, so everyone
	// else is denied — the same shape as the freshly-configured 389 oracle
	// (password_test.go mirrors this for the policy seam).
	opts.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
		return check.Subject.BypassACI, nil
	}}
	ctx := context.Background()
	if err := opts.Store.Update(ctx, func(tx UpdateTx) error {
		return tx.Add(ctx, NewEntry("dc=example,dc=test",
			StringAttribute("objectClass", "top", "domain"),
			StringAttribute("dc", "example")))
	}); err != nil {
		t.Fatalf("seed suffix: %v", err)
	}
	return serveTestServerFrom(t, opts, nil)
}

// ---------------------------------------------------------------------------
// 389 oracle leg (opt-in: LABLDAP_DIFF_389=1 + Docker + pinned image)
// ---------------------------------------------------------------------------

// TestDifferential389Oracle replays the identical PDU sequence against the
// pinned 389 DS container and the in-process native engine and compares
// normalized outcomes. Divergences outside the logged Delta set fail.
func TestDifferential389Oracle(t *testing.T) {
	if os.Getenv(diffOracleEnv) != "1" {
		t.Skipf("set %s=1 to run the 389 oracle comparison (needs Docker and the pinned image)", diffOracleEnv)
	}
	oracle := start389Oracle(t)

	s, nativeAddr := diffNativeServer(t, NewFakeStore())
	defer func() { _ = s.Close() }()
	seedDiffEngine(&diffSession{t: t, addr: nativeAddr, dmPass: diffDMFixturePassword})
	seedDiffEngine(&diffSession{t: t, addr: oracle, dmPass: diffDMFixturePassword})

	nativeSess := &diffSession{t: t, addr: nativeAddr, dmPass: diffDMFixturePassword}
	oracleSess := &diffSession{t: t, addr: oracle, dmPass: diffDMFixturePassword}

	var failures int
	for _, step := range diffSequence() {
		t.Run(step.name, func(t *testing.T) {
			gotNative := step.run(t, nativeSess)
			got389 := step.run(t, oracleSess)
			if diffOutcomeEqual(gotNative, got389) {
				if step.delta != "" {
					t.Logf("note: engines agree on %q; delta %s may be resolved", step.name, step.delta)
				}
				return
			}
			if step.delta != "" {
				t.Logf("accepted divergence under %s: native=%s 389=%s",
					step.delta, formatOutcome(gotNative), formatOutcome(got389))
				return
			}
			failures++
			t.Errorf("DIVERGENCE (no logged delta): native=%s 389=%s",
				formatOutcome(gotNative), formatOutcome(got389))
		})
	}
	if failures > 0 {
		t.Fatalf("%d undecided divergences; each is a native bug or a new Delta in docs/design/parity-delta-log.md", failures)
	}
}

func formatOutcome(o diffOutcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "code=%s", o.code)
	if o.dns != nil {
		fmt.Fprintf(&b, " dns=%v", o.dns)
	}
	if o.attrs != nil {
		fmt.Fprintf(&b, " attrs=%v", o.attrs)
	}
	if o.ext != nil {
		fmt.Fprintf(&b, " ext=%q", *o.ext)
	}
	return b.String()
}

// start389Oracle starts the pinned 389 DS container configured for the
// compared surface: backend userroot with the lab suffix (creates the
// suffix root), anonymous access off (native default), cleartext binds on
// the loopback LDAP lane (native leg sets AllowCleartextBind). It returns
// the host loopback LDAP address. The DM password is the fixture value.
func start389Oracle(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not on PATH")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("docker daemon not available")
	}
	refBytes, err := os.ReadFile("../../deploy/docker/dirsrv.digest")
	if err != nil {
		t.Fatalf("read dirsrv.digest: %v", err)
	}
	ref := strings.TrimSpace(string(refBytes))
	if !strings.Contains(ref, "@sha256:") {
		t.Fatalf("image ref is not a digest pin: %s", ref)
	}
	if err := exec.Command("docker", "image", "inspect", ref).Run(); err != nil {
		t.Skipf("pinned 389 image not present locally (%s); docker pull it to run the oracle", ref)
	}

	name := "labldap-diff-" + randID(t)
	args := []string{
		"run", "-d", "--name", name,
		"--label", "labldap.test=differential",
		"-e", "DS_DM_PASSWORD=" + diffDMFixturePassword,
		"-p", "127.0.0.1::3389",
		"-v", "/data",
		ref,
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, scrubSecret(string(out), diffDMFixturePassword))
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", name).Run()
	})

	addr := oracleHostPort(t, name)
	stageDsconfPassword(t, name)
	waitOracleReady(t, addr, name)

	// Backend + suffix root, then anonymous access off to match the native
	// default policy surface.
	runDsconf(t, name, "backend", "create",
		"--suffix", "dc=example,dc=test", "--be-name", "userroot", "--create-suffix")
	runDsconf(t, name, "config", "replace", "nsslapd-allow-anonymous-access=off")
	return addr
}

// stageDsconfPassword writes the DM fixture password to a container-local
// file so dsconf invocations never carry it on argv (AGENTS.md
// secret-handling rule).
func stageDsconfPassword(t *testing.T, name string) {
	t.Helper()
	stage := exec.Command("docker", "exec", "-i", name,
		"sh", "-c", "cat > /tmp/diff-dm.pw && chmod 600 /tmp/diff-dm.pw")
	stage.Stdin = strings.NewReader(diffDMFixturePassword + "\n")
	if out, err := stage.CombinedOutput(); err != nil {
		t.Fatalf("stage dm password file: %v\n%s", err, out)
	}
}

// dsconfArgs builds the argument vector for one in-container dsconf call.
func dsconfArgs(name string, args ...string) []string {
	return append([]string{"exec", name, "dsconf", "-D", "cn=Directory Manager", "-y", "/tmp/diff-dm.pw", "localhost"}, args...)
}

// runDsconf executes one dsconf command inside the oracle container.
func runDsconf(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command("docker", dsconfArgs(name, args...)...).CombinedOutput()
	if err != nil {
		logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
		t.Fatalf("dsconf %s: %v\n%s\nlogs:\n%s", strings.Join(args, " "), err,
			scrubSecret(string(out), diffDMFixturePassword),
			scrubSecret(string(logs), diffDMFixturePassword))
	}
}

// oracleHostPort resolves the published loopback port for 3389/tcp.
func oracleHostPort(t *testing.T, name string) string {
	t.Helper()
	out, err := exec.Command("docker", "port", name, "3389/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	// Output form: "127.0.0.1:49153" (possibly several lines).
	line := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	if _, _, err := net.SplitHostPort(line); err != nil {
		t.Fatalf("unexpected docker port output %q: %v", line, err)
	}
	return line
}

// waitOracleReady waits until both consumers of the oracle work:
//
//   - the published TCP port answers a real LDAP DM bind (a bare dial is
//     not enough — docker-proxy accepts before ns-slapd binds 3389), and
//   - the in-container dsconf path answers (ns-slapd serves the ldapi and
//     TCP listeners on its own schedule; dsconf must not race them).
//
// Readiness is defined by the exact commands the test will run, polled,
// rather than by proxy heuristics that can pass seconds early.
func waitOracleReady(t *testing.T, addr, name string) {
	t.Helper()
	codec := NewBERCodec(BERCodecOptions{})
	deadline := time.Now().Add(180 * time.Second)
	var bindOK, dsconfOK bool
	for time.Now().Before(deadline) && !(bindOK && dsconfOK) {
		if !bindOK {
			bindOK = probeOracleBind(codec, addr)
		}
		if !dsconfOK {
			dsconfOK = exec.Command("docker", dsconfArgs(name, "backend", "suffix", "list")...).Run() == nil
		}
		if !(bindOK && dsconfOK) {
			time.Sleep(500 * time.Millisecond)
		}
	}
	if bindOK && dsconfOK {
		return
	}
	logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
	t.Fatalf("389 oracle not ready (bind=%v dsconf=%v)\n%s", bindOK, dsconfOK,
		scrubSecret(string(logs), diffDMFixturePassword))
}

// probeOracleBind attempts one DM bind over the published TCP port.
func probeOracleBind(codec *BERCodec, addr string) bool {
	c, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	err = codec.WriteMessage(context.Background(), c, &Message{ID: 1,
		Op: &BindRequest{Version: 3, Name: "cn=Directory Manager", Password: []byte(diffDMFixturePassword)}})
	if err != nil {
		return false
	}
	m, err := codec.ReadMessage(context.Background(), c)
	if err != nil {
		return false
	}
	resp, ok := m.Op.(*BindResponse)
	return ok && resp.Result.Code == ResultSuccess
}

// randID returns a short random container-name suffix.
func randID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// scrubSecret removes the fixture password from process output before it
// reaches test logs.
func scrubSecret(s, secret string) string {
	return strings.ReplaceAll(s, secret, "[redacted]")
}
