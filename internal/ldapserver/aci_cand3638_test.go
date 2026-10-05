package ldapserver

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

const (
	c3638People = "ou=people,dc=example,dc=test"
	c3638Alice  = "uid=alice," + c3638People
	c3638Subj   = "uid=p36,ou=people,dc=example,dc=test"
)

// c3638Server serves the searchOptions tree with the real ACI engine over
// texts, evaluating every check as the non-root subject c3638Subj (the
// test client itself stays anonymous on the wire).
func c3638Server(t *testing.T, texts []string) (*ldapTestClient, Options) {
	t.Helper()
	eng, err := NewACIEngine(texts, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	subj := Subject{DN: mustDNA(t, c3638Subj)}
	opts := writeOptions(t, func(o *Options) {
		o.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
			check.Subject = subj
			return eng.Allowed(ctx, tx, check)
		}}
	})
	_, addr := serveTestServerFrom(t, opts, nil)
	return dialTestClient(t, addr), opts
}

// c3638ACI builds one probe-style ACI for c3638Subj. perm "DENYx" is a deny.
func c3638ACI(target, targetattr, perm string) string {
	rule := "allow (" + perm + ")"
	if p, ok := strings.CutPrefix(perm, "DENY"); ok {
		rule = "deny (" + p + ")"
	}
	return `(target="ldap:///` + target + `")` + targetattr + `(version 3.0; acl "labldap:p36"; ` + rule + ` userdn="ldap:///` + c3638Subj + `";)`
}

// TestModifyDNRenameMatchesOracle replays oracle probes 25-28 (resolved
// CAND-36): a same-parent rename is blocked at entry level only by a
// deny-write ACI without targetattr on the old DN; the new RDN attribute
// (and the old one with deleteoldrdn) needs write on the old DN; no add
// right is needed.
func TestModifyDNRenameMatchesOracle(t *testing.T) {
	t.Parallel()
	P := c3638People
	newDN := "uid=alicex," + P
	type op struct {
		newRDN string
		del    bool
	}
	renUID1, renUID0, renCN0 := op{"uid=alicex", true}, op{"uid=alicex", false}, op{"cn=alice new", false}
	for _, tc := range []struct {
		name string
		acis []string
		op   op
		want ResultCode
	}{
		{"write uid del1", []string{c3638ACI(P, `(targetattr="uid")`, "write")}, renUID1, ResultSuccess},
		{"write uid del0", []string{c3638ACI(P, `(targetattr="uid")`, "write")}, renUID0, ResultSuccess},
		{"write uid to cn", []string{c3638ACI(P, `(targetattr="uid")`, "write")}, renCN0, ResultInsufficientAccessRights},
		{"write cn uid rename", []string{c3638ACI(P, `(targetattr="cn")`, "write")}, renUID0, ResultInsufficientAccessRights},
		{"write cn to cn del0", []string{c3638ACI(P, `(targetattr="cn")`, "write")}, renCN0, ResultSuccess},
		{"write star deny description", []string{c3638ACI(P, `(targetattr="*")`, "write"), c3638ACI(P, `(targetattr="description")`, "DENYwrite")}, renUID1, ResultSuccess},
		{"write star deny description;lang-en", []string{c3638ACI(P, `(targetattr="*")`, "write"), c3638ACI(P, `(targetattr="description;lang-en")`, "DENYwrite")}, renUID1, ResultSuccess},
		{"write star deny uid", []string{c3638ACI(P, `(targetattr="*")`, "write"), c3638ACI(P, `(targetattr="uid")`, "DENYwrite")}, renUID1, ResultInsufficientAccessRights},
		{"write star deny uid to cn del0", []string{c3638ACI(P, `(targetattr="*")`, "write"), c3638ACI(P, `(targetattr="uid")`, "DENYwrite")}, renCN0, ResultSuccess},
		{"write without targetattr", []string{c3638ACI(P, ``, "write")}, renUID1, ResultInsufficientAccessRights},
		{"write uid deny write without targetattr", []string{c3638ACI(P, `(targetattr="uid")`, "write"), c3638ACI(P, ``, "DENYwrite")}, renUID1, ResultInsufficientAccessRights},
		{"write uid deny add without targetattr", []string{c3638ACI(P, `(targetattr="uid")`, "write"), c3638ACI(P, ``, "DENYadd")}, renUID1, ResultSuccess},
		{"write uid;x-test", []string{c3638ACI(P, `(targetattr="uid;x-test")`, "write")}, renUID1, ResultInsufficientAccessRights},
		{"write cn deny targetattr!=cn", []string{c3638ACI(P, `(targetattr="cn")`, "write"), c3638ACI(P, `(targetattr!="cn")`, "DENYwrite")}, renCN0, ResultSuccess},
		{"write cn deny targetattr!=*", []string{c3638ACI(P, `(targetattr="cn")`, "write"), c3638ACI(P, `(targetattr!="*")`, "DENYwrite")}, renCN0, ResultSuccess},
		{"write cn deny targetattr=*", []string{c3638ACI(P, `(targetattr="cn")`, "write"), c3638ACI(P, `(targetattr="*")`, "DENYwrite")}, renCN0, ResultInsufficientAccessRights},
		{"write uid || cn to cn del1", []string{c3638ACI(P, `(targetattr="uid || cn")`, "write")}, op{"cn=alice new", true}, ResultSuccess},
		// Probe 27: only ACIs covering the old DN count.
		{"allow on old DN only", []string{c3638ACI(c3638Alice, `(targetattr="uid")`, "write")}, renUID1, ResultSuccess},
		{"allow on new DN only", []string{c3638ACI(newDN, `(targetattr="uid")`, "write")}, renUID1, ResultInsufficientAccessRights},
		{"deny without targetattr on old DN", []string{c3638ACI(P, `(targetattr="uid")`, "write"), c3638ACI(c3638Alice, ``, "DENYwrite")}, renUID1, ResultInsufficientAccessRights},
		{"deny without targetattr on new DN", []string{c3638ACI(P, `(targetattr="uid")`, "write"), c3638ACI(newDN, ``, "DENYwrite")}, renUID1, ResultSuccess},
		{"deny uid on new DN", []string{c3638ACI(P, `(targetattr="uid")`, "write"), c3638ACI(newDN, `(targetattr="uid")`, "DENYwrite")}, renUID1, ResultSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cl, _ := c3638Server(t, tc.acis)
			res := roundTrip(t, cl, &ModifyDNRequest{DN: c3638Alice, NewRDN: tc.op.newRDN, DeleteOldRDN: tc.op.del})
			if res.Code != tc.want {
				t.Fatalf("got %v, oracle %d", res, tc.want)
			}
		})
	}
}

// TestModifyDNOrderingMatchesOracle pins probes 27-29: for a non-root
// subject a missing source is 50 (even with write *), and a rename onto an
// existing DN (68) or beneath itself (53) is reported before any access
// check, for subjects without any right too.
func TestModifyDNOrderingMatchesOracle(t *testing.T) {
	t.Parallel()
	P := c3638People
	star := []string{c3638ACI("dc=example,dc=test", `(targetattr="*")`, "write")}
	for _, tc := range []struct {
		name string
		acis []string
		req  ModifyDNRequest
		want ResultCode
	}{
		{"missing source with write *", star, ModifyDNRequest{DN: "uid=ghost," + P, NewRDN: "uid=ghost2", DeleteOldRDN: true}, ResultInsufficientAccessRights},
		{"missing source move with write *", star, ModifyDNRequest{DN: "uid=ghost," + P, NewRDN: "uid=ghost", NewSuperior: "ou=groups,dc=example,dc=test"}, ResultInsufficientAccessRights},
		{"onto existing without rights", nil, ModifyDNRequest{DN: c3638Alice, NewRDN: "uid=bob", DeleteOldRDN: true}, ResultEntryAlreadyExists},
		{"beneath itself without rights", nil, ModifyDNRequest{DN: P, NewRDN: "ou=people", NewSuperior: c3638Alice}, ResultUnwillingToPerform},
		{"plain rename without rights", nil, ModifyDNRequest{DN: c3638Alice, NewRDN: "uid=alicex", DeleteOldRDN: true}, ResultInsufficientAccessRights},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cl, _ := c3638Server(t, tc.acis)
			req := tc.req
			if res := roundTrip(t, cl, &req); res.Code != tc.want {
				t.Fatalf("got %v, oracle %d", res, tc.want)
			}
		})
	}
}

// TestModifyDNMissingSourceAsRoot: Directory Manager still gets 32.
func TestModifyDNMissingSourceAsRoot(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, func(o *Options) {
		o.AllowCleartextBind = true
		o.DirectoryManager = dmIdentity("dm-fixture-password")
		o.ACI = &FakeACI{Decide: func(context.Context, ReadTx, ACICheck) (bool, error) { return false, nil }}
	})
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	if res := bindResult(t, cl, "cn=Directory Manager", "dm-fixture-password"); res.Code != ResultSuccess {
		t.Fatalf("dm bind = %v", res)
	}
	if res := roundTrip(t, cl, &ModifyDNRequest{DN: "uid=ghost," + c3638People, NewRDN: "uid=x"}); res.Code != ResultNoSuchObject {
		t.Fatalf("root missing moddn = %v, want noSuchObject", res)
	}
}

// TestModifyDNNoOpRename pins probe 28: renaming an entry to its own DN is
// success (it was 68), updates modifyTimestamp, keeps value order, and
// still needs write on the RDN attribute.
func TestModifyDNNoOpRename(t *testing.T) {
	t.Parallel()
	P := c3638People
	for _, tc := range []struct {
		name string
		acis []string
		req  ModifyDNRequest
		want ResultCode
	}{
		{"write uid, newSuperior, del0", []string{c3638ACI(P, `(targetattr="uid")`, "write")}, ModifyDNRequest{DN: c3638Alice, NewRDN: "uid=alice", NewSuperior: P}, ResultSuccess},
		{"write uid, del1", []string{c3638ACI(P, `(targetattr="uid")`, "write")}, ModifyDNRequest{DN: c3638Alice, NewRDN: "uid=alice", DeleteOldRDN: true}, ResultSuccess},
		{"no write (inferred)", []string{c3638ACI(P, `(targetattr="cn")`, "write")}, ModifyDNRequest{DN: c3638Alice, NewRDN: "uid=alice"}, ResultInsufficientAccessRights},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cl, opts := c3638Server(t, tc.acis)
			ctx := context.Background()
			if err := opts.Store.Update(ctx, func(tx UpdateTx) error {
				e, err := tx.Entry(ctx, mustDNA(t, c3638Alice))
				if err != nil {
					return err
				}
				e.Attributes = upsertValue(e, "uid", []byte("alice-second"))
				return tx.Replace(ctx, e)
			}); err != nil {
				t.Fatal(err)
			}
			req := tc.req
			if res := roundTrip(t, cl, &req); res.Code != tc.want {
				t.Fatalf("got %v, want %d", res, tc.want)
			}
			e, err := fetchEntry(t, opts, c3638Alice)
			if err != nil {
				t.Fatal(err)
			}
			got := e.Values("uid")
			if len(got) != 2 || string(got[0]) != "alice" || string(got[1]) != "alice-second" {
				t.Fatalf("uid = %q, want [alice alice-second] in order", got)
			}
			if stamped := len(e.Values("modifyTimestamp")) == 1; stamped != (tc.want == ResultSuccess) {
				t.Fatalf("modifyTimestamp present = %v", stamped)
			}
		})
	}
}

// TestEntryDenyOnlyFailsClosed: an evaluation error on the rename entry
// gate denies the rename.
func TestEntryDenyOnlyFailsClosed(t *testing.T) {
	t.Parallel()
	opts := writeOptions(t, func(o *Options) {
		o.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
			if check.EntryDenyOnly {
				return true, errors.New("group read failed")
			}
			return true, nil
		}}
	})
	_, addr := serveTestServerFrom(t, opts, nil)
	cl := dialTestClient(t, addr)
	if res := roundTrip(t, cl, &ModifyDNRequest{DN: c3638Alice, NewRDN: "uid=alicex", DeleteOldRDN: true}); res.Code != ResultInsufficientAccessRights {
		t.Fatalf("got %v, want insufficientAccessRights", res)
	}
}

// TestEntryDenyOnlySelectsDenyWithoutTargetattr checks the evaluator mode.
func TestEntryDenyOnlySelectsDenyWithoutTargetattr(t *testing.T) {
	t.Parallel()
	alice := mustDNA(t, c3638Alice)
	subj := Subject{DN: mustDNA(t, c3638Subj)}
	for _, tc := range []struct {
		acis []string
		want bool
	}{
		{nil, true},
		{[]string{c3638ACI(c3638People, ``, "DENYwrite")}, false},
		{[]string{c3638ACI(c3638People, `(targetattr="*")`, "DENYwrite")}, true},
		{[]string{c3638ACI(c3638People, `(targetattr!="*")`, "DENYwrite")}, true},
		{[]string{c3638ACI(c3638People, `(targetattr="uid")`, "DENYwrite")}, true},
		{[]string{c3638ACI(c3638People, ``, "DENYadd")}, true},
		{[]string{c3638ACI(c3638People, ``, "write")}, true},
		{[]string{c3638ACI("ou=groups,dc=example,dc=test", ``, "DENYwrite")}, true},
	} {
		eng, err := NewACIEngine(tc.acis, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		got, err := eng.Allowed(context.Background(), nil, ACICheck{Subject: subj, Target: alice, Perm: PermWrite, EntryDenyOnly: true})
		if err != nil || got != tc.want {
			t.Errorf("%v: got %v (%v), want %v", tc.acis, got, err, tc.want)
		}
	}
}

// TestTargetAttrStarListsMatchOracle pins probes 25-26 (resolved CAND-37):
// 389 accepts "*" after != and inside lists; a negated star list covers no
// attribute, a positive one every attribute, and entry-level add/delete
// checks still apply the ACI.
func TestTargetAttrStarListsMatchOracle(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		clause   string
		mode     ACITargetAttrModeA
		coversSN bool
	}{
		{`(targetattr!="*")`, ACITargetAttrDenyA, false},
		{`(targetattr!="* || sn")`, ACITargetAttrDenyA, false},
		{`(targetattr="* || sn")`, ACITargetAttrAllA, true},
		{`(targetattr="*")`, ACITargetAttrAllA, true},
	} {
		p, err := ParseACITextA(`(target="ldap:///dc=example,dc=test")` + tc.clause + `(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`)
		if err != nil {
			t.Fatalf("%s: %v", tc.clause, err)
		}
		if p.AttrMode != tc.mode || p.TargetsAttr("sn", nil) != tc.coversSN || p.TargetsAttr("uid", []string{"x-test"}) != tc.coversSN {
			t.Errorf("%s: mode %v, covers sn %v", tc.clause, p.AttrMode, p.TargetsAttr("sn", nil))
		}
	}
	subj := Subject{DN: mustDNA(t, c3638Subj)}
	target := mustDNA(t, "uid=new,"+c3638People)
	for _, tc := range []struct {
		acis []string
		perm Permission
		attr string
		want bool
	}{
		{[]string{c3638ACI(c3638People, `(targetattr!="*")`, "add,delete")}, PermAdd, "", true},
		{[]string{c3638ACI(c3638People, `(targetattr!="*")`, "add,delete")}, PermDelete, "", true},
		{[]string{c3638ACI(c3638People, `(targetattr="*")`, "add,delete"), c3638ACI(c3638People, `(targetattr!="*")`, "DENYadd,delete")}, PermAdd, "", false},
		{[]string{c3638ACI(c3638People, `(targetattr!="*")`, "read,search,compare")}, PermRead, "sn", false},
		{[]string{c3638ACI(c3638People, `(targetattr="*")`, "read"), c3638ACI(c3638People, `(targetattr!="*")`, "DENYread")}, PermRead, "sn", true},
		{[]string{c3638ACI(c3638People, `(targetattr!="*")`, "write")}, PermWrite, "description", false},
	} {
		eng, err := NewACIEngine(tc.acis, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		got, err := eng.Allowed(context.Background(), nil, ACICheck{Subject: subj, Target: target, Attribute: tc.attr, Perm: tc.perm})
		if err != nil || got != tc.want {
			t.Errorf("%v %s %q: got %v (%v), oracle %v", tc.acis, tc.perm, tc.attr, got, err, tc.want)
		}
	}
}

// TestAbsoluteFilterRejectedMatchesOracle pins probes 19, 25, 26, 28, 29
// (resolved CAND-38): any filter holding (&) or (|) gets protocolError(2)
// "Bad search filter" for every base, before controls, and the connection
// stays usable.
func TestAbsoluteFilterRejectedMatchesOracle(t *testing.T) {
	t.Parallel()
	_, addr := serveTestServerFrom(t, searchOptions(t, nil), nil)
	cl := dialTestClient(t, addr)
	crit := Control{OID: "1.3.6.1.4.1.99999.1", Critical: true}
	for _, tc := range []struct {
		base, filter string
		ctrls        []Control
	}{
		{"dc=example,dc=test", "(&)", nil},
		{"dc=example,dc=test", "(|)", nil},
		{"dc=example,dc=test", "(!(&))", nil},
		{"dc=example,dc=test", "(!(|))", nil},
		{"dc=example,dc=test", "(&(uid=alice)(&))", nil},
		{"dc=example,dc=test", "(|(uid=alice)(|))", nil},
		{"dc=example,dc=test", "(&(uid=alice)(|(&)))", nil},
		{"", "(&)", nil},
		{"cn=schema", "(|)", nil},
		{"not a dn", "(&)", nil},
		{"uid=ghost,dc=example,dc=test", "(&)", nil},
		{"dc=example,dc=test", "(&)", []Control{crit}},
	} {
		_, done, _ := searchFull(t, cl, &SearchRequest{BaseDN: tc.base, Scope: ScopeWholeSubtree, Filter: parseTestFilter(t, tc.filter), Attributes: []string{"1.1"}}, tc.ctrls...)
		if done.Result.Code != ResultProtocolError || done.Result.DiagnosticMessage != "Bad search filter" {
			t.Errorf("base %q %s: %v, oracle protocolError(2) Bad search filter", tc.base, tc.filter, done.Result)
		}
	}
	entries, done, _ := searchFull(t, cl, &SearchRequest{BaseDN: c3638Alice, Scope: ScopeBaseObject, Filter: parseTestFilter(t, "(uid=alice)"), Attributes: []string{"1.1"}})
	if done.Result.Code != ResultSuccess || len(entries) != 1 {
		t.Fatalf("connection not usable after rejections: %v, %d entries", done.Result, len(entries))
	}
	// Leaf-only nesting is not absolute.
	for _, f := range []string{"(&(uid=alice)(!(uid=x)))", "(|(uid=alice)(&(uid=alice)(!(cn=x))))", "(!(!(uid=alice)))"} {
		entries, done, _ := searchFull(t, cl, &SearchRequest{BaseDN: c3638Alice, Scope: ScopeBaseObject, Filter: parseTestFilter(t, f), Attributes: []string{"1.1"}})
		if done.Result.Code != ResultSuccess || len(entries) != 1 {
			t.Errorf("leaf-only %s: %v, %d entries, want success with alice", f, done.Result, len(entries))
		}
	}
	_, done, _ = searchFull(t, cl, &SearchRequest{BaseDN: c3638Alice, Scope: ScopeBaseObject, Filter: parseTestFilter(t, "(uid=alice)")}, crit)
	if done.Result.Code != ResultUnavailableCriticalExtension {
		t.Fatalf("leaf filter with critical unknown control = %v, want 12", done.Result)
	}
}

// TestMaxACIAttrsInSync keeps the compiler's list bound equal to the
// parser's.
func TestMaxACIAttrsInSync(t *testing.T) {
	if config.MaxACIAttrs != aciMaxAttrsA {
		t.Fatalf("config.MaxACIAttrs = %d, aciMaxAttrsA = %d", config.MaxACIAttrs, aciMaxAttrsA)
	}
}
