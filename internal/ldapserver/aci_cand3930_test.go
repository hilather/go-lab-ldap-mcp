package ldapserver

import (
	"context"
	"slices"
	"testing"
)

// Oracle probes 30-34 (pinned 389 image f2851654, nsslapd-moddn-aci on;
// transcripts in test/parity/testdata/filter-attr-oracle-probes.txt) for
// resolved CAND-39 (moves need moddn on the new superior) and CAND-30
// (case-only renames respell the DN). B, D and E are probe 30's ou=src,
// ou=dst and ou=other; P and G are people and groups.
const (
	c39S = "dc=example,dc=test"
	c39B = "ou=src," + c39S
	c39D = "ou=dst," + c39S
	c39E = "ou=other," + c39S
	c39P = "ou=people," + c39S
	c39G = "ou=groups," + c39S
	c39N = "dc=example,dc=net"
)

// c3930Server is c3638Server plus probe 30's tree and an additional
// suffix. root evaluates every check as Directory Manager instead.
func c3930Server(t *testing.T, texts []string, root bool, plugins ...Plugin) (*ldapTestClient, Options) {
	t.Helper()
	eng, err := NewACIEngine(texts, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	subj := Subject{DN: mustDNA(t, c3638Subj)}
	if root {
		subj = Subject{DN: mustDNA(t, "cn=Directory Manager"), BypassACI: true}
	}
	opts := writeOptions(t, func(o *Options) {
		o.AdditionalSuffixes = []string{c39N}
		o.Plugins = plugins
		o.ACI = &FakeACI{Decide: func(ctx context.Context, tx ReadTx, check ACICheck) (bool, error) {
			check.Subject = subj
			return eng.Allowed(ctx, tx, check)
		}}
	})
	ou := func(dn, v string) *Entry {
		return NewEntry(dn, StringAttribute("objectClass", "top", "organizationalUnit"), StringAttribute("ou", v))
	}
	user := func(dn, v string) *Entry {
		return NewEntry(dn, StringAttribute("objectClass", "top", "person"), StringAttribute("uid", v), StringAttribute("cn", v), StringAttribute("sn", "S"))
	}
	err = opts.Store.Update(context.Background(), func(tx UpdateTx) error {
		for _, e := range []*Entry{
			ou(c39B, "src"), ou(c39D, "dst"), ou(c39E, "other"), ou("ou=sub,"+c39B, "sub"),
			ou("ou=team,"+c39P, "team"), ou("ou=t,"+c39B, "t"), ou("ou=MixCase,"+c39D, "MixCase"),
			NewEntry(c39N, StringAttribute("objectClass", "top", "domain")), ou("ou=far,"+c39N, "far"),
			user("uid=e,"+c39B, "e"), user("uid=d,"+c39D, "d"), user("uid=taken,"+c39D, "taken"),
			user("uid=p,"+c39P, "p"), user("uid=g,"+c39G, "g"), user("uid=n,ou=far,"+c39N, "n"),
		} {
			if err := tx.Add(context.Background(), e); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	_, addr := serveTestServerFrom(t, opts, nil)
	return dialTestClient(t, addr), opts
}

// c39Stored returns the stored DN spelling and uid values of dn.
func c39Stored(t *testing.T, opts Options, dn string) (string, []string) {
	t.Helper()
	var gotDN string
	var vals []string
	err := opts.Store.View(context.Background(), func(tx ReadTx) error {
		e, err := tx.Entry(context.Background(), mustDNA(t, dn))
		if err != nil {
			return err
		}
		gotDN = e.DN
		for _, v := range e.Values("uid") {
			vals = append(vals, string(v))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("read %s: %v", dn, err)
	}
	return gotDN, vals
}

var c39WU = c3638ACI(c39S, `(targetattr="uid || ou")`, "write")

func c39MV(dn, rdn, sup string, del bool) ModifyDNRequest {
	return ModifyDNRequest{DN: dn, NewRDN: rdn, NewSuperior: sup, DeleteOldRDN: del}
}

// TestModDNMovesMatchOracle: a move needs moddn on the new superior at
// entry level plus the rename gates on the old DN; no add or delete right
// (probes 26, 30, 33, 34).
func TestModDNMovesMatchOracle(t *testing.T) {
	t.Parallel()
	md := func(target, ta string) string { return c3638ACI(target, ta, "moddn") }
	BD := c39MV("uid=e,"+c39B, "uid=e", c39D, false)
	BDren := c39MV("uid=e,"+c39B, "uid=er", c39D, true)
	BDcn := c39MV("uid=e,"+c39B, "cn=ec", c39D, false)
	BE := c39MV("uid=e,"+c39B, "uid=e", c39E, false)
	Bsub := c39MV("uid=e,"+c39B, "uid=e", "ou=sub,"+c39B, false)
	DB := c39MV("uid=d,"+c39D, "uid=d", c39B, false)
	for _, tc := range []struct {
		name string
		acis []string
		req  ModifyDNRequest
		want ResultCode
	}{
		{"plain_S BD", []string{c39WU, md(c39S, "")}, BD, ResultSuccess},
		{"plain_S BDren", []string{c39WU, md(c39S, "")}, BDren, ResultSuccess},
		{"plain_S BDcn needs write cn", []string{c39WU, md(c39S, "")}, BDcn, ResultInsufficientAccessRights},
		{"plain_S BE", []string{c39WU, md(c39S, "")}, BE, ResultSuccess},
		{"plain_S Bsub", []string{c39WU, md(c39S, "")}, Bsub, ResultSuccess},
		{"plain_S DB", []string{c39WU, md(c39S, "")}, DB, ResultSuccess},
		{"plain_S_ta_cn BD", []string{c39WU, md(c39S, `(targetattr="cn")`)}, BD, ResultSuccess},
		{"plain_S_ta_notstar BD", []string{c39WU, md(c39S, `(targetattr!="*")`)}, BD, ResultSuccess},
		{"plain_B BD (source grant only)", []string{c39WU, md(c39B, "")}, BD, ResultInsufficientAccessRights},
		{"plain_B Bsub", []string{c39WU, md(c39B, "")}, Bsub, ResultSuccess},
		{"plain_B DB", []string{c39WU, md(c39B, "")}, DB, ResultSuccess},
		{"plain_D BD", []string{c39WU, md(c39D, "")}, BD, ResultSuccess},
		{"plain_D BE", []string{c39WU, md(c39D, "")}, BE, ResultInsufficientAccessRights},
		{"plain_D DB", []string{c39WU, md(c39D, "")}, DB, ResultInsufficientAccessRights},
		{"new DN only", []string{c39WU, c3638ACI("uid=e,"+c39D, "", "moddn")}, BD, ResultInsufficientAccessRights},
		{"S_deny_add_D", []string{c39WU, md(c39S, ""), c3638ACI(c39D, "", "DENYadd")}, BD, ResultSuccess},
		{"S_deny_del_B", []string{c39WU, md(c39S, ""), c3638ACI(c39B, "", "DENYdelete")}, BD, ResultSuccess},
		{"S_deny_moddn_D BD", []string{c39WU, md(c39S, ""), c3638ACI(c39D, "", "DENYmoddn")}, BD, ResultInsufficientAccessRights},
		{"S_deny_moddn_B BD", []string{c39WU, md(c39S, ""), c3638ACI(c39B, "", "DENYmoddn")}, BD, ResultSuccess},
		{"S_deny_moddn_B DB", []string{c39WU, md(c39S, ""), c3638ACI(c39B, "", "DENYmoddn")}, DB, ResultInsufficientAccessRights},
		{"deny moddn uid on D", []string{c39WU, md(c39S, ""), c3638ACI(c39D, `(targetattr="uid")`, "DENYmoddn")}, BD, ResultInsufficientAccessRights},
		{"deny moddn notstar on D", []string{c39WU, md(c39S, ""), c3638ACI(c39D, `(targetattr!="*")`, "DENYmoddn")}, BD, ResultInsufficientAccessRights},
		{"S_deny_write_B BD", []string{c39WU, md(c39S, ""), c3638ACI(c39B, "", "DENYwrite")}, BD, ResultInsufficientAccessRights},
		{"S_deny_write_B DB", []string{c39WU, md(c39S, ""), c3638ACI(c39B, "", "DENYwrite")}, DB, ResultSuccess},
		{"S_nowrite", []string{md(c39S, "")}, BD, ResultInsufficientAccessRights},
		{"S_writecn BDcn", []string{c3638ACI(c39S, `(targetattr="cn")`, "write"), md(c39S, "")}, BDcn, ResultSuccess},
		{"S_writecn BD", []string{c3638ACI(c39S, `(targetattr="cn")`, "write"), md(c39S, "")}, BD, ResultInsufficientAccessRights},
		{"S_addD without moddn", []string{c39WU, c3638ACI(c39D, "", "add")}, BD, ResultInsufficientAccessRights},
		{"w_uid only", []string{c39WU}, BD, ResultInsufficientAccessRights},
		{"write on source only", []string{c3638ACI(c39B, `(targetattr="uid || ou")`, "write"), md(c39S, "")}, BD, ResultSuccess},
		{"write on destination only", []string{c3638ACI(c39D, `(targetattr="uid || ou")`, "write"), md(c39S, "")}, BD, ResultInsufficientAccessRights},
		{"deny write uid on destination", []string{c39WU, md(c39S, ""), c3638ACI(c39D, `(targetattr="uid")`, "DENYwrite")}, BD, ResultSuccess},
		{"deny write uid on source", []string{c39WU, md(c39S, ""), c3638ACI(c39B, `(targetattr="uid")`, "DENYwrite")}, BD, ResultInsufficientAccessRights},
		{"taken before access", nil, c39MV("uid=e,"+c39B, "uid=taken", c39D, true), ResultEntryAlreadyExists},
		{"under itself before access", nil, c39MV("ou=t,"+c39B, "ou=t", "ou=t,"+c39B, false), ResultUnwillingToPerform},
		{"cross suffix, full grants", []string{c39WU, md(c39S, ""), md(c39N, ""), c3638ACI(c39N, `(targetattr="uid || ou")`, "write")}, c39MV("uid=e,"+c39B, "uid=e", "ou=far,"+c39N, false), ResultAffectsMultipleDSAs},
		{"cross suffix back", []string{c39WU, md(c39S, ""), md(c39N, ""), c3638ACI(c39N, `(targetattr="uid || ou")`, "write")}, c39MV("uid=n,ou=far,"+c39N, "uid=n", c39D, false), ResultAffectsMultipleDSAs},
		{"cross suffix, ghost, no grants", nil, c39MV("uid=ghost,"+c39B, "uid=ghost", "ou=far,"+c39N, false), ResultAffectsMultipleDSAs},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cl, _ := c3930Server(t, tc.acis, false)
			req := tc.req
			if res := roundTrip(t, cl, &req); res.Code != tc.want {
				t.Fatalf("got %v, want %d", res, tc.want)
			}
		})
	}
}

// TestModDNRuntimeLikeMatchesOracle: probe 30's rt_PG / rt_P rows, the
// runtime ACI shape with moddn added to the people and groups writes.
func TestModDNRuntimeLikeMatchesOracle(t *testing.T) {
	t.Parallel()
	w := func(target string) string {
		return c3638ACI(target, `(targetattr!="aci")`, "add,delete,write,read,search,compare,moddn")
	}
	read := c3638ACI(c39S, `(targetattr!="userPassword")`, "read,search,compare")
	PG := []string{w(c39P), w(c39G), read}
	Ponly := []string{w(c39P), read}
	for _, tc := range []struct {
		name string
		acis []string
		req  ModifyDNRequest
		want ResultCode
	}{
		{"rt_PG P->G", PG, c39MV("uid=p,"+c39P, "uid=p", c39G, false), ResultSuccess},
		{"rt_PG G->P", PG, c39MV("uid=g,"+c39G, "uid=g", c39P, false), ResultSuccess},
		{"rt_PG P->team", PG, c39MV("uid=p,"+c39P, "uid=p", "ou=team,"+c39P, false), ResultSuccess},
		{"rt_PG P->B", PG, c39MV("uid=p,"+c39P, "uid=p", c39B, false), ResultInsufficientAccessRights},
		{"rt_PG B->P", PG, c39MV("uid=e,"+c39B, "uid=e", c39P, false), ResultInsufficientAccessRights},
		{"rt_PG rename", PG, c39MV("uid=p,"+c39P, "uid=pr", "", true), ResultSuccess},
		{"rt_P P->G", Ponly, c39MV("uid=p,"+c39P, "uid=p", c39G, false), ResultInsufficientAccessRights},
		{"rt_P G->P", Ponly, c39MV("uid=g,"+c39G, "uid=g", c39P, false), ResultInsufficientAccessRights},
		{"rt_P P->team", Ponly, c39MV("uid=p,"+c39P, "uid=p", "ou=team,"+c39P, false), ResultSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cl, _ := c3930Server(t, tc.acis, false)
			req := tc.req
			if res := roundTrip(t, cl, &req); res.Code != tc.want {
				t.Fatalf("got %v, want %d", res, tc.want)
			}
		})
	}
}

// TestModDNExistenceMatchesOracle: a missing source or new superior is
// noSuchObject only for subjects holding moddn on that DN through an ACI
// whose targetattr covers an arbitrary attribute; else 50 (probes 30-34).
func TestModDNExistenceMatchesOracle(t *testing.T) {
	t.Parallel()
	md := func(target, ta string) string { return c3638ACI(target, ta, "moddn") }
	dmd := func(target, ta string) string { return c3638ACI(target, ta, "DENYmoddn") }
	gRen := c39MV("uid=ghost,"+c39B, "uid=ghostr", "", false)
	gMv := c39MV("uid=ghost,"+c39B, "uid=ghost", c39D, false)
	nosupS := c39MV("uid=e,"+c39B, "uid=e", "ou=nope,"+c39S, false)
	nosupD := c39MV("uid=e,"+c39B, "uid=e", "ou=nope,"+c39D, false)
	for _, tc := range []struct {
		name string
		acis []string
		want map[string]ResultCode
	}{
		{"m_S", []string{c39WU, md(c39S, "")}, map[string]ResultCode{"gRen": 32, "gMv": 32, "nosupS": 32, "nosupD": 32}},
		{"m_S_ta_cn", []string{c39WU, md(c39S, `(targetattr="cn")`)}, map[string]ResultCode{"gRen": 50, "gMv": 50, "nosupS": 50, "nosupD": 50}},
		{"m_S_ta_uid", []string{c39WU, md(c39S, `(targetattr="uid")`)}, map[string]ResultCode{"gRen": 50, "gMv": 50, "nosupS": 50}},
		{"m_S_ta_notaci", []string{c39WU, md(c39S, `(targetattr!="aci")`)}, map[string]ResultCode{"gMv": 32, "nosupS": 32}},
		{"m_S_ta_star", []string{c39WU, md(c39S, `(targetattr="*")`)}, map[string]ResultCode{"gMv": 32, "nosupS": 32}},
		{"m_S_ta_notstar", []string{c39WU, md(c39S, `(targetattr!="*")`)}, map[string]ResultCode{"gMv": 50, "nosupS": 50}},
		{"m_S_ta_notuid", []string{c39WU, md(c39S, `(targetattr!="uid")`)}, map[string]ResultCode{"gMv": 32, "nosupS": 32}},
		{"m_B", []string{c39WU, md(c39B, "")}, map[string]ResultCode{"gRen": 32, "gMv": 32, "nosupS": 50, "nosupD": 50}},
		{"m_D", []string{c39WU, md(c39D, "")}, map[string]ResultCode{"gRen": 50, "gMv": 50, "nosupS": 50, "nosupD": 32}},
		{"none", []string{c39WU}, map[string]ResultCode{"gRen": 50, "gMv": 50, "nosupS": 50, "nosupD": 50}},
		{"denyM_B", []string{c39WU, md(c39S, ""), dmd(c39B, "")}, map[string]ResultCode{"gRen": 50, "gMv": 50, "nosupS": 32, "nosupD": 32}},
		{"denyM_S", []string{c39WU, dmd(c39S, "")}, map[string]ResultCode{"gMv": 50, "nosupS": 50}},
		{"denyM_B_uid", []string{c39WU, md(c39S, ""), dmd(c39B, `(targetattr="uid")`)}, map[string]ResultCode{"gMv": 32}},
		{"denyM_B_notstar", []string{c39WU, md(c39S, ""), dmd(c39B, `(targetattr!="*")`)}, map[string]ResultCode{"gMv": 32}},
		{"denyM_B_star", []string{c39WU, md(c39S, ""), dmd(c39B, `(targetattr="*")`)}, map[string]ResultCode{"gMv": 50}},
		{"m_S_nowrite (superior before write)", []string{md(c39S, "")}, map[string]ResultCode{"gRen": 32, "nosupS": 32}},
		{"m_S_denywB", []string{c39WU, md(c39S, ""), c3638ACI(c39B, "", "DENYwrite")}, map[string]ResultCode{"gMv": 32, "nosupS": 32}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cl, _ := c3930Server(t, tc.acis, false)
			reqs := map[string]ModifyDNRequest{"gRen": gRen, "gMv": gMv, "nosupS": nosupS, "nosupD": nosupD}
			for col, want := range tc.want {
				req := reqs[col]
				if res := roundTrip(t, cl, &req); res.Code != want {
					t.Errorf("%s: got %v, want %d", col, res, want)
				}
			}
		})
	}
	t.Run("root", func(t *testing.T) {
		t.Parallel()
		cl, _ := c3930Server(t, nil, true)
		for col, req := range map[string]ModifyDNRequest{"gMv": gMv, "nosupS": nosupS} {
			if res := roundTrip(t, cl, &req); res.Code != ResultNoSuchObject {
				t.Errorf("%s: got %v, want noSuchObject", col, res)
			}
		}
	})
}

// TestModDNCaseOnlyMatchesOracle: a case-only rename succeeds with the
// same-parent rename gates and respells the DN (probes 30, 31, 33, 34).
func TestModDNCaseOnlyMatchesOracle(t *testing.T) {
	t.Parallel()
	md := c3638ACI(c39S, "", "moddn")
	for _, tc := range []struct {
		name string
		acis []string
		req  ModifyDNRequest
		want ResultCode
	}{
		{"w_uid", []string{c39WU}, c39MV("uid=e,"+c39B, "uid=E", "", true), ResultSuccess},
		{"S_writecn", []string{c3638ACI(c39S, `(targetattr="cn")`, "write"), md}, c39MV("uid=e,"+c39B, "uid=E", "", true), ResultInsufficientAccessRights},
		{"S_deny_write_B", []string{c39WU, md, c3638ACI(c39B, "", "DENYwrite")}, c39MV("uid=e,"+c39B, "uid=E", "", true), ResultInsufficientAccessRights},
		{"denyM_S, explicit superior", []string{c39WU, c3638ACI(c39S, "", "DENYmoddn")}, c39MV("uid=e,"+c39B, "uid=E", "ou=SRC,"+c39S, true), ResultSuccess},
		{"case plus move", []string{c39WU, md}, c39MV("uid=e,"+c39B, "uid=E", c39D, true), ResultSuccess},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cl, _ := c3930Server(t, tc.acis, false)
			req := tc.req
			if res := roundTrip(t, cl, &req); res.Code != tc.want {
				t.Fatalf("got %v, want %d", res, tc.want)
			}
		})
	}
}

// TestModDNSpellingMatchesOracle pins the resulting DN spelling and RDN
// values (probes 30, 31, 33, 34). Attribute types are lowercase on native
// (D37), so every row spells them lowercase.
func TestModDNSpellingMatchesOracle(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		req     ModifyDNRequest
		lookup  string
		wantDN  string
		wantUID []string
	}{
		{"case-only del0 keeps values", c39MV("uid=e,"+c39B, "uid=E", "", false), "uid=e," + c39B, "uid=E," + c39B, []string{"e"}},
		{"case-only del1 respells the value", c39MV("uid=e,"+c39B, "uid=E", "", true), "uid=e," + c39B, "uid=E," + c39B, []string{"E"}},
		{"explicit equal superior is ignored", c39MV("uid=e,"+c39B, "uid=e2", "ou=SRC,"+c39S, true), "uid=e2," + c39B, "uid=e2," + c39B, []string{"e2"}},
		{"request parent spelling is kept", c39MV("uid=e,ou=SRC,"+c39S, "uid=e2", "", true), "uid=e2," + c39B, "uid=e2,ou=SRC," + c39S, []string{"e2"}},
		{"same value via respelled parent", c39MV("uid=e,ou=SRC,"+c39S, "uid=e", "", true), "uid=e," + c39B, "uid=e,ou=SRC," + c39S, []string{"e"}},
		{"move takes the stored superior spelling", c39MV("uid=e,"+c39B, "uid=e", "ou=DST,"+c39S, false), "uid=e," + c39D, "uid=e," + c39D, []string{"e"}},
		{"move under a mixed-case superior", c39MV("uid=e,"+c39B, "uid=e", "ou=mixcase,"+c39D, false), "uid=e,ou=mixcase," + c39D, "uid=e,ou=MixCase," + c39D, []string{"e"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cl, opts := c3930Server(t, nil, true)
			req := tc.req
			if res := roundTrip(t, cl, &req); res.Code != ResultSuccess {
				t.Fatalf("got %v, want success", res)
			}
			dn, uids := c39Stored(t, opts, tc.lookup)
			if dn != tc.wantDN || !slices.Equal(uids, tc.wantUID) {
				t.Fatalf("stored %q %q, want %q %q", dn, uids, tc.wantDN, tc.wantUID)
			}
		})
	}
	t.Run("case-only subtree respells children", func(t *testing.T) {
		t.Parallel()
		cl, opts := c3930Server(t, nil, true)
		if res := roundTrip(t, cl, &ModifyDNRequest{DN: "ou=src," + c39S, NewRDN: "ou=SRC", DeleteOldRDN: true}); res.Code != ResultSuccess {
			t.Fatalf("got %v", res)
		}
		if dn, _ := c39Stored(t, opts, "uid=e,"+c39B); dn != "uid=e,ou=SRC,"+c39S {
			t.Fatalf("child DN %q, want respelled parent", dn)
		}
		if dn, _ := c39Stored(t, opts, "ou=sub,"+c39B); dn != "ou=sub,ou=SRC,"+c39S {
			t.Fatalf("child DN %q, want respelled parent", dn)
		}
	})
	t.Run("non-ASCII case-only", func(t *testing.T) {
		t.Parallel()
		cl, opts := c3930Server(t, nil, true)
		if res := roundTrip(t, cl, &ModifyDNRequest{DN: "ou=t," + c39B, NewRDN: "ou=\u0130t", DeleteOldRDN: true}); res.Code != ResultSuccess {
			t.Fatalf("rename to dotted capital I: %v", res)
		}
		// strings.ToLower("\u0130") is longer than "\u0130"; the subtree
		// must still resolve under the new key.
		if dn, _ := c39Stored(t, opts, "ou=\u0130t,"+c39B); dn != "ou=\u0130t,"+c39B {
			t.Fatalf("stored %q", dn)
		}
	})
}

// TestModDNPluginsMatchOracle: refint and memberOf after moves and
// case-only renames (probes 30, 31, 33, 34).
func TestModDNPluginsMatchOracle(t *testing.T) {
	t.Parallel()
	mo, err := NewMemberOfPlugin(c39S, false, c39N)
	if err != nil {
		t.Fatal(err)
	}
	ri, err := NewRefIntPlugin(c39S, c39N)
	if err != nil {
		t.Fatal(err)
	}
	cl, opts := c3930Server(t, nil, true, mo, ri)
	add := func(e *Entry) {
		t.Helper()
		if res := roundTrip(t, cl, &AddRequest{DN: e.DN, Attributes: e.Attributes}); res.Code != ResultSuccess {
			t.Fatalf("add %s: %v", e.DN, res)
		}
	}
	values := func(dn, attr string) []string {
		t.Helper()
		var out []string
		err := opts.Store.View(context.Background(), func(tx ReadTx) error {
			e, err := tx.Entry(context.Background(), mustDNA(t, dn))
			if err != nil {
				return err
			}
			for _, v := range e.Values(attr) {
				out = append(out, string(v))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("read %s: %v", dn, err)
		}
		slices.Sort(out)
		return out
	}
	mv := func(dn, rdn, sup string) {
		t.Helper()
		if res := roundTrip(t, cl, &ModifyDNRequest{DN: dn, NewRDN: rdn, NewSuperior: sup, DeleteOldRDN: true}); res.Code != ResultSuccess {
			t.Fatalf("moddn %s: %v", dn, res)
		}
	}
	group := func(dn, cn string, members ...string) *Entry {
		return NewEntry(dn, StringAttribute("objectClass", "top", "groupOfNames"), StringAttribute("cn", cn), StringAttribute("member", members...))
	}
	unit := "ou=unit," + c39B
	add(NewEntry(unit, StringAttribute("objectClass", "top", "organizationalUnit"), StringAttribute("ou", "unit")))
	add(NewEntry("uid=inner,"+unit, StringAttribute("objectClass", "top", "person"), StringAttribute("uid", "inner"), StringAttribute("cn", "i"), StringAttribute("sn", "S")))
	add(group("cn=ingrp,"+unit, "ingrp", "uid=inner,"+unit))
	add(group("cn=outgrp,"+c39G, "outgrp", "uid=inner,"+unit))

	mv(unit, "ou=unit", c39D)
	moved := "ou=unit," + c39D
	if got, want := values("cn=outgrp,"+c39G, "member"), []string{"uid=inner," + moved}; !slices.Equal(got, want) {
		t.Errorf("outgrp member = %q, want %q", got, want)
	}
	if got, want := values("cn=ingrp,"+moved, "member"), []string{"uid=inner," + moved}; !slices.Equal(got, want) {
		t.Errorf("ingrp member = %q, want %q", got, want)
	}
	if got, want := values("uid=inner,"+moved, "memberOf"), []string{"cn=ingrp," + moved, "cn=outgrp," + c39G}; !slices.Equal(got, want) {
		t.Errorf("inner memberOf = %q, want %q", got, want)
	}

	// Moving a group respells its members' memberOf.
	add(group("cn=mob,"+c39P, "mob", "uid=p,"+c39P))
	mv("cn=mob,"+c39P, "cn=mob", c39G)
	if got, want := values("uid=p,"+c39P, "memberOf"), []string{"cn=mob," + c39G}; !slices.Equal(got, want) {
		t.Errorf("memberOf after group move = %q, want %q", got, want)
	}
	// A case-only group rename leaves memberOf as written, and a case-only
	// member rename leaves member values as written.
	mv("cn=mob,"+c39G, "cn=Mob", "")
	if got, want := values("uid=p,"+c39P, "memberOf"), []string{"cn=mob," + c39G}; !slices.Equal(got, want) {
		t.Errorf("memberOf after case-only group rename = %q, want %q", got, want)
	}
	mv("uid=p,"+c39P, "uid=P", "")
	if got, want := values("cn=mob,"+c39G, "member"), []string{"uid=p," + c39P}; !slices.Equal(got, want) {
		t.Errorf("member after case-only member rename = %q, want %q", got, want)
	}
	if got, want := values("uid=p,"+c39P, "memberOf"), []string{"cn=mob," + c39G}; !slices.Equal(got, want) {
		t.Errorf("memberOf after case-only member rename = %q, want %q", got, want)
	}
}
