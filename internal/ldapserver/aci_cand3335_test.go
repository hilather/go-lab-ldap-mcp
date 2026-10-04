package ldapserver

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Oracle probes 16 and 18 (test/parity/testdata/filter-attr-oracle-probes.txt)
// pin targetattr options (resolved CAND-34) and 389's lack of an entry-level
// search check (resolved CAND-35). The tests below replay every filter and
// compare row of those transcripts for the subjects in cand3335ACIs.

const cand3335Base = "ou=probe-fattr,dc=example,dc=test"

const rscPerms = "read,search,compare"

// cand3335ACIs mirrors the probe scripts' subject -> ACI tables; a "DENY"
// prefix makes a deny rule, an empty targetattr omits the clause.
var cand3335ACIs = map[string][][2]string{
	// probe 16
	"t_uidopt":           {{`(targetattr="uid;x-test")`, rscPerms}},
	"t_descopt":          {{`(targetattr="description;lang-en")`, rscPerms}, {`(targetattr="objectClass || sn")`, "read,search"}},
	"d_uidopt":           {{`(targetattr="*")`, rscPerms}, {`(targetattr="uid;x-test")`, "DENY" + rscPerms}},
	"e_deny_noattr":      {{`(targetattr="*")`, rscPerms}, {``, "DENYsearch"}},
	"e_deny_star":        {{`(targetattr="*")`, rscPerms}, {`(targetattr="*")`, "DENYsearch"}},
	"e_deny_notpw":       {{`(targetattr="*")`, rscPerms}, {`(targetattr!="userPassword")`, "DENYsearch"}},
	"e_deny_pwsn":        {{`(targetattr="*")`, rscPerms}, {`(targetattr="userPassword || sn")`, "DENYsearch"}},
	"e_deny_readstar":    {{`(targetattr="*")`, "search"}, {`(targetattr="*")`, "DENYread"}},
	"e_allow_noattr":     {{``, rscPerms}},
	"e_allow_noattr_uid": {{``, rscPerms}, {`(targetattr="uid")`, "read,search"}},
	// probe 18
	"t_deny_uidopt": {{`(targetattr!="uid;x-test")`, rscPerms}},
	"t_uidsemi":     {{`(targetattr="uid;")`, rscPerms}},
}

func cand3335Entries() map[string]*Entry {
	oc := StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
	base := func(u string, extra ...Attribute) *Entry {
		return NewEntry("uid="+u+","+cand3335Base, append([]Attribute{oc, StringAttribute("uid", u), StringAttribute("cn", u), StringAttribute("sn", "S")}, extra...)...)
	}
	return map[string]*Entry{
		"fa_alice": base("fa_alice"),
		"fa_bob": base("fa_bob", StringAttribute("userPassword", "x"), StringAttribute("uid;x-test", "bobtag"),
			StringAttribute("description;lang-en", "hello")),
		"fa_carol": base("fa_carol", StringAttribute("description;lang-en;x-foo", "multi"), StringAttribute("uid;x-test;x-two", "two")),
	}
}

func cand3335Server(t *testing.T) *Server { return probeACIServer(t, cand3335ACIs) }

func probeACIServer(t *testing.T, table map[string][][2]string) *Server {
	t.Helper()
	var texts []string
	for subj, acis := range table {
		for i, a := range acis {
			rule := "allow (" + a[1] + ")"
			if p, ok := strings.CutPrefix(a[1], "DENY"); ok {
				rule = "deny (" + p + ")"
			}
			texts = append(texts, `(target="ldap:///`+cand3335Base+`")`+a[0]+`(version 3.0; acl "labldap:`+subj+`-`+string(rune('0'+i))+`"; `+rule+` userdn="ldap:///uid=`+subj+`,ou=people,dc=example,dc=test";)`)
		}
	}
	opts := testOptions()
	opts.Schema = standardSchemaT(t)
	opts.ACI = nil
	opts.ACITexts = texts
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// oracleSection returns the output lines of "===== probe <n> =====".
func oracleSection(t *testing.T, n string) []string {
	t.Helper()
	b, err := os.ReadFile("../../test/parity/testdata/filter-attr-oracle-probes.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, rest, ok := strings.Cut(string(b), "\n===== probe "+n+" =====\n")
	if !ok {
		t.Fatalf("probe %s not in transcript", n)
	}
	body, _, _ := strings.Cut(rest, "\n=====")
	return strings.Split(body, "\n")
}

var (
	oracleFilterRowRe  = regexp.MustCompile(`^(\w+)\s+(\(\S*\))\s+rc=0 \[(.*?)\]\s*$`)
	oracleCompareRowRe = regexp.MustCompile(`^(\w+)\s+COMPARE fa_bob (\S+):(\S+) rc=(\d+)`)
)

func TestTargetAttrOptionsAndEntryLevelSearchMatchOracle(t *testing.T) {
	t.Parallel()
	rows, compares := replayOracleRows(t, []string{"16", "18"}, cand3335ACIs, cand3335Entries())
	if rows < 200 || compares < 50 {
		t.Fatalf("replayed %d filter and %d compare rows; transcript format changed?", rows, compares)
	}
}

// TestTargetAttrOptionsMatchProbe12 replays probe 12 (its own ACI table and
// seed: no userPassword, carol without uid;x-test;x-two).
func TestTargetAttrOptionsMatchProbe12(t *testing.T) {
	t.Parallel()
	u := [2]string{`(targetattr="userid")`, rscPerms}
	table := map[string][][2]string{
		"p_userid":      {u},
		"p_userid_sn":   {u, {`(targetattr="sn")`, rscPerms}},
		"t_uidopt":      {{`(targetattr="uid;x-test")`, rscPerms}},
		"t_descopt":     {{`(targetattr="description;lang-en")`, rscPerms}, {`(targetattr="sn")`, "read"}},
		"t_deny_uidopt": {{`(targetattr!="uid;x-test")`, rscPerms}},
	}
	entries := cand3335Entries()
	oc := StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
	entries["fa_bob"] = NewEntry("uid=fa_bob,"+cand3335Base, oc, StringAttribute("uid", "fa_bob"), StringAttribute("cn", "fa_bob"), StringAttribute("sn", "S"),
		StringAttribute("uid;x-test", "bobtag"), StringAttribute("description;lang-en", "hello"))
	entries["fa_carol"] = NewEntry("uid=fa_carol,"+cand3335Base, oc, StringAttribute("uid", "fa_carol"), StringAttribute("cn", "fa_carol"), StringAttribute("sn", "S"),
		StringAttribute("description;lang-en;x-foo", "multi"))
	if rows, _ := replayOracleRows(t, []string{"12"}, table, entries); rows < 30 {
		t.Fatalf("replayed %d rows", rows)
	}
}

// replayOracleRows checks every one-level filter row and fa_bob compare row
// of the given probe transcripts for the subjects in table.
func replayOracleRows(t *testing.T, probes []string, table map[string][][2]string, entries map[string]*Entry) (rows, compares int) {
	t.Helper()
	srv := probeACIServer(t, table)
	ctx := context.Background()
	for _, probe := range probes {
		for _, line := range oracleSection(t, probe) {
			if m := oracleFilterRowRe.FindStringSubmatch(line); m != nil {
				if _, ok := table[m[1]]; !ok {
					continue
				}
				want := strings.NewReplacer("'", "", " ", "", "uid=", "").Replace(m[3])
				f := parseTestFilter(t, m[2])
				s := Subject{DN: mustDNA(t, "uid="+m[1]+",ou=people,dc=example,dc=test")}
				var got string
				if err := srv.opts.Store.View(ctx, func(tx ReadTx) error {
					got = matchingNames(t, entries, func(e *Entry) bool {
						return srv.searchResultVisible(ctx, tx, s, mustDNA(t, e.DN), e, f, filterHasAbsoluteSet(f))
					})
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				rows++
				if got != want {
					t.Errorf("probe %s %s %s: native [%s], oracle [%s]", probe, m[1], m[2], got, want)
				}
				continue
			}
			if m := oracleCompareRowRe.FindStringSubmatch(line); m != nil {
				if _, ok := table[m[1]]; !ok {
					continue
				}
				s := Subject{DN: mustDNA(t, "uid="+m[1]+",ou=people,dc=example,dc=test")}
				var got bool
				if err := srv.opts.Store.View(ctx, func(tx ReadTx) error {
					got = srv.allowed(ctx, tx, s, mustDNA(t, "uid=fa_bob,"+cand3335Base), m[2], PermCompare)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				compares++
				if want := m[4] != "50"; got != want {
					t.Errorf("probe %s %s COMPARE %s: native allowed=%v, oracle rc=%s", probe, m[1], m[2], got, m[4])
				}
			}
		}
	}
	return rows, compares
}

// TestAbsoluteFilterKeepsEntryLevelSearchCheck: 389 rejects (&) and (|)
// (oracle probe 19), so native keeps the entry-level search check for a
// filter holding one (CAND-38) and a read-only subject cannot list entries.
func TestAbsoluteFilterKeepsEntryLevelSearchCheck(t *testing.T) {
	t.Parallel()
	srv := cand3335Server(t)
	entries := cand3335Entries()
	ctx := context.Background()
	for _, tc := range []struct{ subj, filter, want string }{
		{"e_deny_star", "(&)", ""},
		{"e_deny_star", "(|(&)(sn=S))", ""},
		{"e_deny_star", "(!(|))", ""},
		{"e_deny_notpw", "(&)", ""},
		// The kept entry-level check still applies attribute-scoped denies
		// (pre-existing behaviour, no 389 result to compare with).
		{"d_uidopt", "(&)", ""},
		{"t_descopt", "(&)", "fa_alice,fa_bob,fa_carol"},
		{"e_allow_noattr", "(&)", ""},
	} {
		f := parseTestFilter(t, tc.filter)
		if !filterHasAbsoluteSet(f) {
			t.Fatalf("%s: not absolute", tc.filter)
		}
		s := Subject{DN: mustDNA(t, "uid="+tc.subj+",ou=people,dc=example,dc=test")}
		var got string
		if err := srv.opts.Store.View(ctx, func(tx ReadTx) error {
			got = matchingNames(t, entries, func(e *Entry) bool {
				return srv.searchResultVisible(ctx, tx, s, mustDNA(t, e.DN), e, f, true)
			})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s %s: got [%s], want [%s]", tc.subj, tc.filter, got, tc.want)
		}
	}
	if filterHasAbsoluteSet(parseTestFilter(t, "(&(sn=S)(!(uid=x)))")) {
		t.Fatal("leaf-only filter reported absolute")
	}
}

// TestTargetAttrSchemaCheckMatchesOracle replays probe 16/19's verdicts for
// ACI text added over LDAP: names outside the 389 schema fail to parse.
func TestTargetAttrSchemaCheckMatchesOracle(t *testing.T) {
	t.Parallel()
	re := regexp.MustCompile(`^v(?:33|19) targetattr(!?)="([^"]*)" rc=(\d+)`)
	n := 0
	for _, probe := range []string{"16", "19"} {
		for _, line := range oracleSection(t, probe) {
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			op := "="
			if m[1] == "!" {
				op = "!="
			}
			if op == "!=" && m[2] == "*" {
				continue // CAND-37 (open): native rejects targetattr!="*", 389 accepts it.
			}
			text := `(target="ldap:///dc=example,dc=test")(targetattr` + op + `"` + m[2] + `")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`
			_, err := ParseACITextA(text)
			n++
			if accepted := m[3] == "0"; (err == nil) != accepted {
				t.Errorf("targetattr%s%q: native err=%v, oracle rc=%s", op, m[2], err, m[3])
			}
		}
	}
	if n < 70 {
		t.Fatalf("replayed %d rows", n)
	}
	// ldapserver.New fails closed on such raw ACI text (as 389 refuses the add).
	opts := testOptions()
	opts.ACI = nil
	opts.ACITexts = []string{`(target="ldap:///dc=example,dc=test")(targetattr="fooBar")(version 3.0; acl "x"; allow (read) userdn="ldap:///all";)`}
	if _, err := New(opts); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("New: %v", err)
	}
}

// TestAttributeIdentityResolvesSecondDescriptors pins Ilya's #28 note and
// oracle probe 20: 389 stores a value written as userid under uid, so
// targetattr="uid" covers it and targetattr="userid" covers nothing. Native
// keeps the written spelling, so the ACI identity resolves it.
func TestAttributeIdentityResolvesSecondDescriptors(t *testing.T) {
	t.Parallel()
	const base = "ou=probe-fattr,dc=example,dc=test"
	texts := []string{
		`(target="ldap:///` + base + `")(targetattr="uid")(version 3.0; acl "a"; allow (read,search) userdn="ldap:///uid=i_uid_rs,ou=people,dc=example,dc=test";)`,
		`(target="ldap:///` + base + `")(targetattr="userid")(version 3.0; acl "b"; allow (read,search) userdn="ldap:///uid=i_userid_rs,ou=people,dc=example,dc=test";)`,
	}
	opts := testOptions()
	opts.Schema = standardSchemaT(t)
	opts.ACI = nil
	opts.ACITexts = texts
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	e := NewEntry("uid=v_u,"+base, StringAttribute("objectClass", "top", "person", "organizationalPerson", "inetOrgPerson"),
		StringAttribute("userid", "v_u"), StringAttribute("commonName", "v_u"), StringAttribute("surname", "S"))
	entries := map[string]*Entry{"v_u": e}
	ctx := context.Background()
	for _, tc := range []struct{ subj, filter, want string }{
		{"i_uid_rs", "(uid=v_u)", "v_u"},
		{"i_uid_rs", "(userid=v_u)", "v_u"},
		{"i_uid_rs", "(cn=v_u)", ""},
		{"i_userid_rs", "(uid=v_u)", ""},
		{"i_userid_rs", "(userid=v_u)", ""},
	} {
		f := parseTestFilter(t, tc.filter)
		s := Subject{DN: mustDNA(t, "uid="+tc.subj+",ou=people,dc=example,dc=test")}
		var got string
		if err := srv.opts.Store.View(ctx, func(tx ReadTx) error {
			got = matchingNames(t, entries, func(e *Entry) bool {
				return srv.searchResultVisible(ctx, tx, s, mustDNA(t, e.DN), e, f, false)
			})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s %s: got [%s], oracle [%s]", tc.subj, tc.filter, got, tc.want)
		}
	}
}

// TestEmptyFilterOptionMatchesNothing pins Ilya's #28 note and oracle probe
// 20b: 389 matches nothing for (cn;=v), (cn;lang-en;=v) and (uid;=v), even
// for Directory Manager, while (cn;LANG-EN=v) matches.
func TestEmptyFilterOptionMatchesNothing(t *testing.T) {
	t.Parallel()
	s := standardSchemaT(t)
	e := NewEntry("uid=v_u,ou=probe-fattr,dc=example,dc=test", StringAttribute("uid", "v_u"), StringAttribute("cn", "v_u"), StringAttribute("cn;lang-en", "en_u"))
	for _, tc := range []struct {
		filter string
		want   bool
	}{
		{"(cn;=v_u)", false}, {"(cn;=en_u)", false}, {"(cn;lang-en;=en_u)", false}, {"(uid;=v_u)", false},
		{"(cn;LANG-EN=en_u)", true}, {"(cn=v_u)", true}, {"(cn=en_u)", true},
	} {
		if got := matchFilter(e, parseTestFilter(t, tc.filter), s); got != tc.want {
			t.Errorf("%s: got %v, oracle %v", tc.filter, got, tc.want)
		}
	}
}

// TestCodeSweepEdgeCases pins the code-sweep follow-ups: an empty targetattr
// option covers nothing (not even a description with an empty option), a
// description with an empty base fails closed instead of becoming an
// entry-level check, and pwdChangedTime never counts for visibility.
func TestCodeSweepEdgeCases(t *testing.T) {
	t.Parallel()
	p, err := ParseACITextA(`(target="ldap:///dc=example,dc=test")(targetattr="uid;")(version 3.0; acl "e"; allow (read,search) userdn="ldap:///anyone";)`)
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range [][]string{nil, {""}, {"x-test"}} {
		if p.TargetsAttr("uid", opts) {
			t.Errorf(`targetattr="uid;" covers uid with options %q`, opts)
		}
	}

	opts := testOptions()
	opts.Schema = standardSchemaT(t)
	opts.ACI = nil
	opts.ACITexts = []string{`(target="ldap:///dc=example,dc=test")(targetattr="*")(version 3.0; acl "all"; allow (read,search,write) userdn="ldap:///uid=someone,ou=people,dc=example,dc=test";)`}
	srv, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	s := Subject{DN: mustDNA(t, "uid=someone,ou=people,dc=example,dc=test")}
	target := mustDNA(t, "ou=probe-fattr,dc=example,dc=test")
	if err := srv.opts.Store.View(ctx, func(tx ReadTx) error {
		if !srv.allowed(ctx, tx, s, target, "description", PermWrite) {
			t.Error("control: write on description denied")
		}
		if srv.allowed(ctx, tx, s, target, ";x", PermWrite) {
			t.Error(`write on ";x" allowed; want fail-closed`)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if srv.countsForVisibility("pwdChangedTime") {
		t.Error("pwdChangedTime counts for visibility")
	}
}
