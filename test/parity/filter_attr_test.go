package parity

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

// Filter attribute descriptions (contract C6): subtype/option matching,
// second-descriptor and OID resolution, and the filter-leaf search
// identity. Expected DN sets are the 389 oracle's (probes 1-7, pinned image;
// transcripts in testdata/filter-attr-oracle-probes.txt). This test uses
// its own fixture so the shared ledger fixture and its C8 rows never see
// these ACIs.

const (
	fattrOU       = "ou=probe-fattr," + suffixDN
	fattrPassword = "parity-fattr-secret-01"
	fattrOID      = "0.9.2342.19200300.100.1.1"
)

var fattrSubjects = []struct{ id, targetattr string }{
	{"fa_allow_uid", `(targetattr="uid")`},
	{"fa_allow_userid", `(targetattr="userid")`},
	{"fa_deny_uid", `(targetattr!="uid")`},
	{"fa_deny_userid", `(targetattr!="userid")`},
}

func filterAttrFixture(t *testing.T) *fixture {
	t.Helper()
	var acls strings.Builder
	for _, s := range fattrSubjects {
		// Probe-6 rawACI text verbatim (single-attribute targetattr with a
		// target clause; the multi-attribute and numeric-OID shapes 389
		// also accepts are CAND-32).
		fmt.Fprintf(&acls, "    - id: %s\n      rawACI: '(target=\"ldap:///%s\")%s(version 3.0; acl \"labldap:%s\"; allow (read,search,compare) userdn=\"ldap:///uid=%s,%s\";)'\n",
			strings.ReplaceAll(s.id, "_", "-"), fattrOU, s.targetattr, s.id, s.id, peopleDN)
	}
	scenario := append(scenarioYAML(), []byte(acls.String())...)
	secrets := config.MapResolver{"secrets/runtime": runtimePassword}
	for id, pw := range userPasswords {
		secrets["secrets/"+id] = pw
	}
	c, err := config.Compile(t.Context(), scenario, "filter-attr-parity.yaml", config.LoadOptions{Caller: config.CallerCLI, Secrets: secrets})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{compiled: c, tls: makeTLSFixture(t)}
}

func fattrDN(id string) string { return "uid=" + id + "," + fattrOU }

func seedFilterAttr(t *testing.T, dm *ldap.Conn) {
	t.Helper()
	person := []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
	add := func(dn string, attrs map[string][]string) {
		t.Helper()
		req := ldap.NewAddRequest(dn, nil)
		names := make([]string, 0, len(attrs))
		for n := range attrs {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			req.Attribute(n, attrs[n])
		}
		if err := dm.Add(req); err != nil {
			t.Fatalf("seed %s: %v", dn, err)
		}
	}
	add(fattrOU, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"probe-fattr"}})
	add(fattrDN("fa_alice"), map[string][]string{"objectClass": person, "uid": {"fa_alice"}, "cn": {"fa_alice"}, "sn": {"S"}})
	add(fattrDN("fa_bob"), map[string][]string{"objectClass": person, "uid": {"fa_bob"}, "cn": {"fa_bob"}, "sn": {"S"},
		"uid;x-test": {"bobtag"}, "description;lang-en": {"hello"}, "userPassword;x-b": {"parity-fattr-variant-1"}})
	add(fattrDN("fa_carol"), map[string][]string{"objectClass": person, "uid": {"fa_carol"}, "cn": {"fa_carol"}, "sn": {"S"},
		"description;lang-en;x-foo": {"multi"}, "cn;lang-en": {"Karla"}})
	for _, s := range fattrSubjects {
		add(userDN(s.id), map[string][]string{"objectClass": person, "uid": {s.id}, "cn": {s.id}, "sn": {"S"}, "userPassword": {fattrPassword}})
	}
}

func cleanupFilterAttr(t *testing.T, dm *ldap.Conn) {
	t.Helper()
	dns := []string{fattrDN("fa_alice"), fattrDN("fa_bob"), fattrDN("fa_carol"), fattrOU}
	for _, s := range fattrSubjects {
		dns = append(dns, userDN(s.id))
	}
	for _, dn := range dns {
		if err := dm.Del(ldap.NewDelRequest(dn, nil)); err != nil {
			t.Errorf("cleanup %s: %v", dn, err)
		}
	}
}

type fattrRow struct{ filter, want string }

const (
	fattrAll    = "fa_alice,fa_bob,fa_carol"
	fattrNotBob = "fa_alice,fa_carol"
)

// fattrDMRows are the Directory Manager rows (probes 1-3, 6, 7).
func fattrDMRows() []fattrRow {
	return []fattrRow{
		{"(uid=fa_bob)", "fa_bob"}, {"(!(uid=fa_bob))", fattrNotBob},
		{"(userid=fa_bob)", "fa_bob"}, {"(!(userid=fa_bob))", fattrNotBob},
		{"(" + fattrOID + "=fa_bob)", "fa_bob"}, {"(!(" + fattrOID + "=fa_bob))", fattrNotBob},
		{"(uid;x-test=bobtag)", "fa_bob"}, {"(!(uid;x-test=bobtag))", fattrNotBob},
		{"(uid;X-TEST=bobtag)", "fa_bob"}, {"(uid=bobtag)", "fa_bob"},
		{"(uid;x-test=fa_*)", ""}, {"(uid;x-test>=a)", "fa_bob"},
		{"(userid;x-test=bobtag)", ""}, {"(!(userid;x-test=bobtag))", fattrAll},
		{"(" + fattrOID + ";x-test=bobtag)", ""}, {"(!(" + fattrOID + ";x-test=bobtag))", fattrAll},
		{"(cn=fa_bob)", "fa_bob"}, {"(!(cn=fa_bob))", fattrNotBob},
		{"(description=hello)", "fa_bob"}, {"(!(description=hello))", fattrNotBob},
		{"(description=hel*)", "fa_bob"}, {"(description;lang-en=hello)", "fa_bob"},
		{"(2.5.4.13=hello)", "fa_bob"}, {"(2.5.4.13;lang-en=hello)", ""}, {"(!(2.5.4.13;lang-en=hello))", fattrAll},
		{"(description;lang-fr=hello)", ""},
		{"(description=multi)", "fa_carol"}, {"(description;x-foo;lang-en=multi)", "fa_carol"},
		{"(description;LANG-EN=multi)", "fa_carol"}, {"(description;lang-en;x-bar=multi)", ""},
		{"(description;lang-=multi)", ""}, {"(!(description;lang-=multi))", fattrAll},
		{"(userPassword=*)", "fa_bob"}, {"(userPassword;x-b=*)", "fa_bob"}, {"(!(userPassword=*))", fattrNotBob},
		{"(2.5.4.0=inetOrgPerson)", fattrAll}, {"(!(2.5.4.0=inetOrgPerson))", ""},
		{"(cn;lang-en=Karla)", "fa_carol"}, {"(commonName=Karla)", "fa_carol"},
		{"(commonName;lang-en=Karla)", ""}, {"(!(commonName;lang-en=Karla))", fattrAll},
		{"(2.5.4.3;lang-en=Karla)", ""},
		{"(surname;x-a=S)", ""}, {"(!(surname;x-a=S))", fattrAll},
	}
}

// fattrSubjectRows are the probe-6 rows per subject. The CAND-31 row
// (fa_allow_userid (!(userid;x-test=bobtag)): 389 none, native all three)
// is excluded until the owner adjudicates it. Native checks that leaf under
// the literal base userid, which matches the literal allow list.
func fattrSubjectRows(subject string) []fattrRow {
	uidRows := []fattrRow{
		{"(uid=fa_bob)", "fa_bob"}, {"(!(uid=fa_bob))", fattrNotBob},
		{"(userid=fa_bob)", "fa_bob"}, {"(!(userid=fa_bob))", fattrNotBob},
		{"(" + fattrOID + "=fa_bob)", "fa_bob"}, {"(!(" + fattrOID + "=fa_bob))", fattrNotBob},
		{"(uid;x-test=bobtag)", "fa_bob"}, {"(!(uid;x-test=bobtag))", fattrNotBob},
	}
	otherRows := []fattrRow{
		{"(cn=fa_bob)", "fa_bob"}, {"(!(cn=fa_bob))", fattrNotBob},
		{"(description=hello)", "fa_bob"}, {"(!(description=hello))", fattrNotBob},
	}
	var out []fattrRow
	for _, r := range uidRows {
		if subject != "fa_allow_uid" && subject != "fa_deny_userid" {
			r.want = ""
		}
		out = append(out, r)
	}
	for _, r := range otherRows {
		if subject != "fa_deny_uid" && subject != "fa_deny_userid" {
			r.want = ""
		}
		out = append(out, r)
	}
	notUserid, notOID := "", ""
	switch subject {
	case "fa_deny_uid":
		notUserid, notOID = fattrAll, fattrAll
	case "fa_deny_userid":
		notOID = fattrAll
	}
	out = append(out,
		fattrRow{"(userid;x-test=bobtag)", ""},
		fattrRow{"(" + fattrOID + ";x-test=bobtag)", ""},
		fattrRow{"(!(" + fattrOID + ";x-test=bobtag))", notOID},
	)
	if subject != "fa_allow_userid" { // CAND-31
		out = append(out, fattrRow{"(!(userid;x-test=bobtag))", notUserid})
	}
	return out
}

// fattrCompare is the D34 per-engine Compare table on fa_bob (probe 5):
// 389 applies subtype semantics for primary names but resolves neither
// second descriptors nor OIDs (16); native matches the stored name exactly.
var fattrCompare = []struct {
	attr, value string
	oracle      int
	native      int
}{
	{"uid", "fa_bob", 6, 6},
	{"cn", "FA_BOB", 6, 6},
	{"uid;x-test", "bobtag", 6, 6},
	{"description;lang-en", "hello", 6, 6},
	{"uid", "bobtag", 6, 5},
	{"description", "hello", 6, 5},
	{"uid;x-test", "fa_bob", 5, 5},
	{"userid", "fa_bob", 16, 5},
	{fattrOID, "fa_bob", 16, 5},
	{"userid;x-test", "bobtag", 16, 5},
	{fattrOID + ";x-test", "bobtag", 16, 5},
	{"2.5.4.13", "hello", 16, 5},
	{"description;lang-fr", "hello", 16, 5},
}

func fattrNames(o opOutcome) string {
	var names []string
	for _, e := range o.Entries {
		rdn, _, _ := strings.Cut(e.DN, ",")
		names = append(names, strings.TrimPrefix(strings.ToLower(rdn), "uid="))
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// filterAttrOutcomes runs every row on e, asserting the oracle DN sets (and
// the engine's own D34 Compare column), and returns the outcomes for the
// dual-engine comparison.
func filterAttrOutcomes(t *testing.T, e engine) []opOutcome {
	t.Helper()
	dm := e.dm(t)
	defer dm.Close()
	seedFilterAttr(t, dm)
	defer cleanupFilterAttr(t, dm)

	var out []opOutcome
	run := func(conn *ldap.Conn, who string, rows []fattrRow) {
		for _, r := range rows {
			o := searchOutcome(conn, fattrOU, ldap.ScopeSingleLevel, 0, r.filter, []string{"1.1"})
			if o.Code != 0 {
				t.Errorf("%s %s %s: code %d", e.name(), who, r.filter, o.Code)
			} else if got := fattrNames(o); got != r.want {
				t.Errorf("%s %s %s: [%s], oracle [%s]", e.name(), who, r.filter, got, r.want)
			}
			o.Note = who + " " + r.filter
			out = append(out, o)
		}
	}
	run(dm, "dm", fattrDMRows())
	for _, s := range fattrSubjects {
		conn := mustDial(t, e, userSpec(userDN(s.id), fattrPassword))
		run(conn, s.id, fattrSubjectRows(s.id))
		conn.Close()
	}
	for _, c := range fattrCompare {
		code := ldap.LDAPResultCompareFalse
		ok, err := dm.Compare(fattrDN("fa_bob"), c.attr, c.value)
		switch {
		case err != nil:
			code = codeOutcome(err).Code
		case ok:
			code = ldap.LDAPResultCompareTrue
		}
		want := c.native
		if e.name() == "389" {
			want = c.oracle
		}
		if code != int(want) {
			t.Errorf("%s compare %s:%s = %d, D34 table %d", e.name(), c.attr, c.value, code, want)
		}
	}
	return out
}

func TestNativeFilterAttributeDescriptions(t *testing.T) {
	fx := filterAttrFixture(t)
	native := startNative(t, fx)
	defer native.close(t)
	filterAttrOutcomes(t, native)
}
