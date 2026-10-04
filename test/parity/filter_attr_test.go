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

const fattrRSC = "read,search,compare"

// fattrSubjects are the probe-6 subjects plus the probe 8/10 subjects
// (entry visibility, targetattr list syntax). Each ACI is a targetattr
// clause and a permission list.
var fattrSubjects = []struct {
	id   string
	acis [][2]string
}{
	{"fa_allow_uid", [][2]string{{`(targetattr="uid")`, fattrRSC}}},
	{"fa_allow_userid", [][2]string{{`(targetattr="userid")`, fattrRSC}}},
	{"fa_deny_uid", [][2]string{{`(targetattr!="uid")`, fattrRSC}}},
	{"fa_deny_userid", [][2]string{{`(targetattr!="userid")`, fattrRSC}}},
	{"p_userid", [][2]string{{`(targetattr="userid")`, fattrRSC}}},
	{"p_star_read", [][2]string{{`(targetattr="*")`, "read"}}},
	{"p_list_case", [][2]string{{`(targetattr="UID || Sn")`, fattrRSC}}},
	{"p_oid_only", [][2]string{{`(targetattr="0.9.2342.19200300.100.1.1")`, fattrRSC}}},
	{"p_userid_sn", [][2]string{{`(targetattr="userid")`, fattrRSC}, {`(targetattr="sn")`, fattrRSC}}},
	{"p_userid_snsearch", [][2]string{{`(targetattr="userid")`, fattrRSC}, {`(targetattr="sn")`, "search"}}},
	{"p_userid_snread", [][2]string{{`(targetattr="userid")`, fattrRSC}, {`(targetattr="sn")`, "read"}}},
	{"p_star_search", [][2]string{{`(targetattr="*")`, "search"}}},
	{"p_list", [][2]string{{`(targetattr="uid || sn")`, fattrRSC}}},
	{"p_list_nospace", [][2]string{{`(targetattr="uid||sn")`, fattrRSC}}},
	{"p_oid_sn", [][2]string{{`(targetattr="2.5.4.4 || uid")`, fattrRSC}}},
	{"p_deny_oid", [][2]string{{`(targetattr!="0.9.2342.19200300.100.1.1")`, fattrRSC}}},
	{"p_deny_list", [][2]string{{`(targetattr!="uid || description")`, fattrRSC}}},
	{"q_oc", [][2]string{{`(targetattr="userid")`, fattrRSC}, {`(targetattr="objectClass")`, "read"}}},
	{"q_entryuuid", [][2]string{{`(targetattr="userid")`, fattrRSC}, {`(targetattr="entryUUID")`, "read"}}},
}

// fattr35Subjects are the probe 14/16/18 subjects for resolved CAND-34/35:
// options inside targetattr, deny ACIs ("deny:" permission prefix) and an
// omitted targetattr (empty clause). Their rows run on a fresh connection
// each, because 389 reuses a connection's earlier decision for the plain
// type when it later checks an option-bearing description (D36).
var fattr35Subjects = []struct {
	id   string
	acis [][2]string
	rows []fattrRow
}{
	{"t_uidopt", [][2]string{{`(targetattr="uid;x-test")`, fattrRSC}},
		[]fattrRow{{"(uid=fa_bob)", ""}, {"(uid;x-test=bobtag)", "fa_bob"}, {"(uid;X-TEST=bobtag)", "fa_bob"}, {"(sn=S)", ""}}},
	{"t_uidsemi", [][2]string{{`(targetattr="uid;")`, fattrRSC}},
		[]fattrRow{{"(uid=fa_bob)", ""}, {"(uid;x-test=bobtag)", ""}}},
	{"t_deny_uidopt", [][2]string{{`(targetattr!="uid;x-test")`, fattrRSC}},
		[]fattrRow{{"(uid=fa_bob)", "fa_bob"}, {"(uid;x-test=bobtag)", ""}, {"(sn=S)", fattrAll}}},
	{"d_uidopt", [][2]string{{`(targetattr="*")`, fattrRSC}, {`(targetattr="uid;x-test")`, "deny:" + fattrRSC}},
		[]fattrRow{{"(uid=fa_bob)", "fa_bob"}, {"(uid;x-test=bobtag)", ""}, {"(description=hello)", "fa_bob"}}},
	{"r_deny_pw_search", [][2]string{{`(targetattr="*")`, fattrRSC}, {`(targetattr="userPassword")`, "deny:search"}},
		[]fattrRow{{"(sn=S)", fattrAll}, {"(uid=fa_bob)", "fa_bob"}, {"(userPassword=*)", ""}}},
	{"e_deny_noattr", [][2]string{{`(targetattr="*")`, fattrRSC}, {``, "deny:search"}},
		[]fattrRow{{"(sn=S)", fattrAll}, {"(uid=fa_bob)", "fa_bob"}}},
	{"e_deny_pwsn", [][2]string{{`(targetattr="*")`, fattrRSC}, {`(targetattr="userPassword || sn")`, "deny:search"}},
		[]fattrRow{{"(sn=S)", ""}, {"(uid=fa_bob)", "fa_bob"}, {"(objectClass=*)", fattrAll}}},
	{"e_allow_noattr", [][2]string{{``, fattrRSC}},
		[]fattrRow{{"(objectClass=*)", ""}, {"(uid=fa_bob)", ""}}},
	{"e_allow_noattr_u", [][2]string{{``, fattrRSC}, {`(targetattr="uid")`, "read,search"}},
		[]fattrRow{{"(uid=*)", fattrAll}, {"(sn=S)", ""}}},
}

// fattrVisRows are the probe 8/10 rows (389 DN sets, generated from the
// transcripts) for the subjects added with CAND-31/32.
var fattrVisRows = map[string][]fattrRow{
	"p_userid": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_userid_sn": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_userid_snsearch": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_userid_snread": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_star_search": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_star_read": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_list": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_list_nospace": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_list_case": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_oid_sn": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_oid_only": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(!(sn=X))`, ""},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, ""},
		{`(!(cn=fa_bob))`, ""},
		{`(2.5.4.4=S)`, ""},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"p_deny_oid": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, ""},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, "fa_bob"},
		{`(!(uid=fa_bob))`, "fa_alice,fa_carol"},
		{`(cn=fa_bob)`, "fa_bob"},
		{`(!(cn=fa_bob))`, "fa_alice,fa_carol"},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, "fa_bob"},
		{`(!(description=hello))`, "fa_alice,fa_carol"},
	},
	"p_deny_list": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(!(0.9.2342.19200300.100.1.1;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(sn=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(!(sn=X))`, "fa_alice,fa_bob,fa_carol"},
		{`(uid=fa_bob)`, ""},
		{`(!(uid=fa_bob))`, ""},
		{`(cn=fa_bob)`, "fa_bob"},
		{`(!(cn=fa_bob))`, "fa_alice,fa_carol"},
		{`(2.5.4.4=S)`, "fa_alice,fa_bob,fa_carol"},
		{`(description=hello)`, ""},
		{`(!(description=hello))`, ""},
	},
	"q_oc": {
		{`(!(userid;x-test=bobtag))`, "fa_alice,fa_bob,fa_carol"},
		{`(sn=S)`, ""},
		{`(uid=fa_bob)`, ""},
	},
	"q_entryuuid": {
		{`(!(userid;x-test=bobtag))`, ""},
		{`(sn=S)`, ""},
		{`(uid=fa_bob)`, ""},
	},
}

func filterAttrFixture(t *testing.T) *fixture {
	t.Helper()
	var acls strings.Builder
	for _, s := range fattr35Subjects {
		for i, a := range s.acis {
			action, perms := "allow", a[1]
			if p, ok := strings.CutPrefix(perms, "deny:"); ok {
				action, perms = "deny", p
			}
			id := fmt.Sprintf("%s-%d", strings.ReplaceAll(s.id, "_", "-"), i)
			fmt.Fprintf(&acls, "    - id: %s\n      rawACI: '(target=\"ldap:///%s\")%s(version 3.0; acl \"labldap:%s\"; %s (%s) userdn=\"ldap:///uid=%s,%s\";)'\n",
				id, fattrOU, a[0], id, action, perms, s.id, peopleDN)
		}
	}
	for _, s := range fattrSubjects {
		// Probe 6/8/10 rawACI texts verbatim (target clause, one targetattr).
		for i, a := range s.acis {
			id := strings.ReplaceAll(s.id, "_", "-")
			acl := s.id
			if len(s.acis) > 1 {
				id = fmt.Sprintf("%s-%d", id, i)
				acl = fmt.Sprintf("%s-%d", s.id, i)
			}
			fmt.Fprintf(&acls, "    - id: %s\n      rawACI: '(target=\"ldap:///%s\")%s(version 3.0; acl \"labldap:%s\"; allow (%s) userdn=\"ldap:///uid=%s,%s\";)'\n",
				id, fattrOU, a[0], acl, a[1], s.id, peopleDN)
		}
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
	for _, s := range fattr35Subjects {
		add(userDN(s.id), map[string][]string{"objectClass": person, "uid": {s.id}, "cn": {s.id}, "sn": {"S"}, "userPassword": {fattrPassword}})
	}
}

func cleanupFilterAttr(t *testing.T, dm *ldap.Conn) {
	t.Helper()
	dns := []string{fattrDN("fa_alice"), fattrDN("fa_bob"), fattrDN("fa_carol"), fattrOU}
	for _, s := range fattrSubjects {
		dns = append(dns, userDN(s.id))
	}
	for _, s := range fattr35Subjects {
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

// fattrSubjectRows are the probe-6 rows per subject, then the probe 8/10
// rows. The CAND-31 row (fa_allow_userid (!(userid;x-test=bobtag)): none,
// because the subject can read no attribute the entries hold) is included.
func fattrSubjectRows(subject string) []fattrRow {
	if rows, ok := fattrVisRows[subject]; ok {
		return rows
	}
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
	out = append(out, fattrRow{"(!(userid;x-test=bobtag))", notUserid})
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
	for _, s := range fattr35Subjects {
		for _, r := range s.rows {
			conn := mustDial(t, e, userSpec(userDN(s.id), fattrPassword))
			run(conn, s.id, []fattrRow{r})
			conn.Close()
		}
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
