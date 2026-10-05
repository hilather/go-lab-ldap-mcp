//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

// TestModDNMatchesOracle (contract C8; resolved CAND-39 and CAND-30,
// oracle probes 30-34 in test/parity/testdata/filter-attr-oracle-probes.txt)
// runs the same client and assertions on both engines:
//   - a move needs moddn on the new superior (entry level, targetattr
//     ignored) plus write on the RDN attribute on the old DN; no add,
//     delete or source-side moddn;
//   - a missing source or superior is 32 only with moddn on that DN
//     through an ACI whose targetattr covers an arbitrary attribute;
//   - a case-only rename succeeds with the rename gates and respells the
//     DN; a move takes the stored superior's spelling;
//   - referint and memberOf follow a subtree move.
//
// Every row uses a fresh connection (D36).
func TestModDNMatchesOracle(t *testing.T) {
	const (
		suffix = "dc=example,dc=test"
		people = "ou=people," + suffix
		groups = "ou=groups," + suffix
		B      = "ou=c39src," + suffix
		D      = "ou=c39dst," + suffix
		pw     = "Cand39-Probe-Secret-1"
	)
	wu := `(target="ldap:///` + suffix + `")(targetattr="uid || ou")|write`
	md := func(target, ta string) string { return `(target="ldap:///` + target + `")` + ta + `|moddn` }
	dmd := func(target, ta string) string { return `(target="ldap:///` + target + `")` + ta + `|deny:moddn` }
	subjects := map[string][]string{
		"c_plain_s":     {wu, md(suffix, "")},
		"c_plain_b":     {wu, md(B, "")},
		"c_plain_d":     {wu, md(D, "")},
		"c_ta_cn":       {wu, md(suffix, `(targetattr="cn")`)},
		"c_ta_notuid":   {wu, md(suffix, `(targetattr!="uid")`)},
		"c_deny_m_b":    {wu, md(suffix, ""), dmd(B, "")},
		"c_deny_m_d_ta": {wu, md(suffix, ""), dmd(D, `(targetattr="uid")`)},
		"c_deny_m_star": {wu, md(suffix, ""), dmd(B, `(targetattr="*")`)},
		"c_deny_w_b":    {wu, md(suffix, ""), `(target="ldap:///` + B + `")|deny:write`},
		"c_nowrite":     {md(suffix, "")},
		"c_w_src":       {`(target="ldap:///` + B + `")(targetattr="uid || ou")|write`, md(suffix, "")},
		"c_w_dst":       {`(target="ldap:///` + D + `")(targetattr="uid || ou")|write`, md(suffix, "")},
		"c_w_cn":        {`(target="ldap:///` + suffix + `")(targetattr="cn")|write`, md(suffix, "")},
		"c_w_uid":       {wu},
		"c_rt":          {`(target="ldap:///` + people + `")(targetattr!="aci")|add,delete,write,read,search,compare,moddn`, `(target="ldap:///` + groups + `")(targetattr!="aci")|add,delete,write,read,search,compare,moddn`},
	}
	yaml := strings.Replace(workflowYAML(), `directory: { suffix: "dc=example,dc=test" }`, `directory: { suffix: "dc=example,dc=test", allowRawACI: true }`, 1)
	yaml += "  acls:\n"
	names := make([]string, 0, len(subjects))
	for s := range subjects {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, s := range names {
		for n, a := range subjects[s] {
			i := strings.LastIndex(a, "|")
			ta, perms := a[:i], a[i+1:]
			action := "allow"
			if p, ok := strings.CutPrefix(perms, "deny:"); ok {
				action, perms = "deny", p
			}
			id := fmt.Sprintf("%s-%d", strings.ReplaceAll(s, "_", "-"), n)
			yaml += fmt.Sprintf("    - id: %s\n      rawACI: '%s(version 3.0; acl \"labldap:%s\"; %s (%s) userdn=\"ldap:///uid=%s,%s\";)'\n", id, ta, id, action, perms, s, people)
		}
	}
	env := startCompatEngineFromYAML(t, yaml)
	pem, err := os.ReadFile(env.caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("parse test CA")
	}
	dial := func(dn, password string) *ldap.Conn {
		t.Helper()
		c, err := ldap.DialURL("ldaps://"+env.ldapsAddr, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: env.serverName, MinVersion: tls.VersionTLS12}))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Bind(dn, password); err != nil {
			c.Close()
			t.Fatalf("bind %s: %v", dn, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	as := func(s string) *ldap.Conn { return dial("uid="+s+","+people, pw) }
	dm := dial("cn=Directory Manager", env.dmPassword)
	if env.engine == Engine389DS {
		// Every oracle fact here assumes 389's moddn ACI mode.
		res, err := dm.Search(ldap.NewSearchRequest("cn=config", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"nsslapd-moddn-aci"}, nil))
		if err != nil || len(res.Entries) != 1 || !strings.EqualFold(res.Entries[0].GetAttributeValue("nsslapd-moddn-aci"), "on") {
			t.Fatalf("389 nsslapd-moddn-aci must be on: %v %v", err, res)
		}
	}
	add := func(dn string, attrs map[string][]string) {
		t.Helper()
		req := ldap.NewAddRequest(dn, nil)
		keys := make([]string, 0, len(attrs))
		for k := range attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			req.Attribute(k, attrs[k])
		}
		if err := dm.Add(req); err != nil {
			t.Fatalf("add %s: %v", dn, err)
		}
	}
	person := func(uid string) map[string][]string {
		return map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"}, "uid": {uid}, "cn": {uid}, "sn": {"S"}}
	}
	orgUnit := func(name string) map[string][]string {
		return map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {name}}
	}
	add(B, orgUnit("c39src"))
	add(D, orgUnit("c39dst"))
	add("ou=MixCase,"+D, orgUnit("MixCase"))
	for _, s := range names {
		p := person(s)
		p["userPassword"] = []string{pw}
		add("uid="+s+","+people, p)
	}
	code := func(err error) uint16 {
		var le *ldap.Error
		if err == nil {
			return 0
		}
		if errors.As(err, &le) {
			return le.ResultCode
		}
		t.Fatalf("unexpected error %v", err)
		return 0
	}
	read := func(dn string, attrs ...string) (string, map[string][]string) {
		t.Helper()
		res, err := dm.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", attrs, nil))
		if err != nil || len(res.Entries) != 1 {
			t.Fatalf("read %s: %v", dn, err)
		}
		out := map[string][]string{}
		for _, a := range attrs {
			v := res.Entries[0].GetAttributeValues(a)
			slices.Sort(v)
			out[a] = v
		}
		return res.Entries[0].DN, out
	}
	n := 0
	fresh := func(base string) string {
		n++
		uid := fmt.Sprintf("c39e%02d", n)
		add("uid="+uid+","+base, person(uid))
		return uid
	}

	// Moves (probes 30, 33, 34): uid=x,B -> D unless noted.
	for _, tc := range []struct {
		subject, from, rdnFmt, to string
		del                       bool
		want                      uint16
	}{
		{"c_plain_s", B, "uid=%s", D, false, 0},
		{"c_plain_s", B, "uid=%sr", D, true, 0},
		{"c_plain_s", B, "cn=%sc", D, false, 50},
		{"c_plain_s", D, "uid=%s", B, false, 0},
		{"c_plain_b", B, "uid=%s", D, false, 50},
		{"c_plain_b", D, "uid=%s", B, false, 0},
		{"c_plain_d", B, "uid=%s", D, false, 0},
		{"c_plain_d", D, "uid=%s", B, false, 50},
		{"c_ta_cn", B, "uid=%s", D, false, 0},
		{"c_deny_m_b", B, "uid=%s", D, false, 0},
		{"c_deny_m_b", D, "uid=%s", B, false, 50},
		{"c_deny_m_d_ta", B, "uid=%s", D, false, 50},
		{"c_deny_w_b", B, "uid=%s", D, false, 50},
		{"c_deny_w_b", D, "uid=%s", B, false, 0},
		{"c_nowrite", B, "uid=%s", D, false, 50},
		{"c_w_src", B, "uid=%s", D, false, 0},
		{"c_w_dst", B, "uid=%s", D, false, 50},
		{"c_w_cn", B, "cn=%sc", D, false, 0},
		{"c_w_uid", B, "uid=%s", D, false, 50},
		{"c_rt", people, "uid=%s", groups, false, 0},
		{"c_rt", groups, "uid=%s", people, false, 0},
		{"c_rt", people, "uid=%s", B, false, 50},
	} {
		uid := fresh(tc.from)
		rdn := fmt.Sprintf(tc.rdnFmt, uid)
		if got := code(as(tc.subject).ModifyDN(ldap.NewModifyDNRequest("uid="+uid+","+tc.from, rdn, tc.del, tc.to))); got != tc.want {
			t.Errorf("%s: %s move uid=%s,%s -> %s,%s: got %d, oracle %d", env.engine, tc.subject, uid, tc.from, rdn, tc.to, got, tc.want)
		}
	}

	// Existence (probes 30-34): ghost source in B, or a missing superior.
	for _, tc := range []struct {
		subject, dn, rdn, sup string
		want                  uint16
	}{
		{"c_plain_s", "uid=ghost," + B, "uid=ghost", D, 32},
		{"c_plain_s", "uid=ghost," + B, "uid=ghostr", "", 32},
		{"c_ta_cn", "uid=ghost," + B, "uid=ghost", D, 50},
		{"c_ta_notuid", "uid=ghost," + B, "uid=ghost", D, 32},
		{"c_plain_b", "uid=ghost," + B, "uid=ghost", D, 32},
		{"c_plain_d", "uid=ghost," + B, "uid=ghost", D, 50},
		{"c_deny_m_b", "uid=ghost," + B, "uid=ghost", D, 50},
		{"c_deny_m_star", "uid=ghost," + B, "uid=ghost", D, 50},
		{"c_w_uid", "uid=ghost," + B, "uid=ghost", D, 50},
		{"c_plain_d", "", "", "ou=nope," + D, 32},
		{"c_plain_b", "", "", "ou=nope," + D, 50},
		{"c_nowrite", "", "", "ou=nope," + suffix, 32},
	} {
		dn, rdn := tc.dn, tc.rdn
		if dn == "" {
			uid := fresh(B)
			dn, rdn = "uid="+uid+","+B, "uid="+uid
		}
		if got := code(as(tc.subject).ModifyDN(ldap.NewModifyDNRequest(dn, rdn, false, tc.sup))); got != tc.want {
			t.Errorf("%s: %s existence %s -> %s,%s: got %d, oracle %d", env.engine, tc.subject, dn, rdn, tc.sup, got, tc.want)
		}
	}

	// Case-only renames (probes 30, 31): rename gates, no moddn needed.
	for _, tc := range []struct {
		subject string
		want    uint16
	}{
		{"c_w_uid", 0},
		{"c_w_cn", 50},
		{"c_deny_w_b", 50},
	} {
		uid := fresh(B)
		if got := code(as(tc.subject).ModifyDN(ldap.NewModifyDNRequest("uid="+uid+","+B, "uid="+strings.ToUpper(uid), true, ""))); got != tc.want {
			t.Errorf("%s: %s case-only rename: got %d, oracle %d", env.engine, tc.subject, got, tc.want)
		}
	}

	// Spelling (probes 30, 33, 34). Attribute types stay lowercase (D37).
	uid := fresh(B)
	if got := code(dm.ModifyDN(ldap.NewModifyDNRequest("uid="+uid+","+B, "uid="+strings.ToUpper(uid), true, ""))); got != 0 {
		t.Fatalf("%s: DM case-only rename: got %d", env.engine, got)
	}
	if dn, a := read("uid="+uid+","+B, "uid"); !strings.EqualFold(dn, "uid="+uid+","+B) || !strings.HasPrefix(dn, "uid="+strings.ToUpper(uid)+",") || !slices.Equal(a["uid"], []string{strings.ToUpper(uid)}) {
		t.Errorf("%s: case-only del1: DN %q uid %q, oracle respelled DN and value", env.engine, dn, a["uid"])
	}
	uid = fresh(B)
	if got := code(dm.ModifyDN(ldap.NewModifyDNRequest("uid="+uid+","+B, "uid="+uid, false, "ou=mixcase,"+D))); got != 0 {
		t.Fatalf("%s: DM move: got %d", env.engine, got)
	}
	if dn, _ := read("uid="+uid+",ou=mixcase,"+D, "uid"); dn != "uid="+uid+",ou=MixCase,"+D {
		t.Errorf("%s: move under mixed-case superior: DN %q, oracle stored spelling", env.engine, dn)
	}
	uid = fresh(B)
	if got := code(dm.ModifyDN(ldap.NewModifyDNRequest("uid="+uid+",ou=C39SRC,"+suffix, "uid="+uid, true, ""))); got != 0 {
		t.Fatalf("%s: DM respell via parent: got %d", env.engine, got)
	}
	if dn, _ := read("uid="+uid+","+B, "uid"); dn != "uid="+uid+",ou=C39SRC,"+suffix {
		t.Errorf("%s: rename via respelled parent: DN %q, oracle request parent spelling", env.engine, dn)
	}

	// Plugins on a subtree move (probe 34).
	unit := "ou=c39unit," + B
	add(unit, orgUnit("c39unit"))
	add("uid=c39inner,"+unit, person("c39inner"))
	add("cn=c39in,"+unit, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"c39in"}, "member": {"uid=c39inner," + unit}})
	add("cn=c39out,"+groups, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"c39out"}, "member": {"uid=c39inner," + unit}})
	if got := code(dm.ModifyDN(ldap.NewModifyDNRequest(unit, "ou=c39unit", false, D))); got != 0 {
		t.Fatalf("%s: subtree move: got %d", env.engine, got)
	}
	moved := "ou=c39unit," + D
	lower := func(v []string) []string {
		out := make([]string, len(v))
		for i, s := range v {
			out[i] = strings.ToLower(s)
		}
		slices.Sort(out)
		return out
	}
	if _, a := read("cn=c39out,"+groups, "member"); !slices.Equal(lower(a["member"]), []string{"uid=c39inner," + moved}) {
		t.Errorf("%s: outer group member after subtree move = %q", env.engine, a["member"])
	}
	if _, a := read("cn=c39in,"+moved, "member"); !slices.Equal(lower(a["member"]), []string{"uid=c39inner," + moved}) {
		t.Errorf("%s: inner group member after subtree move = %q", env.engine, a["member"])
	}
	if _, a := read("uid=c39inner,"+moved, "memberOf"); !slices.Equal(lower(a["memberOf"]), []string{"cn=c39in," + moved, "cn=c39out," + groups}) {
		t.Errorf("%s: memberOf after subtree move = %q", env.engine, a["memberOf"])
	}
}
