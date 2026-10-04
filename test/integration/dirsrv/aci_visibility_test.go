//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

// TestACIEntryVisibilityAndTargetAttrLists (contract C8; CAND-31/32
// resolved as Contract, oracle probes 8/10/11 in
// test/parity/testdata/filter-attr-oracle-probes.txt) runs the same client
// and assertions on both engines:
//   - a search result entry needs read on at least one non-operational
//     attribute it holds (search-only subjects see nothing);
//   - targetattr lists use "||" and accept numeric OIDs, compared literally.
func TestACIEntryVisibilityAndTargetAttrLists(t *testing.T) {
	const (
		suffix = "dc=example,dc=test"
		people = "ou=people," + suffix
		ou     = "ou=probe-vis," + suffix
		pw     = "Vis-Probe-Secret-1"
	)
	subjects := map[string][]string{
		"vis_list":        {`(targetattr="uid || sn")|read,search`},
		"vis_star_search": {`(targetattr="*")|search`},
		"vis_userid":      {`(targetattr="userid")|read,search,compare`},
		"vis_userid_oc":   {`(targetattr="userid")|read,search,compare`, `(targetattr="objectClass")|read`},
		"vis_oid":         {`(targetattr="2.5.4.4 || uid")|read,search,compare`},
		// Probes 11/14: a deny names its attributes literally, so the
		// numeric OID of userPassword denies nothing; the name does.
		"vis_deny_pwoid": {`(targetattr="*")|read,search,compare`, `(targetattr="2.5.4.35")|deny:read`},
		"vis_deny_pw":    {`(targetattr="*")|read,search,compare`, `(targetattr="userPassword")|deny:read`},
		// Probe 13: memberOf counts for visibility (a user attribute on
		// 389), nsAccountLock does not (directoryOperation).
		"vis_memberof": {`(targetattr="userid")|read,search,compare`, `(targetattr="memberOf")|read`},
		"vis_acctlock": {`(targetattr="userid")|read,search,compare`, `(targetattr="nsAccountLock")|read`},
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
			yaml += fmt.Sprintf("    - id: %s\n      rawACI: '(target=\"ldap:///%s\")%s(version 3.0; acl \"labldap:%s\"; %s (%s) userdn=\"ldap:///uid=%s,%s\";)'\n", id, ou, ta, id, action, perms, s, people)
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
	dm := dial("cn=Directory Manager", env.dmPassword)
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
	person := []string{"top", "person", "organizationalPerson", "inetOrgPerson"}
	add(ou, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"probe-vis"}})
	add("uid=v_a,"+ou, map[string][]string{"objectClass": person, "uid": {"v_a"}, "cn": {"v_a"}, "sn": {"S"}})
	add("uid=v_b,"+ou, map[string][]string{"objectClass": person, "uid": {"v_b"}, "cn": {"v_b"}, "sn": {"S"}, "uid;x-test": {"btag"}, "userPassword": {"Vis-Target-Secret-2"}, "nsAccountLock": {"true"}})
	// memberOf on v_a comes from the memberOf plugin on both engines.
	add("cn=vis-grp,"+suffix, map[string][]string{"objectClass": {"top", "groupOfNames"}, "cn": {"vis-grp"}, "member": {"uid=v_a," + ou}})
	for _, s := range names {
		add("uid="+s+","+people, map[string][]string{"objectClass": person, "uid": {s}, "cn": {s}, "sn": {"S"}, "userPassword": {pw}})
	}

	search := func(c *ldap.Conn, base string, scope int, filter string) string {
		t.Helper()
		res, err := c.Search(ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"1.1"}, nil))
		if err != nil {
			t.Fatalf("%s %s: %v", base, filter, err)
		}
		var got []string
		if res != nil {
			for _, e := range res.Entries {
				rdn, _, _ := strings.Cut(strings.ToLower(e.DN), ",")
				got = append(got, strings.TrimPrefix(rdn, "uid="))
			}
		}
		sort.Strings(got)
		return strings.Join(got, ",")
	}
	for _, tc := range []struct {
		subject, filter, want string
		base                  bool
	}{
		{"vis_list", "(sn=S)", "v_a,v_b", false},
		{"vis_list", "(uid=v_a)", "v_a", false},
		{"vis_list", "(cn=v_a)", "", false},
		{"vis_star_search", "(sn=*)", "", false},
		{"vis_star_search", "(objectClass=*)", "", true},
		{"vis_userid", "(!(userid;x-test=btag))", "", false},
		{"vis_userid_oc", "(!(userid;x-test=btag))", "v_a,v_b", false},
		{"vis_oid", "(uid=v_a)", "v_a", false},
		{"vis_oid", "(sn=S)", "", false},
		{"vis_oid", "(2.5.4.4=S)", "", false},
		{"vis_userid_oc", "(!(userid;x-test=btag))", "v_a", true},
		{"vis_userid", "(!(userid;x-test=btag))", "", true},
		{"vis_memberof", "(!(userid;x-test=x))", "v_a", false},
		{"vis_acctlock", "(!(userid;x-test=x))", "", false},
	} {
		c := dial("uid="+tc.subject+","+people, pw)
		base, scope := ou, ldap.ScopeSingleLevel
		if tc.base {
			base, scope = "uid=v_a,"+ou, ldap.ScopeBaseObject
		}
		if got := search(c, base, scope, tc.filter); got != tc.want {
			t.Errorf("%s %s %s: [%s], want [%s]", env.engine, tc.subject, tc.filter, got, tc.want)
		}
	}
	for _, tc := range []struct {
		subject string
		want    bool
	}{
		{"vis_deny_pwoid", true},
		{"vis_deny_pw", false},
		{"vis_list", false},
	} {
		c := dial("uid="+tc.subject+","+people, pw)
		res, err := c.Search(ldap.NewSearchRequest("uid=v_b,"+ou, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(uid=v_b)", []string{"userPassword"}, nil))
		got := false
		if err == nil && len(res.Entries) == 1 {
			got = len(res.Entries[0].GetAttributeValues("userPassword")) > 0
		} else if err != nil {
			t.Errorf("%s %s read userPassword: %v", env.engine, tc.subject, err)
		}
		if got != tc.want {
			t.Errorf("%s %s userPassword readable = %v, want %v", env.engine, tc.subject, got, tc.want)
		}
	}
}
