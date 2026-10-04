//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

// TestACITargetAttrOptionsAndEntryLevel (contract C8; resolved CAND-34/35,
// oracle probes 12, 14, 16, 18, 19 and 20 in
// test/parity/testdata/filter-attr-oracle-probes.txt) runs the same client
// and assertions on both engines:
//   - targetattr options cover only descriptions carrying them;
//   - there is no entry-level search check: a deny on userPassword hides
//     only userPassword leaves, and an omitted targetattr targets no
//     attribute;
//   - Modify checks each change's attribute, before the entry lookup;
//   - a value written as userid is stored and checked as uid.
//
// Not asserted here (open, see the parity contract): modrdn under an
// attribute-scoped deny-write (CAND-36), targetattr!="*" (CAND-37) and
// absolute filters such as (&), which 389 rejects (CAND-38).
func TestACITargetAttrOptionsAndEntryLevel(t *testing.T) {
	const (
		suffix = "dc=example,dc=test"
		people = "ou=people," + suffix
		ou     = "ou=probe-acl35," + suffix
		pw     = "Acl35-Probe-Secret-1"
		rsc    = "read,search,compare"
	)
	subjects := map[string][]string{
		"t_uidopt":         {`(targetattr="uid;x-test")|` + rsc},
		"t_uidsemi":        {`(targetattr="uid;")|` + rsc},
		"t_deny_uidopt":    {`(targetattr!="uid;x-test")|` + rsc},
		"d_uidopt":         {`(targetattr="*")|` + rsc, `(targetattr="uid;x-test")|deny:` + rsc},
		"r_deny_pw_search": {`(targetattr="*")|` + rsc, `(targetattr="userPassword")|deny:search`},
		"e_deny_noattr":    {`(targetattr="*")|` + rsc, `|deny:search`},
		"e_deny_pwsn":      {`(targetattr="*")|` + rsc, `(targetattr="userPassword || sn")|deny:search`},
		"e_allow_noattr":   {`|` + rsc},
		"e_allow_noattr_u": {`|` + rsc, `(targetattr="uid")|read,search`},
		"w_noattr":         {`(targetattr="*")|read,search`, `|write`},
		"w_deny_noattr":    {`(targetattr="*")|read,search,write`, `|deny:write`},
		"w_descopt":        {`(targetattr="*")|read,search`, `(targetattr="description;lang-en")|write`},
		"w_deny_descopt":   {`(targetattr="*")|read,search,write`, `(targetattr="description;lang-en")|deny:write`},
		"w_deny_uid":       {`(targetattr="*")|read,search,write`, `(targetattr="uid")|deny:write`},
		"w_none":           {`(targetattr="*")|read,search`},
		"r_noattr_wa":      {`(targetattr="*")|read,search`, `|write,add`},
		"i_uid_rs":         {`(targetattr="uid")|read,search`},
		"i_userid_rs":      {`(targetattr="userid")|read,search`},
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
	conns := map[string]*ldap.Conn{}
	dial := func(dn, password string) *ldap.Conn {
		t.Helper()
		if c, ok := conns[dn]; ok {
			return c
		}
		c, err := ldap.DialURL("ldaps://"+env.ldapsAddr, ldap.DialWithTLSConfig(&tls.Config{RootCAs: pool, ServerName: env.serverName, MinVersion: tls.VersionTLS12}))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Bind(dn, password); err != nil {
			c.Close()
			t.Fatalf("bind %s: %v", dn, err)
		}
		t.Cleanup(func() { _ = c.Close() })
		conns[dn] = c
		return c
	}
	as := func(s string) *ldap.Conn { return dial("uid="+s+","+people, pw) }
	dm := dial("cn=Directory Manager", env.dmPassword)
	add := func(dn string, attrs [][2]string) {
		t.Helper()
		req := ldap.NewAddRequest(dn, nil)
		vals := map[string][]string{}
		var order []string
		for _, kv := range attrs {
			if _, ok := vals[kv[0]]; !ok {
				order = append(order, kv[0])
			}
			vals[kv[0]] = append(vals[kv[0]], kv[1])
		}
		for _, k := range order {
			req.Attribute(k, vals[k])
		}
		if err := dm.Add(req); err != nil {
			t.Fatalf("add %s: %v", dn, err)
		}
	}
	person := [][2]string{{"objectClass", "top"}, {"objectClass", "person"}, {"objectClass", "organizationalPerson"}, {"objectClass", "inetOrgPerson"}}
	add(ou, [][2]string{{"objectClass", "top"}, {"objectClass", "organizationalUnit"}, {"ou", "probe-acl35"}})
	add("uid=fa_alice,"+ou, append(person, [2]string{"uid", "fa_alice"}, [2]string{"cn", "fa_alice"}, [2]string{"sn", "S"}))
	add("uid=fa_bob,"+ou, append(person, [2]string{"uid", "fa_bob"}, [2]string{"cn", "fa_bob"}, [2]string{"sn", "S"},
		[2]string{"userPassword", "Acl35-Target-Secret-2"}, [2]string{"uid;x-test", "bobtag"}, [2]string{"description;lang-en", "hello"}))
	add("uid=fa_carol,"+ou, append(person, [2]string{"uid", "fa_carol"}, [2]string{"cn", "fa_carol"}, [2]string{"sn", "S"},
		[2]string{"description;lang-en;x-foo", "multi"}, [2]string{"uid;x-test;x-two", "two"}))
	// Ilya's #28 note / probe 20: written as userid, stored and checked as uid.
	add("cn=v_u,"+ou, append(person, [2]string{"cn", "v_u"}, [2]string{"userid", "v_u"}, [2]string{"sn", "S"}))
	for _, s := range names {
		add("uid="+s+","+people, append(person, [2]string{"uid", s}, [2]string{"cn", s}, [2]string{"sn", "S"}, [2]string{"userPassword", pw}))
	}

	search := func(c *ldap.Conn, filter string) string {
		t.Helper()
		res, err := c.Search(ldap.NewSearchRequest(ou, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"1.1"}, nil))
		if err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
		var got []string
		for _, e := range res.Entries {
			rdn, _, _ := strings.Cut(strings.ToLower(e.DN), ",")
			_, v, _ := strings.Cut(rdn, "=")
			got = append(got, v)
		}
		sort.Strings(got)
		return strings.Join(got, ",")
	}
	const all = "fa_alice,fa_bob,fa_carol"
	for _, tc := range []struct{ subject, filter, want string }{
		// CAND-34 (probes 12, 16, 18).
		{"t_uidopt", "(uid=fa_bob)", ""},
		{"t_uidopt", "(uid;x-test=bobtag)", "fa_bob"},
		{"t_uidopt", "(uid;x-test=two)", "fa_carol"},
		{"t_uidopt", "(uid;x-two=two)", ""},
		{"t_uidopt", "(!(uid;x-test=bobtag))", "fa_carol"},
		{"t_uidsemi", "(uid;x-test=bobtag)", ""},
		{"t_uidsemi", "(uid=fa_bob)", ""},
		{"t_deny_uidopt", "(uid=fa_bob)", "fa_bob"},
		{"t_deny_uidopt", "(uid;x-test=bobtag)", ""},
		{"t_deny_uidopt", "(uid;x-two=two)", "fa_carol"},
		{"d_uidopt", "(uid=fa_bob)", "fa_bob"},
		{"d_uidopt", "(uid;x-test=bobtag)", ""},
		{"d_uidopt", "(description=hello)", "fa_bob"},
		// CAND-35 (probes 14, 16).
		{"r_deny_pw_search", "(sn=S)", all + ",v_u"},
		{"r_deny_pw_search", "(uid=fa_bob)", "fa_bob"},
		{"r_deny_pw_search", "(userPassword=*)", ""},
		{"r_deny_pw_search", "(!(userPassword=*))", ""},
		{"e_deny_noattr", "(sn=S)", all + ",v_u"},
		{"e_deny_noattr", "(userPassword=*)", "fa_bob"},
		{"e_deny_pwsn", "(sn=S)", ""},
		{"e_deny_pwsn", "(uid=fa_bob)", "fa_bob"},
		{"e_deny_pwsn", "(objectClass=*)", all + ",v_u"},
		{"e_allow_noattr", "(objectClass=*)", ""},
		{"e_allow_noattr", "(uid=fa_bob)", ""},
		{"e_allow_noattr_u", "(uid=*)", all + ",v_u"},
		{"e_allow_noattr_u", "(sn=S)", ""},
		// Probe 20: userid-spelled value.
		{"i_uid_rs", "(uid=v_u)", "v_u"},
		{"i_uid_rs", "(userid=v_u)", "v_u"},
		{"i_userid_rs", "(uid=v_u)", ""},
		{"i_userid_rs", "(userid=v_u)", ""},
	} {
		if got := search(as(tc.subject), tc.filter); got != tc.want {
			t.Errorf("%s: %s %s: got [%s], oracle [%s]", env.engine, tc.subject, tc.filter, got, tc.want)
		}
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
	// Compare (probe 16).
	for _, tc := range []struct {
		subject, attr, value string
		want                 uint16
	}{
		{"t_uidopt", "uid;x-test", "bobtag", ldap.LDAPResultCompareTrue},
		{"t_uidopt", "uid", "fa_bob", ldap.LDAPResultInsufficientAccessRights},
		{"t_uidopt", "description;lang-en", "hello", ldap.LDAPResultInsufficientAccessRights},
		{"e_allow_noattr", "uid", "fa_bob", ldap.LDAPResultInsufficientAccessRights},
	} {
		ok, err := as(tc.subject).Compare("uid=fa_bob,"+ou, tc.attr, tc.value)
		got := code(err)
		if err == nil && ok {
			got = ldap.LDAPResultCompareTrue
		} else if err == nil {
			got = ldap.LDAPResultCompareFalse
		}
		if got != tc.want {
			t.Errorf("%s: %s COMPARE %s: got %d, oracle %d", env.engine, tc.subject, tc.attr, got, tc.want)
		}
	}
	// Modify (probes 16, 18) and modrdn (probes 18, 19).
	for _, tc := range []struct {
		subject, dn, attr string
		want              uint16
	}{
		{"w_noattr", "uid=fa_alice", "sn", 50},
		{"w_noattr", "uid=nobody", "sn", 50},
		{"w_deny_noattr", "uid=fa_alice", "sn", 0},
		{"w_deny_noattr", "uid=nobody", "sn", 32},
		{"w_descopt", "uid=fa_alice", "description;lang-en", 0},
		{"w_descopt", "uid=fa_alice", "description", 50},
		{"w_descopt", "uid=fa_alice", "description;lang-en;x-foo", 0},
		{"w_descopt", "uid=fa_alice", "sn", 50},
		{"w_deny_descopt", "uid=fa_alice", "description;lang-en", 50},
		{"w_deny_descopt", "uid=fa_alice", "description;LANG-EN", 50},
		{"w_deny_descopt", "uid=fa_alice", "description", 0},
		{"w_deny_descopt", "uid=fa_alice", "sn", 0},
		{"w_deny_descopt", "uid=nobody", "sn", 32},
		{"w_deny_uid", "uid=fa_alice", "sn", 0},
		{"w_none", "uid=fa_alice", "sn", 50},
		{"w_none", "uid=nobody", "sn", 50},
		{"r_noattr_wa", "uid=fa_alice", "sn", 50},
	} {
		req := ldap.NewModifyRequest(tc.dn+","+ou, nil)
		req.Add(tc.attr, []string{tc.subject + "-" + strings.ReplaceAll(tc.attr, ";", "-")})
		if got := code(as(tc.subject).Modify(req)); got != tc.want {
			t.Errorf("%s: %s MODIFY %s add %s: got %d, oracle %d", env.engine, tc.subject, tc.dn, tc.attr, got, tc.want)
		}
	}
	for _, tc := range []struct {
		subject, rdn, newRDN string
		want                 uint16
	}{
		{"w_deny_uid", "uid=fa_alice", "uid=fa_alice2", 50},
		{"w_noattr", "uid=fa_bob", "uid=fa_bob2", 50},
		{"w_none", "uid=fa_bob", "uid=fa_bob3", 50},
		{"r_noattr_wa", "uid=fa_bob", "uid=fa_bob4", 50},
	} {
		if got := code(as(tc.subject).ModifyDN(ldap.NewModifyDNRequest(tc.rdn+","+ou, tc.newRDN, true, ""))); got != tc.want {
			t.Errorf("%s: %s MODRDN %s: got %d, oracle %d", env.engine, tc.subject, tc.rdn, got, tc.want)
		}
	}
}
