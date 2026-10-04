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

// TestACIModRDNStarListsAbsoluteFilters (contract C8; resolved CAND-36,
// CAND-37, CAND-38 and the DSL list follow-up, oracle probes 25-29 in
// test/parity/testdata/filter-attr-oracle-probes.txt) runs the same client
// and assertions on both engines:
//   - a same-parent rename needs write on the new RDN attribute (and the
//     old one with deleteoldrdn) on the old DN; only a deny-write ACI
//     without targetattr blocks at entry level; add is not needed;
//   - a rename onto an existing DN is 68 and a move beneath itself 53 for
//     a subject without rights; a missing source is 50 for non-root;
//   - targetattr!="*" loads and covers no attribute, while entry-level
//     add/delete still apply it;
//   - filters holding (&) or (|) get protocolError(2) for every subject;
//   - DSL attributes.allow/deny compile to one 389 list.
//
// Engine-conditional rows pin the open candidates: a cross-parent move
// with write and add (CAND-39: 389 needs a moddn grant) and a case-only
// rename (CAND-30). Every row uses a fresh connection (D36).
func TestACIModRDNStarListsAbsoluteFilters(t *testing.T) {
	const (
		suffix = "dc=example,dc=test"
		people = "ou=people," + suffix
		ou     = "ou=probe-acl38," + suffix
		dest   = "ou=probe-acl38-dest," + suffix
		pw     = "Acl38-Probe-Secret-1"
		rsc    = "read,search,compare"
	)
	subjects := map[string][]string{
		"m_uid":            {`(targetattr="*")|read,search`, `(targetattr="uid")|write`},
		"m_cn":             {`(targetattr="*")|read,search`, `(targetattr="cn")|write`},
		"m_star_deny_desc": {`(targetattr="*")|read,search,write`, `(targetattr="description")|deny:write`},
		"m_star_deny_uid":  {`(targetattr="*")|read,search,write`, `(targetattr="uid")|deny:write`},
		"m_deny_noattr":    {`(targetattr="uid")|write`, `|deny:write`},
		"m_deny_add":       {`(targetattr="uid")|write`, `|deny:add`},
		"m_star":           {`(targetattr="*")|write`},
		"m_none":           {`(targetattr="*")|read,search`},
		"m_rt":             {`(targetattr="*")|read,search,compare,write,add,delete`},
		"n_rsc":            {`(targetattr!="*")|` + rsc},
		"n_deny":           {`(targetattr="*")|` + rsc, `(targetattr!="*")|deny:` + rsc},
		"n_mix":            {`(targetattr!="* || sn")|` + rsc},
		"n_ad":             {`(targetattr="*")|` + rsc, `(targetattr!="*")|add,delete`},
		"n_deny_ad":        {`(targetattr="*")|` + rsc + `,add,delete`, `(targetattr!="*")|deny:add,delete`},
		"p_star_sn":        {`(targetattr="* || sn")|` + rsc},
	}
	yaml := strings.Replace(workflowYAML(), `directory: { suffix: "dc=example,dc=test" }`, `directory: { suffix: "dc=example,dc=test", allowRawACI: true }`, 1)
	yaml += "  acls:\n"
	yaml += "    - id: dsl-list\n      principal: { kind: user, ref: alice }\n      target: { kind: suffix }\n      permissions: [read, search]\n      attributes: { allow: [uid, sn, description], deny: [description] }\n"
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
			yaml += fmt.Sprintf("    - id: %s\n      rawACI: '(target=\"ldap:///%s\")%s(version 3.0; acl \"labldap:%s\"; %s (%s) userdn=\"ldap:///uid=%s,%s\";)'\n", id, suffix, ta, id, action, perms, s, people)
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
	add := func(dn string, attrs ...[2]string) {
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
	person := func(uid string, extra ...[2]string) [][2]string {
		return append([][2]string{{"objectClass", "top"}, {"objectClass", "person"}, {"objectClass", "organizationalPerson"}, {"objectClass", "inetOrgPerson"},
			{"uid", uid}, {"cn", uid}, {"sn", "S"}}, extra...)
	}
	orgUnit := func(name string) [][2]string {
		return [][2]string{{"objectClass", "top"}, {"objectClass", "organizationalUnit"}, {"ou", name}}
	}
	add(ou, orgUnit("probe-acl38")...)
	add(dest, orgUnit("probe-acl38-dest")...)
	add("uid=fa_bob,"+ou, person("fa_bob", [2]string{"description", "hello"})...)
	for _, s := range names {
		add("uid="+s+","+people, person(s, [2]string{"userPassword", pw})...)
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
	exists := func(dn string) bool {
		t.Helper()
		_, err := dm.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"1.1"}, nil))
		return err == nil
	}

	// CAND-36 renames (probes 25, 27): one fresh target entry per row.
	for i, tc := range []struct {
		subject, newRDN string
		del             bool
		want            uint16
	}{
		{"m_uid", "uid=%s-r", true, 0},
		{"m_uid", "uid=%s-r", false, 0},
		{"m_uid", "cn=%s-r", false, 50},
		{"m_cn", "uid=%s-r", false, 50},
		{"m_cn", "cn=%s-r", false, 0},
		{"m_star_deny_desc", "uid=%s-r", true, 0},
		{"m_star_deny_uid", "uid=%s-r", true, 50},
		{"m_star_deny_uid", "cn=%s-r", false, 0},
		{"m_deny_noattr", "uid=%s-r", true, 50},
		{"m_deny_add", "uid=%s-r", true, 0},
		{"m_none", "uid=%s-r", true, 50},
		// Unknown RDN type (probes 27, 29): 50 without write. With write
		// 389 answers 65; native does not check undefined attribute types
		// on writes (open CAND-8), so that row is not asserted.
		{"m_uid", "bogusAttr=%s", false, 50},
	} {
		uid := fmt.Sprintf("ren%02d", i)
		add("uid="+uid+","+ou, person(uid)...)
		newRDN := fmt.Sprintf(tc.newRDN, uid)
		if got := code(as(tc.subject).ModifyDN(ldap.NewModifyDNRequest("uid="+uid+","+ou, newRDN, tc.del, ""))); got != tc.want {
			t.Errorf("%s: %s MODRDN %s -> %s del=%v: got %d, oracle %d", env.engine, tc.subject, uid, newRDN, tc.del, got, tc.want)
		}
		if moved := exists(newRDN + "," + ou); moved != (tc.want == 0) {
			t.Errorf("%s: %s MODRDN %s -> %s: new DN present = %v", env.engine, tc.subject, uid, newRDN, moved)
		}
	}

	// Ordering (probe 27): existence answers before the access check.
	add("uid=ord_a,"+ou, person("ord_a")...)
	add("uid=ord_b,"+ou, person("ord_b")...)
	for _, tc := range []struct {
		name, subject, dn, newRDN, sup string
		want                           uint16
	}{
		{"missing source", "m_star", "uid=ghost," + ou, "uid=ghost2", "", 50},
		{"onto existing", "m_none", "uid=ord_a," + ou, "uid=ord_b", "", 68},
		{"beneath itself", "m_none", ou, "ou=probe-acl38", "uid=ord_a," + ou, 53},
		{"missing source as DM", "", "uid=ghost," + ou, "uid=ghost2", "", 32},
	} {
		c := dm
		if tc.subject != "" {
			c = as(tc.subject)
		}
		if got := code(c.ModifyDN(ldap.NewModifyDNRequest(tc.dn, tc.newRDN, true, tc.sup))); got != tc.want {
			t.Errorf("%s: %s %s: got %d, oracle %d", env.engine, tc.name, tc.subject, got, tc.want)
		}
	}

	// No-op rename (probe 28): success, entry still there.
	add("uid=noop,"+ou, person("noop")...)
	if got := code(as("m_uid").ModifyDN(ldap.NewModifyDNRequest("uid=noop,"+ou, "uid=noop", true, ou))); got != 0 {
		t.Errorf("%s: no-op rename: got %d, oracle 0", env.engine, got)
	}
	if got := code(as("m_cn").ModifyDN(ldap.NewModifyDNRequest("uid=noop,"+ou, "uid=noop", false, ""))); got != 50 {
		t.Errorf("%s: no-op rename without write on uid: got %d, oracle 50", env.engine, got)
	}

	// Open candidates, engine-conditional.
	add("uid=mv,"+ou, person("mv")...)
	wantMove := uint16(0) // native: entry write + add on the new DN
	if env.engine == Engine389DS {
		wantMove = 50 // CAND-39: 389 needs the moddn right
	}
	if got := code(as("m_rt").ModifyDN(ldap.NewModifyDNRequest("uid=mv,"+ou, "uid=mv", true, dest))); got != wantMove {
		t.Errorf("%s: CAND-39 runtime-like cross-parent move: got %d, want %d", env.engine, got, wantMove)
	}
	add("uid=casey,"+ou, person("casey")...)
	wantCase := uint16(68) // native: case-only rename is entryAlreadyExists
	if env.engine == Engine389DS {
		wantCase = 0 // CAND-30: 389 respells the DN
	}
	if got := code(dm.ModifyDN(ldap.NewModifyDNRequest("uid=casey,"+ou, "uid=CASEY", true, ""))); got != wantCase {
		t.Errorf("%s: CAND-30 case-only rename: got %d, want %d", env.engine, got, wantCase)
	}

	// CAND-37 (probe 25): targetattr!="*" and lists holding "*".
	search := func(c *ldap.Conn, filter string) string {
		t.Helper()
		res, err := c.Search(ldap.NewSearchRequest(ou, ldap.ScopeSingleLevel, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"1.1"}, nil))
		if err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
		var got []string
		for _, e := range res.Entries {
			rdn, _, _ := strings.Cut(strings.ToLower(e.DN), ",")
			got = append(got, rdn)
		}
		sort.Strings(got)
		return strings.Join(got, ",")
	}
	for _, tc := range []struct{ subject, filter, want string }{
		{"n_rsc", "(uid=fa_bob)", ""},
		{"n_mix", "(uid=fa_bob)", ""},
		{"n_mix", "(sn=S)", ""},
		{"n_deny", "(uid=fa_bob)", "uid=fa_bob"},
		{"p_star_sn", "(uid=fa_bob)", "uid=fa_bob"},
		{"p_star_sn", "(description=hello)", "uid=fa_bob"},
	} {
		if got := search(as(tc.subject), tc.filter); got != tc.want {
			t.Errorf("%s: %s %s: got [%s], oracle [%s]", env.engine, tc.subject, tc.filter, got, tc.want)
		}
	}
	for _, tc := range []struct {
		subject string
		want    uint16
	}{
		{"n_ad", 0},
		{"n_deny_ad", 50},
		{"n_rsc", 50},
	} {
		dn := "uid=add-" + strings.ReplaceAll(tc.subject, "_", "-") + "," + ou
		req := ldap.NewAddRequest(dn, nil)
		req.Attribute("objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"})
		req.Attribute("uid", []string{"add-" + strings.ReplaceAll(tc.subject, "_", "-")})
		req.Attribute("cn", []string{"x"})
		req.Attribute("sn", []string{"S"})
		if got := code(as(tc.subject).Add(req)); got != tc.want {
			t.Errorf("%s: %s ADD: got %d, oracle %d", env.engine, tc.subject, got, tc.want)
		}
		if tc.want == 0 {
			if got := code(as(tc.subject).Del(ldap.NewDelRequest(dn, nil))); got != 0 {
				t.Errorf("%s: %s DELETE: got %d, oracle 0", env.engine, tc.subject, got)
			}
		}
	}

	// CAND-38 (probes 19, 25, 26, 28): absolute filters.
	for _, tc := range []struct{ who, base, filter string }{
		{"dm", suffix, "(&)"},
		{"dm", "", "(|)"},
		{"dm", "cn=schema", "(&)"},
		{"dm", "uid=ghost," + suffix, "(&)"},
		{"m_none", suffix, "(!(&))"},
		{"m_none", ou, "(&(uid=fa_bob)(|))"},
	} {
		c := dm
		if tc.who != "dm" {
			c = as(tc.who)
		}
		_, err := c.Search(ldap.NewSearchRequest(tc.base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, tc.filter, []string{"1.1"}, nil))
		if got := code(err); got != ldap.LDAPResultProtocolError {
			t.Errorf("%s: %s base %q %s: got %d (%v), oracle 2", env.engine, tc.who, tc.base, tc.filter, got, err)
		}
		if got := search(c, "(uid=fa_bob)"); tc.who == "dm" && got != "uid=fa_bob" {
			t.Errorf("%s: connection unusable after %s: [%s]", env.engine, tc.filter, got)
		}
	}

	// DSL list (probe 25): allow [uid, sn, description] minus deny
	// [description] is one targetattr="uid || sn" ACI.
	alice := dial("uid=alice,"+people, seedCanary)
	if got := search(alice, "(sn=S)"); !strings.Contains(got, "uid=fa_bob") {
		t.Errorf("%s: DSL list (sn=S): got [%s], want fa_bob", env.engine, got)
	}
	if got := search(dial("uid=alice,"+people, seedCanary), "(description=hello)"); got != "" {
		t.Errorf("%s: DSL list (description=hello): got [%s], want none", env.engine, got)
	}
}
