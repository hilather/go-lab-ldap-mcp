//go:build integration

package dirsrv

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"strings"
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

// These C1/C6/C8 regressions deliberately use the same independent client
// and assertions with LABLDAP_IT_ENGINE=389ds and =native.
func TestNativeReviewDirectoryRegressions(t *testing.T) {
	yaml := strings.Replace(workflowYAML(), `directory: { suffix: "dc=example,dc=test" }`, `directory: { suffix: "dc=example,dc=test", allowRawACI: true }`, 1)
	yaml += `  acls:
    - id: review-search
      rawACI: '(target="ldap:///ou=people,dc=example,dc=test")(targetattr="uid")(version 3.0; acl "labldap:review-search"; allow (read,search) userdn="ldap:///uid=alice,ou=people,dc=example,dc=test";)'
`
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
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	dm := dial("cn=Directory Manager", env.dmPassword)
	const people = "ou=people,dc=example,dc=test"
	const alice = "uid=alice," + people
	t.Run("rename-into-own-subtree", func(t *testing.T) {
		for _, superior := range []string{people, alice, "OU=PEOPLE,dc=example,dc=test", "UID=ALICE,OU=PEOPLE,dc=example,dc=test"} {
			err := dm.ModifyDN(ldap.NewModifyDNRequest(people, "ou=moved", true, superior))
			if !ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
				t.Fatalf("rename code: %v", err)
			}
			res, err := dm.Search(ldap.NewSearchRequest(people, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, "(uid=alice)", []string{"uid"}, nil))
			if err != nil || len(res.Entries) != 1 {
				t.Fatalf("original child no longer visible: %v", err)
			}
		}
	})
	t.Run("rename-schema", func(t *testing.T) {
		const group = "cn=staff,ou=groups,dc=example,dc=test"
		err := dm.ModifyDN(ldap.NewModifyDNRequest(group, "description=renamed", true, ""))
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultObjectClassViolation) {
			t.Fatalf("rename schema code: %v", err)
		}
		res, err := dm.Search(ldap.NewSearchRequest(group, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(objectClass=*)", []string{"cn"}, nil))
		if err != nil || len(res.Entries) != 1 {
			t.Fatalf("failed rename changed original: %v", err)
		}
	})
	t.Run("rename-deleteoldrdn-equality", func(t *testing.T) {
		// Exact values observed on the pinned 389 image: old RDN values
		// are removed by the equality rule, then the new RDN value is
		// appended unless an equal value remains. DN strings are not
		// compared (389 normalises internal spaces in returned DNs).
		add := func(dn string, attrs map[string][]string) {
			t.Helper()
			req := ldap.NewAddRequest(dn, nil)
			for _, k := range []string{"objectClass", "uid", "ou", "cn", "sn"} {
				if v, ok := attrs[k]; ok {
					req.Attribute(k, v)
				}
			}
			if err := dm.Add(req); err != nil {
				t.Fatalf("add %s: %v", dn, err)
			}
		}
		person := func(uids ...string) map[string][]string {
			return map[string][]string{"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson"}, "uid": uids, "cn": {"probe"}, "sn": {"probe"}}
		}
		rename := func(dn, rdn string, del bool, sup string) {
			t.Helper()
			if err := dm.ModifyDN(ldap.NewModifyDNRequest(dn, rdn, del, sup)); err != nil {
				t.Fatalf("moddn %s -> %s: %v", dn, rdn, err)
			}
		}
		uidsUnder := func(base, filter string) []string {
			t.Helper()
			res, err := dm.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"uid"}, nil))
			if err != nil || len(res.Entries) != 1 {
				t.Fatalf("search %s under %s: %v", filter, base, err)
			}
			return res.Entries[0].GetAttributeValues("uid")
		}
		const dest = "ou=rdn-dest,dc=example,dc=test"
		// Registered before the adds so a failed step still removes
		// whatever was created, under original or renamed names.
		t.Cleanup(func() {
			for _, filter := range []string{"(uid=renamer)", "(uid=ren amer)", "(uid=mover)", "(uid=caser)", "(uid=dx)", "(uid=d y)", "(uid=keeper)", "(uid=kee per)"} {
				if res, err := dm.Search(ldap.NewSearchRequest("dc=example,dc=test", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, nil, nil)); err == nil {
					for _, e := range res.Entries {
						_ = dm.Del(ldap.NewDelRequest(e.DN, nil))
					}
				}
			}
			_ = dm.Del(ldap.NewDelRequest(dest, nil))
		})
		add(dest, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"rdn-dest"}})
		add("uid=renamer,"+people, person("renamer"))
		add("uid=mover,"+people, person("Mover", "m2"))
		add("uid=caser,"+people, person("caser"))
		add("uid=dx,"+people, person("dx", "d  y"))
		add("uid=keeper,"+people, person("keeper"))
		rename("uid=renamer,"+people, "uid=ren amer", true, "")
		rename("uid=ren amer,"+people, "uid=ren  amer", true, "")
		if got := uidsUnder(people, "(uid=ren amer)"); len(got) != 1 || got[0] != "ren  amer" {
			t.Fatalf("respell uid = %q, want [ren  amer]", got)
		}
		rename("uid=mover,"+people, "uid=mover", true, dest)
		if got := uidsUnder(dest, "(uid=mover)"); len(got) != 2 || got[0] != "m2" || got[1] != "mover" {
			t.Fatalf("pure move uid = %q, want [m2 mover]", got)
		}
		// Request DN cased differently from the new RDN.
		rename("uid=CASER,"+people, "uid=caser", true, dest)
		if got := uidsUnder(dest, "(uid=caser)"); len(got) != 1 || got[0] != "caser" {
			t.Fatalf("request-DN spelling uid = %q, want [caser]", got)
		}
		rename("uid=dx,"+people, "uid=d y", true, "")
		if got := uidsUnder(people, "(uid=d y)"); len(got) != 1 || got[0] != "d  y" {
			t.Fatalf("equal remaining uid = %q, want [d  y]", got)
		}
		rename("uid=keeper,"+people, "uid=kee per", false, "")
		rename("uid=kee per,"+people, "uid=kee  per", false, "")
		if got := uidsUnder(people, "(uid=kee per)"); len(got) != 2 || got[0] != "keeper" || got[1] != "kee per" {
			t.Fatalf("keep-old respell uid = %q, want [keeper kee per]", got)
		}
	})
	t.Run("rename-restricted-rdn", func(t *testing.T) {
		runtime := dial("uid=rt,"+people, "runtime-secret")
		err := runtime.ModifyDN(ldap.NewModifyDNRequest(alice, "aci=policy", false, ""))
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
			t.Fatalf("restricted rename code: %v", err)
		}
	})
	t.Run("protected-attribute-aliases", func(t *testing.T) {
		runtime := dial("uid=rt,"+people, "runtime-secret")
		for _, attr := range []string{"aci;lang-en", "2.16.840.1.113730.3.1.55"} {
			req := ldap.NewModifyRequest(alice, nil)
			req.Replace(attr, []string{"policy"})
			err := runtime.Modify(req)
			if !ldap.IsErrorWithCode(err, ldap.LDAPResultInsufficientAccessRights) {
				t.Fatalf("protected alias %s: %v", attr, err)
			}
		}
	})
	t.Run("exact-size-limit", func(t *testing.T) {
		res, err := dm.Search(ldap.NewSearchRequest("dc=example,dc=test", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 0, false, "(uid=alice)", []string{"uid"}, nil))
		if err != nil || len(res.Entries) != 1 {
			t.Fatalf("exact limit: %v", err)
		}
	})
	t.Run("filter-attribute-access", func(t *testing.T) {
		reader := dial(alice, seedCanary)
		for _, filter := range []string{"(sn=Seed)", "(!(sn=Seed))", "(!(sn=Other))", "(sn=*)", "(&(uid=alice)(sn=Seed))"} {
			res, err := reader.Search(ldap.NewSearchRequest(alice, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, filter, []string{"uid"}, nil))
			if err != nil || len(res.Entries) != 0 {
				t.Fatalf("denied filter %s: err=%v", filter, err)
			}
		}
		res, err := reader.Search(ldap.NewSearchRequest(alice, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false, "(|(uid=alice)(sn=Seed))", []string{"uid"}, nil))
		if err != nil || len(res.Entries) != 1 {
			t.Fatalf("allowed OR branch: %v", err)
		}
	})
}
