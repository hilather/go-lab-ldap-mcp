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
