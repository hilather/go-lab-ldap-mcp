package config_test

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func TestFoldedDNKeyPreservesRDNSepAndEscapes(t *testing.T) {
	a, err := config.ParseDN(`uid=alice\,ou=people,dc=test`)
	if err != nil {
		t.Fatal(err)
	}
	b, err := config.ParseDN(`uid=alice,ou=people,dc=test`)
	if err != nil {
		t.Fatal(err)
	}
	if a.FoldedKey() == b.FoldedKey() {
		t.Fatal("different DN structures have identical keys")
	}
	for _, raw := range []string{`cn=foo\2cbar,dc=test`, `cn=foo\,bar,dc=test`} {
		dn, err := config.ParseDN(raw)
		if err != nil {
			t.Fatal(err)
		}
		if dn.FoldedKey() != `cn=foo\,bar,dc=test` {
			t.Fatalf("hex escape mismatch: %s", dn.FoldedKey())
		}
	}
	dn, err := config.ParseDN(`cn=\ leading\ ,dc=test`)
	if err != nil {
		t.Fatal(err)
	}
	_, val, _ := dn.Leaf()
	if val != " leading " {
		t.Fatalf("escaped spaces lost: %q", val)
	}
}
func TestDNRejectsInvalidIdentitySyntax(t *testing.T) {
	for _, raw := range []string{`cn=x+uid=y,dc=test`, `bad attr=x,dc=test`, `cn=x\zz,dc=test`, `cn=x\00,dc=test`} {
		if _, err := config.ParseDN(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	if _, err := config.BuildRDN("cn=x,uid", "value"); err == nil {
		t.Fatal("unsafe RDN attr accepted")
	}
}
