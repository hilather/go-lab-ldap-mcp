package config_test

import (
	"testing"

	"github.com/hilather/go-lab-ldap-mcp/internal/config"
)

func TestProtectedAttrOptionsAndOIDs(t *testing.T) {
	for _, name := range []string{"userPassword;binary", "2.5.4.35", "2.5.4.35;binary", "ACI;lang-en", "2.16.840.1.113730.3.1.55", "nsAccountLock;binary"} {
		if !config.ForbiddenUserAttr(name) {
			t.Fatalf("protected write bypass via %s", name)
		}
	}
	if config.ForbiddenUserAttr("description;lang-en") {
		t.Fatal("safe option rejected")
	}
}

func TestForbiddenUserWriteAttrSingleRule(t *testing.T) {
	for _, name := range []string{
		"objectClass", "OBJECTCLASS;x-a", "2.5.4.0",
		"cn;lang-en", "commonName", "surname", "userid", "uid;x-a", "2.5.4.3", "0.9.2342.19200300.100.1.1",
		"userPassword;lang-en", "authPassword",
	} {
		if !config.ForbiddenUserWriteAttr(name) {
			t.Fatalf("%s must be rejected on user writes", name)
		}
	}
	for _, name := range []string{"cn", " CN ", "sn", "uid", "mail", "mail;lang-en", "ou", "organizationalUnitName"} {
		if config.ForbiddenUserWriteAttr(name) {
			t.Fatalf("%s must stay writable", name)
		}
	}
}

func TestCanonicalAttrTypeResolvesAliases(t *testing.T) {
	cases := map[string]string{
		"commonName;lang-en": "cn", "SURNAME": "sn", "userID": "uid", "organizationalUnitName": "ou",
		"domainComponent": "dc", "organizationName": "o", "2.5.4.0": "objectclass", "mail;x-a": "mail",
	}
	for in, want := range cases {
		if got := config.CanonicalAttrType(in); got != want {
			t.Fatalf("CanonicalAttrType(%q) = %q, want %q", in, got, want)
		}
	}
}
